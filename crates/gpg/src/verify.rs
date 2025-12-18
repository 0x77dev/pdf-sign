//! OpenPGP signature verification.

use anyhow::{Context, Result, bail};
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::parse::stream::*;
use openpgp::policy::StandardPolicy;
use pdf_sign_core::VerifiedSignature;
use sequoia_openpgp as openpgp;
use std::cell::RefCell;
use std::rc::Rc;

#[cfg(feature = "native")]
use crate::keybox::{find_certs_in_keybox, load_keybox_certs};

struct Helper {
  certs: Vec<Cert>,
  #[cfg(feature = "native")]
  keybox: Option<Vec<Cert>>,
  signer_cert: Rc<RefCell<Option<Cert>>>,
}

impl VerificationHelper for Helper {
  fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
    if !self.certs.is_empty() {
      return Ok(self.certs.clone());
    }

    #[cfg(not(feature = "native"))]
    {
      // Non-native targets (including WASM) cannot access a local keybox.
      // Require the caller to provide certificates explicitly.
      let _ = ids;
      return Err(
        openpgp::Error::InvalidOperation(
          "No certificates provided (keybox access requires the `native` feature)".into(),
        )
        .into(),
      );
    }

    #[cfg(feature = "native")]
    {
      if self.keybox.is_none() {
        let certs =
          load_keybox_certs().map_err(|e| openpgp::Error::InvalidOperation(e.to_string()))?;
        self.keybox = Some(certs);
      }

      let keybox = self.keybox.as_ref().unwrap();

      let mut out = Vec::new();
      for id in ids {
        let spec = match id {
          openpgp::KeyHandle::Fingerprint(fpr) => fpr.to_string(),
          openpgp::KeyHandle::KeyID(kid) => kid.to_string(),
        };
        out.extend(find_certs_in_keybox(keybox, &spec));
      }

      if out.is_empty() {
        return Ok(keybox.clone());
      }

      Ok(out)
    }
  }

  fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
    for layer in structure.into_iter() {
      if let MessageLayer::SignatureGroup { results } = layer {
        let mut last_error = None;
        for result in results {
          match result {
            Ok(good) => {
              *self.signer_cert.borrow_mut() = Some(good.ka.cert().clone());
              return Ok(());
            }
            Err(e) => {
              last_error = Some(e);
            }
          }
        }
        if let Some(e) = last_error {
          return Err(openpgp::Error::from(e).into());
        }
      }
    }
    Err(openpgp::Error::InvalidOperation("No valid signature".into()).into())
  }
}

/// Options for OpenPGP verification.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
  /// Provided certificates (if any). If empty, will use keybox.
  pub certs: Vec<Cert>,
}

/// Result of verification.
#[derive(Debug, Clone)]
pub struct VerifyResult {
  pub verified: Vec<VerifiedSignature>,
  pub cert_source: CertSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertSource {
  #[cfg(feature = "native")]
  Keybox,
  ProvidedCerts,
}

impl CertSource {
  pub fn as_str(&self) -> &'static str {
    match self {
      #[cfg(feature = "native")]
      CertSource::Keybox => "keybox",
      CertSource::ProvidedCerts => "cert",
    }
  }
}

/// Verify OpenPGP signatures against the given data.
///
/// Returns the list of verified signatures.
#[tracing::instrument(skip(data, signature_blocks), fields(data_len = data.len(), sig_count = signature_blocks.len()))]
pub fn verify_signatures(
  data: &[u8],
  signature_blocks: &[Vec<u8>],
  options: &VerifyOptions,
) -> Result<VerifyResult> {
  if signature_blocks.is_empty() {
    bail!("No PGP signature blocks provided");
  }

  let cert_source = if options.certs.is_empty() {
    #[cfg(feature = "native")]
    {
      CertSource::Keybox
    }
    #[cfg(not(feature = "native"))]
    {
      bail!("No certificates provided (keybox access requires the `native` feature)");
    }
  } else {
    CertSource::ProvidedCerts
  };

  let policy = StandardPolicy::new();
  let mut verified = Vec::new();

  for sig in signature_blocks {
    tracing::debug!("Verifying signature block");
    let signer_cert: Rc<RefCell<Option<Cert>>> = Rc::new(RefCell::new(None));

    let helper = Helper {
      certs: options.certs.clone(),
      #[cfg(feature = "native")]
      keybox: None,
      signer_cert: signer_cert.clone(),
    };

    let mut verifier =
      DetachedVerifierBuilder::from_bytes(sig)?.with_policy(&policy, None, helper)?;

    verifier
      .verify_bytes(data)
      .context("Signature verification failed")?;

    let cert = signer_cert
      .borrow()
      .clone()
      .context("Signature verified but signer certificate could not be resolved")?;

    let fingerprint = cert.fingerprint().to_string();
    let uids: Vec<String> = cert
      .userids()
      .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string())
      .collect();

    tracing::info!(fingerprint = %fingerprint, "Signature verified");

    verified.push(VerifiedSignature {
      key_fingerprint: fingerprint,
      uids,
      source: cert_source.as_str().to_string(),
    });
  }

  Ok(VerifyResult {
    verified,
    cert_source,
  })
}

/// Extract all ASCII-armored PGP signature blocks from suffix data.
#[tracing::instrument(skip(data), fields(data_len = data.len()))]
pub fn extract_pgp_signatures(data: &[u8]) -> Vec<Vec<u8>> {
  const PGP_SIG_BEGIN: &[u8] = b"-----BEGIN PGP SIGNATURE-----";
  const PGP_SIG_END: &[u8] = b"-----END PGP SIGNATURE-----";

  let mut sigs = Vec::new();
  let mut i = 0;
  while let Some(begin) = find_subslice(data, PGP_SIG_BEGIN, i) {
    let Some(end) = find_subslice(data, PGP_SIG_END, begin) else {
      break;
    };
    let mut end_pos = end + PGP_SIG_END.len();
    // Include at most one trailing newline
    if end_pos < data.len() && data[end_pos] == b'\r' {
      end_pos += 1;
      if end_pos < data.len() && data[end_pos] == b'\n' {
        end_pos += 1;
      }
    } else if end_pos < data.len() && data[end_pos] == b'\n' {
      end_pos += 1;
    }
    sigs.push(data[begin..end_pos].to_vec());
    i = end_pos;
  }
  tracing::debug!(count = sigs.len(), "Extracted PGP signature blocks");
  sigs
}

fn find_subslice(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
  if needle.is_empty() || start >= haystack.len() {
    return None;
  }
  haystack[start..]
    .windows(needle.len())
    .position(|w| w == needle)
    .map(|pos| start + pos)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn extract_preserves_crlf() {
    let sig = b"-----BEGIN PGP SIGNATURE-----\r\n\
Version: Test\r\n\
\r\n\
abc\r\n\
-----END PGP SIGNATURE-----\r\n";
    let out = extract_pgp_signatures(sig);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].as_slice(), sig);
  }

  #[test]
  fn extract_preserves_lf() {
    let sig = b"-----BEGIN PGP SIGNATURE-----\n\
Version: Test\n\
\n\
abc\n\
-----END PGP SIGNATURE-----\n";
    let out = extract_pgp_signatures(sig);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].as_slice(), sig);
  }
}
