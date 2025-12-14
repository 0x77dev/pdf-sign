//! WebAssembly bindings for pdf-sign
//!
//! This crate provides WASM bindings for browser environments with automatic
//! TypeScript definition generation via tsify.

use base64::Engine;
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

// Re-export for initialization
#[wasm_bindgen(start)]
pub fn init() {
  // Set panic hook for better error messages in browser
  #[cfg(feature = "console_error_panic_hook")]
  console_error_panic_hook::set_once();
}

/// Challenge for remote GPG signing (auto-generates TS interface)
#[derive(Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
  pub version: u32,
  pub fingerprint: String,
  pub data_base64: String,
  pub gpg_command: String,
  pub created_at: String,
  pub embed_uid: bool,
}

/// Signature information (auto-generates TS interface)
#[derive(Tsify, Serialize, Deserialize, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct SignatureInfo {
  pub fingerprint: String,
  pub uids: Vec<String>,
}

/// Verification result (auto-generates TS interface)
#[derive(Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct VerificationResult {
  pub valid: bool,
  pub gpg_signatures: Vec<SignatureInfo>,
}

/// Prepare a signing challenge for remote/air-gapped GPG signing
#[wasm_bindgen(js_name = prepareChallenge)]
pub fn prepare_challenge(
  pdf_bytes: &[u8],
  cert_armored: &str,
  embed_uid: bool,
) -> Result<Challenge, String> {
  use openpgp::cert::prelude::*;
  use openpgp::parse::Parse;
  use pdf_sign_core::split_pdf;
  use pdf_sign_gpg::challenge;
  use sequoia_openpgp as openpgp;

  // Parse certificate
  let cert = Cert::from_bytes(cert_armored.as_bytes())
    .map_err(|e| format!("Failed to parse certificate: {}", e))?;

  // Split PDF
  let (clean_pdf, _suffix) =
    split_pdf(pdf_bytes).map_err(|e| format!("Failed to parse PDF: {}", e))?;

  // Prepare challenge
  let options = challenge::ChallengeOptions { embed_uid };
  let challenge_data = challenge::prepare_challenge(clean_pdf, &cert, &options)
    .map_err(|e| format!("Failed to prepare challenge: {}", e))?;

  // Convert to JSON-friendly format
  let data_base64 = base64::engine::general_purpose::STANDARD.encode(&challenge_data.data_to_sign);
  let fingerprint = challenge_data.fingerprint.clone();
  let gpg_command = format!(
    "echo '{}' | base64 -d | gpg --detach-sign --armor -u {} > signature.asc",
    data_base64, fingerprint
  );

  Ok(Challenge {
    version: challenge_data.version,
    fingerprint,
    data_base64,
    gpg_command,
    created_at: challenge_data.created_at,
    embed_uid,
  })
}

/// Apply a signature response to complete challenge-response signing
#[wasm_bindgen(js_name = applyResponse)]
pub fn apply_response(
  pdf_bytes: &[u8],
  challenge: Challenge,
  signature_armored: &str,
) -> Result<Vec<u8>, String> {
  use pdf_sign_core::{
    split_pdf,
    suffix::{encode_suffix_block, parse_suffix_blocks},
  };
  let _ = challenge;
  // For WASM we keep `apply_response` intentionally minimal: it performs basic
  // format validation and appends the provided ASCII-armored signature.

  // Split PDF
  let (clean_pdf, suffix) =
    split_pdf(pdf_bytes).map_err(|e| format!("Failed to parse PDF: {}", e))?;

  let existing_blocks = parse_suffix_blocks(suffix)
    .map_err(|e| format!("Failed to parse existing signatures: {}", e))?;

  // Validate signature format
  if !signature_armored.contains("-----BEGIN PGP SIGNATURE-----") {
    return Err("Invalid signature format".to_string());
  }

  // Build signed PDF
  let mut result = clean_pdf.to_vec();
  result.push(b'\n');

  // Write existing blocks
  for block in &existing_blocks {
    let encoded = encode_suffix_block(block);
    result.extend_from_slice(&encoded);
  }

  // Append new signature
  result.extend_from_slice(signature_armored.as_bytes());

  Ok(result)
}

/// Verify GPG signatures in a PDF
#[wasm_bindgen(js_name = verifyGpg)]
pub fn verify_gpg(
  pdf_bytes: &[u8],
  cert_armored: Option<String>,
) -> Result<VerificationResult, String> {
  use openpgp::cert::prelude::*;
  use openpgp::parse::Parse;
  use pdf_sign_core::split_pdf;
  use pdf_sign_gpg::verify::{VerifyOptions, extract_pgp_signatures, verify_signatures};
  use sequoia_openpgp as openpgp;

  // Split PDF
  let (clean_pdf, suffix) =
    split_pdf(pdf_bytes).map_err(|e| format!("Failed to parse PDF: {}", e))?;

  // Extract PGP signatures
  let pgp_sigs = extract_pgp_signatures(suffix);

  if pgp_sigs.is_empty() {
    return Ok(VerificationResult {
      valid: false,
      gpg_signatures: Vec::new(),
    });
  }

  // Parse certificates if provided
  let certs = if let Some(cert_str) = cert_armored {
    vec![
      Cert::from_bytes(cert_str.as_bytes())
        .map_err(|e| format!("Failed to parse certificate: {}", e))?,
    ]
  } else {
    Vec::new()
  };

  let options = VerifyOptions { certs };

  // Verify signatures
  let result = verify_signatures(clean_pdf, &pgp_sigs, &options)
    .map_err(|e| format!("Verification failed: {}", e))?;

  let signatures: Vec<SignatureInfo> = result
    .verified
    .into_iter()
    .map(|v| SignatureInfo {
      fingerprint: v.key_fingerprint,
      uids: v.uids,
    })
    .collect();

  Ok(VerificationResult {
    valid: !signatures.is_empty(),
    gpg_signatures: signatures,
  })
}

/// Sign a PDF with Sigstore (requires identity token)
#[wasm_bindgen(js_name = signSigstore)]
pub async fn sign_sigstore(pdf_bytes: &[u8], identity_token: String) -> Result<Vec<u8>, String> {
  #[cfg(feature = "sigstore")]
  {
    use pdf_sign_core::{
      DigestAlgorithm, split_pdf,
      suffix::{SuffixBlock, encode_suffix_block, parse_suffix_blocks},
    };
    use pdf_sign_sigstore::sign::{SignOptions, SigstoreEndpoints, sign_blob};

    // Split PDF
    let (clean_pdf, suffix) =
      split_pdf(pdf_bytes).map_err(|e| format!("Failed to parse PDF: {}", e))?;

    let existing_blocks = parse_suffix_blocks(suffix)
      .map_err(|e| format!("Failed to parse existing signatures: {}", e))?;

    // Sign with Sigstore
    let endpoints = SigstoreEndpoints::default();
    let options = SignOptions {
      endpoints,
      digest_algorithm: DigestAlgorithm::Sha512,
      identity_token: Some(identity_token),
    };

    let sign_result = sign_blob(clean_pdf, &options)
      .await
      .map_err(|e| format!("Sigstore signing failed: {}", e))?;

    // Build signed PDF
    let mut result = clean_pdf.to_vec();
    result.push(b'\n');

    // Write existing blocks
    for block in &existing_blocks {
      let encoded = encode_suffix_block(block);
      result.extend_from_slice(&encoded);
    }

    // Write new Sigstore signature
    let new_block = SuffixBlock::SigstoreBundle(sign_result.bundle_block);
    let encoded = encode_suffix_block(&new_block);
    result.extend_from_slice(&encoded);

    Ok(result)
  }

  #[cfg(not(feature = "sigstore"))]
  {
    let _ = (pdf_bytes, identity_token);
    Err("Sigstore support is not enabled for this WASM build".to_string())
  }
}

/// Verify Sigstore signatures in a PDF
#[wasm_bindgen(js_name = verifySigstore)]
pub async fn verify_sigstore(
  pdf_bytes: &[u8],
  identity: String,
  issuer: String,
  offline: bool,
) -> Result<VerificationResult, String> {
  #[cfg(feature = "sigstore")]
  {
    use pdf_sign_core::{split_pdf, suffix::parse_suffix_blocks};
    use pdf_sign_sigstore::verify::{
      CertificateIdentityMatcher, OidcIssuerMatcher, VerifyOptions, VerifyPolicy, verify_blob,
    };

    // Split PDF
    let (clean_pdf, suffix) =
      split_pdf(pdf_bytes).map_err(|e| format!("Failed to parse PDF: {}", e))?;

    let blocks =
      parse_suffix_blocks(suffix).map_err(|e| format!("Failed to parse signatures: {}", e))?;

    // Extract Sigstore blocks
    let sigstore_blocks: Vec<_> = blocks
      .into_iter()
      .filter_map(|b| match b {
        pdf_sign_core::suffix::SuffixBlock::SigstoreBundle(bundle) => Some(bundle),
        _ => None,
      })
      .collect();

    if sigstore_blocks.is_empty() {
      return Ok(VerificationResult {
        valid: false,
        gpg_signatures: Vec::new(),
      });
    }

    // Set up verification policy
    let policy = VerifyPolicy {
      certificate_identity: Some(CertificateIdentityMatcher::Exact(identity)),
      certificate_oidc_issuer: Some(OidcIssuerMatcher::Exact(issuer)),
    };

    let options = VerifyOptions { policy, offline };

    // Verify first Sigstore signature (TODO: support multiple)
    let _result = verify_blob(clean_pdf, &sigstore_blocks[0], &options)
      .await
      .map_err(|e| format!("Sigstore verification failed: {}", e))?;

    // For now, return simple success
    Ok(VerificationResult {
      valid: true,
      gpg_signatures: Vec::new(),
    })
  }

  #[cfg(not(feature = "sigstore"))]
  {
    let _ = (pdf_bytes, identity, issuer, offline);
    Err("Sigstore support is not enabled for this WASM build".to_string())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use wasm_bindgen_test::*;

  #[wasm_bindgen_test]
  fn test_challenge_serialization() {
    let challenge = Challenge {
      version: 1,
      fingerprint: "ABCD1234".to_string(),
      data_base64: "SGVsbG8=".to_string(),
      gpg_command: "test command".to_string(),
      created_at: "2025-01-01T00:00:00Z".to_string(),
      embed_uid: true,
    };

    let json = serde_json::to_string(&challenge).unwrap();
    let parsed: Challenge = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.fingerprint, "ABCD1234");
  }
}
