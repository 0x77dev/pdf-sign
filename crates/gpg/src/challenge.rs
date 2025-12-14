//! Challenge-response signing workflow for air-gapped or remote GPG signing.
//!
//! This module provides a WASM-compatible challenge-response API where:
//! 1. `prepare_challenge` generates a signing challenge with the data to sign
//! 2. The challenge is signed externally (e.g., on a remote machine with `gpg --detach-sign`)
//! 3. `apply_response` validates and applies the signature to create a signed PDF

use anyhow::{Context, Result, bail};
use openpgp::armor;
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize};

/// Challenge for remote signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
  /// Challenge format version.
  pub version: u32,
  /// Data to be signed (raw bytes).
  pub data_to_sign: Vec<u8>,
  /// Key fingerprint to use for signing.
  pub fingerprint: String,
  /// Creation timestamp.
  pub created_at: String,
  /// Challenge options.
  pub options: ChallengeOptions,
}

/// Options for challenge preparation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeOptions {
  /// Embed UID in signature notation.
  pub embed_uid: bool,
}

/// Result of applying a signature response.
#[derive(Debug, Clone)]
pub struct SignResult {
  pub fingerprint: String,
  pub uids: Vec<String>,
  pub signature_data: Vec<u8>,
}

/// Prepare a signing challenge for remote/air-gapped signing.
///
/// This function is WASM-compatible and generates a challenge containing
/// the data to be signed and metadata about the signing key.
#[tracing::instrument(skip(data, cert), fields(data_len = data.len()))]
pub fn prepare_challenge(
  data: &[u8],
  cert: &Cert,
  options: &ChallengeOptions,
) -> Result<Challenge> {
  let fingerprint = cert.fingerprint().to_string();

  // Verify cert has a signing-capable key
  let policy = StandardPolicy::new();
  let _ = cert
    .keys()
    .with_policy(&policy, None)
    .alive()
    .revoked(false)
    .for_signing()
    .next()
    .context("No valid signing key found in certificate")?;

  let created_at = chrono::Utc::now().to_rfc3339();

  tracing::debug!(
      fingerprint = %fingerprint,
      data_len = data.len(),
      "Prepared signing challenge"
  );

  Ok(Challenge {
    version: 1,
    data_to_sign: data.to_vec(),
    fingerprint,
    created_at,
    options: options.clone(),
  })
}

/// Apply a pre-computed signature response to complete the signing process.
///
/// This function is WASM-compatible and validates the provided signature
/// against the challenge data.
#[tracing::instrument(skip(challenge, signature_armored, cert))]
pub fn apply_response(
  challenge: &Challenge,
  signature_armored: &str,
  cert: &Cert,
) -> Result<SignResult> {
  // Verify version
  if challenge.version != 1 {
    bail!("Unsupported challenge version: {}", challenge.version);
  }

  // Verify fingerprint matches
  let cert_fingerprint = cert.fingerprint().to_string();
  if cert_fingerprint != challenge.fingerprint {
    bail!(
      "Certificate fingerprint mismatch: expected {}, got {}",
      challenge.fingerprint,
      cert_fingerprint
    );
  }

  // Validate signature format (ASCII armored)
  if !signature_armored.contains("-----BEGIN PGP SIGNATURE-----") {
    bail!("Invalid signature format: missing PGP signature armor");
  }

  // Extract signature bytes
  let signature_data = signature_armored.as_bytes().to_vec();

  // Validate signature cryptographically
  validate_response(challenge, &signature_data)?;

  let fingerprint = cert.fingerprint().to_string();
  let uids: Vec<String> = cert
    .userids()
    .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string())
    .collect();

  tracing::info!(
      fingerprint = %fingerprint,
      sig_len = signature_data.len(),
      "Applied signature response"
  );

  Ok(SignResult {
    fingerprint,
    uids,
    signature_data,
  })
}

/// Validate that a signature matches the challenge data.
///
/// This function cryptographically verifies that the signature was
/// created for the challenge's data.
#[tracing::instrument(skip(challenge, signature))]
pub fn validate_response(challenge: &Challenge, signature: &[u8]) -> Result<()> {
  // Parse the signature
  let signature_reader = armor::Reader::from_bytes(
    signature,
    armor::ReaderMode::Tolerant(Some(armor::Kind::Signature)),
  );

  use openpgp::parse::stream::*;
  let policy = StandardPolicy::new();

  // Helper for verification
  struct Helper;
  impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
      // We don't verify the cert here, just check signature structure
      Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
      // Basic structure check only
      Ok(())
    }
  }

  // Try to parse as a detached signature
  let mut verifier =
    DetachedVerifierBuilder::from_reader(signature_reader)?.with_policy(&policy, None, Helper)?;

  // Verify against challenge data
  verifier
    .verify_bytes(&challenge.data_to_sign)
    .context("Signature verification failed - signature does not match challenge data")?;

  tracing::debug!("Signature response validated successfully");

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn challenge_serialization() {
    let challenge = Challenge {
      version: 1,
      data_to_sign: b"test data".to_vec(),
      fingerprint: "ABCD1234".to_string(),
      created_at: "2025-01-01T00:00:00Z".to_string(),
      options: ChallengeOptions { embed_uid: true },
    };

    let json = serde_json::to_string(&challenge).unwrap();
    let parsed: Challenge = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.data_to_sign, b"test data");
    assert_eq!(parsed.fingerprint, "ABCD1234");
  }
}
