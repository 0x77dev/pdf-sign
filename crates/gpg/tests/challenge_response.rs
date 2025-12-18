//! Integration tests for challenge-response workflow

use openpgp::cert::prelude::*;
use pdf_sign_gpg::challenge::{Challenge, ChallengeOptions, prepare_challenge, validate_response};
use sequoia_openpgp as openpgp;

fn make_test_cert() -> Cert {
  let (cert, _revocation) = CertBuilder::general_purpose(Some("CI Test <ci@example.invalid>"))
    .generate()
    .expect("Failed to generate cert");
  cert
}

#[test]
fn test_prepare_challenge() {
  let cert = make_test_cert();
  let data = b"test data to sign";

  let options = ChallengeOptions { embed_uid: false };
  let challenge = prepare_challenge(data, &cert, &options).expect("Failed to prepare challenge");

  assert_eq!(challenge.version, 1);
  assert_eq!(challenge.data_to_sign, data);
  assert!(!challenge.fingerprint.is_empty());
  assert_eq!(challenge.options.embed_uid, false);
}

#[test]
fn test_challenge_with_embed_uid() {
  let cert = make_test_cert();
  let data = b"test data";

  let options = ChallengeOptions { embed_uid: true };
  let challenge = prepare_challenge(data, &cert, &options).expect("Failed to prepare challenge");

  assert_eq!(challenge.options.embed_uid, true);
}

#[test]
fn test_challenge_serialization() {
  let challenge = Challenge {
    version: 1,
    data_to_sign: b"test".to_vec(),
    fingerprint: "ABCD1234".to_string(),
    created_at: "2025-01-01T00:00:00Z".to_string(),
    options: ChallengeOptions { embed_uid: false },
  };

  let json = serde_json::to_string(&challenge).expect("Failed to serialize");
  let parsed: Challenge = serde_json::from_str(&json).expect("Failed to deserialize");

  assert_eq!(parsed.version, challenge.version);
  assert_eq!(parsed.data_to_sign, challenge.data_to_sign);
  assert_eq!(parsed.fingerprint, challenge.fingerprint);
}

#[test]
fn test_validate_response_rejects_invalid_signature() {
  let cert = make_test_cert();
  let challenge = Challenge {
    version: 1,
    data_to_sign: b"test data".to_vec(),
    fingerprint: "ABCD1234".to_string(),
    created_at: chrono::Utc::now().to_rfc3339(),
    options: ChallengeOptions { embed_uid: false },
  };

  // Invalid signature (not a valid PGP signature)
  let invalid_sig = b"not a signature";

  let result = validate_response(&challenge, invalid_sig, &cert);
  assert!(result.is_err());
}
