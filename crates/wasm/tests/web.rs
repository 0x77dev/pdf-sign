//! WASM integration tests
//!
//! Run with: wasm-pack test --headless --chrome

#![cfg(target_arch = "wasm32")]

use pdf_sign_wasm::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_challenge_structure() {
  let challenge = Challenge {
    version: 1,
    fingerprint: "ABCD1234".to_string(),
    data_base64: "SGVsbG8gV29ybGQ=".to_string(),
    gpg_command: "gpg --detach-sign".to_string(),
    created_at: "2025-01-01T00:00:00Z".to_string(),
    embed_uid: false,
  };

  assert_eq!(challenge.version, 1);
  assert_eq!(challenge.fingerprint, "ABCD1234");
  assert!(!challenge.embed_uid);
}

#[wasm_bindgen_test]
fn test_verification_result() {
  let sig_info = SignatureInfo {
    fingerprint: "TEST123".to_string(),
    uids: vec!["Test User <test@example.com>".to_string()],
  };

  let result = VerificationResult {
    valid: true,
    gpg_signatures: vec![sig_info.clone()],
  };

  assert!(result.valid);
  assert_eq!(result.gpg_signatures.len(), 1);
  assert_eq!(result.gpg_signatures[0].fingerprint, "TEST123");
}

#[wasm_bindgen_test]
fn test_challenge_serialization() {
  let challenge = Challenge {
    version: 1,
    fingerprint: "ABCD".to_string(),
    data_base64: "dGVzdA==".to_string(),
    gpg_command: "test".to_string(),
    created_at: "2025-01-01T00:00:00Z".to_string(),
    embed_uid: true,
  };

  // Test that it can be serialized/deserialized
  let json = serde_json::to_string(&challenge).expect("Failed to serialize");
  let parsed: Challenge = serde_json::from_str(&json).expect("Failed to deserialize");

  assert_eq!(parsed.version, challenge.version);
  assert_eq!(parsed.fingerprint, challenge.fingerprint);
  assert_eq!(parsed.embed_uid, challenge.embed_uid);
}
