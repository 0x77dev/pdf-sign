//! Common types and result structures.

use serde::{Deserialize, Serialize};

/// Result of a successful signature verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedSignature {
  pub key_fingerprint: String,
  pub uids: Vec<String>,
  pub source: String,
}

/// Verification result for Sigstore signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedSigstoreSignature {
  pub certificate_identity: String,
  pub certificate_oidc_issuer: String,
  pub rekor_log_index: Option<u64>,
}
