//! JSON output formats.

use serde::Serialize;

#[derive(Serialize)]
pub struct SignJson<'a> {
  pub status: &'a str,
  pub command: &'a str,
  pub input: String,
  pub output: String,
  pub key_fingerprint: String,
  pub uids: Vec<String>,
  pub embed_uid: bool,
}

#[derive(Serialize)]
pub struct VerifySignatureJson {
  pub key_fingerprint: String,
  pub uids: Vec<String>,
  pub cert_source: String,
}

#[derive(Serialize)]
pub struct SigstoreSignJson<'a> {
  pub status: &'a str,
  pub command: &'a str,
  pub input: String,
  pub output: String,
  pub certificate_identity: String,
  pub certificate_oidc_issuer: String,
  pub rekor_log_index: Option<u64>,
  pub digest_sri: String,
}

#[derive(Serialize)]
pub struct SigstoreVerifiedSigJson {
  pub certificate_identity: String,
  pub certificate_oidc_issuer: String,
  pub rekor_log_index: Option<u64>,
}

#[derive(Serialize)]
pub struct UnifiedVerifyJson<'a> {
  pub status: &'a str,
  pub command: &'a str,
  pub input: String,
  pub openpgp_signatures: Vec<VerifySignatureJson>,
  pub sigstore_signatures: Vec<SigstoreVerifiedSigJson>,
}

#[derive(Serialize)]
pub struct ErrorJson<'a> {
  pub status: &'a str,
  pub error: String,
  pub causes: Vec<String>,
}
