//! Sigstore keyless (OIDC) signing and verification backend.

pub mod sign;
pub mod verify;

pub use sign::{SignOptions, SignResult, SigstoreEndpoints, sign_blob};
pub use verify::{VerifyOptions, VerifyPolicy, verify_blob};

/// Default Sigstore public endpoints.
pub const DEFAULT_OIDC_ISSUER: &str = "https://oauth2.sigstore.dev/auth";
pub const DEFAULT_FULCIO_URL: &str = "https://fulcio.sigstore.dev";
pub const DEFAULT_REKOR_URL: &str = "https://rekor.sigstore.dev";
pub const DEFAULT_OIDC_CLIENT_ID: &str = "sigstore";
