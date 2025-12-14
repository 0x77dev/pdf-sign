//! OpenPGP signing and verification backend using sequoia-openpgp and gpg-agent.

#[cfg(feature = "native")]
pub mod keybox;

pub mod verify;

#[cfg(feature = "native")]
pub mod sign;

#[cfg(feature = "challenge")]
pub mod challenge;

#[cfg(feature = "native")]
pub use keybox::{find_certs_in_keybox, load_cert, load_keybox_certs};

#[cfg(feature = "native")]
pub use sign::{SignOptions, SignResult, create_signature};

#[cfg(feature = "challenge")]
pub use challenge::{
  Challenge, ChallengeOptions, apply_response, prepare_challenge, validate_response,
};

pub use verify::{
  CertSource, VerifyOptions, VerifyResult, extract_pgp_signatures, verify_signatures,
};
