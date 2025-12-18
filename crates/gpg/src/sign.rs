//! OpenPGP signing using gpg-agent.

use anyhow::{Context, Result};
use openpgp::armor;
use openpgp::cert::prelude::*;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::*;
use openpgp::types::SignatureType;
use sequoia_openpgp as openpgp;
use std::io::Write;

/// Options for OpenPGP signing.
#[derive(Debug, Clone)]
pub struct SignOptions {
  /// Embed signer UID into the signature as notation.
  pub embed_uid: bool,
}

/// Result of a signing operation.
#[derive(Debug, Clone)]
pub struct SignResult {
  pub fingerprint: String,
  pub uids: Vec<String>,
  pub signature_data: Vec<u8>,
}

/// Create a detached OpenPGP signature for the given data using gpg-agent.
#[tracing::instrument(skip(data, cert), fields(data_len = data.len()))]
pub async fn create_signature(
  data: &[u8],
  cert: &Cert,
  options: &SignOptions,
) -> Result<SignResult> {
  tracing::debug!("Finding signing-capable key");
  let policy = StandardPolicy::new();
  let valid_key = cert
    .keys()
    .with_policy(&policy, None)
    .alive()
    .revoked(false)
    .for_signing()
    .next()
    .context("No valid signing key found in certificate")?
    .key()
    .clone();

  let fingerprint = cert.fingerprint().to_string();
  let uids: Vec<String> = cert
    .userids()
    .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string())
    .collect();

  let embedded_uid: Option<String> = if options.embed_uid {
    cert
      .userids()
      .next()
      .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string())
  } else {
    None
  };

  tracing::debug!("Connecting to GPG agent");
  use sequoia_gpg_agent as agent;

  let ctx = agent::Context::new().context("Failed to create GPG agent context")?;
  let agent = agent::Agent::connect(&ctx)
    .await
    .context("Failed to connect to GPG agent - is gpg-agent running?")?;

  tracing::debug!("Getting keypair from agent (may trigger PIN/touch)");
  let keypair = agent
    .keypair(&valid_key)
    .context("Failed to get keypair from agent - is the key available?")?;

  tracing::debug!("Creating detached signature");
  let mut signature_data = Vec::new();
  let mut armor_writer = armor::Writer::new(&mut signature_data, armor::Kind::Signature)?;
  let message = Message::new(&mut armor_writer);

  let mut builder = SignatureBuilder::new(SignatureType::Binary);
  if let Some(uid) = &embedded_uid {
    builder = builder.add_notation(
      "pdf-sign.uid",
      uid.as_bytes(),
      NotationDataFlags::empty().set_human_readable(),
      false,
    )?;
  }

  let mut signer = Signer::with_template(message, keypair, builder)?
    .detached()
    .build()?;
  signer.write_all(data)?;
  signer.finalize()?;
  armor_writer.finalize()?;

  tracing::info!(sig_len = signature_data.len(), "Signature created");

  Ok(SignResult {
    fingerprint,
    uids,
    signature_data,
  })
}
