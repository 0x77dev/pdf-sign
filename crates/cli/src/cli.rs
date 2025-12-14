use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
  name = "pdf-sign",
  about = "Secure PDF signing with OpenPGP and Sigstore",
  long_about = "Sign and verify PDFs using OpenPGP (gpg-agent) or Sigstore (keyless OIDC)."
)]
pub struct Cli {
  #[command(subcommand)]
  pub command: Commands,

  /// Output machine-readable JSON to stdout
  #[arg(long, global = true)]
  pub json: bool,

  /// Enable verbose logging (sets RUST_LOG=debug if not already set)
  #[arg(short, long, global = true)]
  pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
  /// Sign a PDF file with GPG or Sigstore
  Sign {
    /// Path to the PDF file to sign
    input: PathBuf,

    /// Output path for signed PDF (default: <input>_signed.pdf)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Signing backend to use
    #[arg(short, long, value_enum, default_value = "gpg")]
    backend: SigningBackend,

    // GPG-specific options
    /// Key specification: file path (.asc), fingerprint, key ID, or email (GPG backend only)
    #[arg(short, long, required_if_eq("backend", "gpg"))]
    key: Option<String>,

    /// Embed signer UID into the OpenPGP signature (GPG backend only)
    #[arg(long)]
    embed_uid: bool,

    // Sigstore-specific options
    /// OIDC issuer URL (Sigstore backend, default: https://oauth2.sigstore.dev/auth)
    #[arg(long)]
    oidc_issuer: Option<String>,

    /// Fulcio URL (Sigstore backend, default: https://fulcio.sigstore.dev)
    #[arg(long)]
    fulcio_url: Option<String>,

    /// Rekor URL (Sigstore backend, default: https://rekor.sigstore.dev)
    #[arg(long)]
    rekor_url: Option<String>,

    /// OIDC client ID (Sigstore backend, default: sigstore)
    #[arg(long)]
    oidc_client_id: Option<String>,

    /// OIDC client secret (Sigstore backend, default: empty)
    #[arg(long)]
    oidc_client_secret: Option<String>,

    /// Identity token (JWT) for non-interactive signing (Sigstore backend, CI mode)
    #[arg(long)]
    identity_token: Option<String>,

    /// Digest algorithm (Sigstore backend, default: sha512)
    #[arg(long, default_value = "sha512")]
    digest_algorithm: String,
  },

  /// Verify a signed PDF file (handles both GPG and Sigstore signatures)
  Verify {
    /// Path to the signed PDF file
    input: PathBuf,

    // GPG verification options
    /// Optional GPG certificate/key spec for OpenPGP verification (can be provided multiple times)
    /// If omitted, uses your GnuPG keybox (pubring.kbx)
    #[arg(short, long)]
    cert: Vec<String>,

    // Sigstore verification options
    /// Expected certificate identity for Sigstore signatures (email, URI, etc.)
    #[arg(long)]
    certificate_identity: Option<String>,

    /// Expected certificate identity (regex) for Sigstore signatures
    #[arg(long, conflicts_with = "certificate_identity")]
    certificate_identity_regexp: Option<String>,

    /// Expected OIDC issuer for Sigstore signatures
    #[arg(long)]
    certificate_oidc_issuer: Option<String>,

    /// Expected OIDC issuer (regex) for Sigstore signatures
    #[arg(long, conflicts_with = "certificate_oidc_issuer")]
    certificate_oidc_issuer_regexp: Option<String>,

    /// Perform offline verification for Sigstore (no network calls)
    #[arg(long)]
    offline: bool,
  },

  /// Prepare a signing challenge for remote/air-gapped GPG signing
  Challenge {
    /// Path to the PDF file to prepare challenge for
    input: PathBuf,

    /// Key specification: file path (.asc), fingerprint, key ID, or email
    #[arg(short, long)]
    key: String,

    /// Output path for challenge JSON (default: stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Embed signer UID into the signature
    #[arg(long)]
    embed_uid: bool,
  },

  /// Apply a signature response to complete challenge-response signing
  ApplyResponse {
    /// Path to the original PDF file
    input: PathBuf,

    /// Path to the challenge JSON file
    #[arg(short, long)]
    challenge: PathBuf,

    /// Path to the signature file (.asc)
    #[arg(short, long)]
    signature: PathBuf,

    /// Output path for signed PDF (default: <input>_signed.pdf)
    #[arg(short, long)]
    output: Option<PathBuf>,
  },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SigningBackend {
  /// OpenPGP signing via gpg-agent
  Gpg,
  /// Sigstore keyless signing via OIDC
  Sigstore,
}
