//! Sigstore keyless signing (OIDC + Fulcio + Rekor).

use anyhow::{Context, Result, bail};
use pdf_sign_core::{DigestAlgorithm, compute_digest, suffix::SigstoreBundleBlock};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Sigstore service endpoints configuration.
#[derive(Debug, Clone)]
pub struct SigstoreEndpoints {
  pub oidc_issuer: String,
  pub fulcio_url: String,
  pub rekor_url: String,
  pub oidc_client_id: String,
  pub oidc_client_secret: String,
}

impl Default for SigstoreEndpoints {
  fn default() -> Self {
    Self {
      oidc_issuer: crate::DEFAULT_OIDC_ISSUER.to_string(),
      fulcio_url: crate::DEFAULT_FULCIO_URL.to_string(),
      rekor_url: crate::DEFAULT_REKOR_URL.to_string(),
      oidc_client_id: crate::DEFAULT_OIDC_CLIENT_ID.to_string(),
      oidc_client_secret: String::new(),
    }
  }
}

/// Options for Sigstore signing.
#[derive(Debug, Clone)]
pub struct SignOptions {
  pub endpoints: SigstoreEndpoints,
  pub digest_algorithm: DigestAlgorithm,
  /// If provided, use this token directly (for CI). Otherwise, perform interactive OIDC flow.
  pub identity_token: Option<String>,
}

impl Default for SignOptions {
  fn default() -> Self {
    Self {
      endpoints: SigstoreEndpoints::default(),
      digest_algorithm: DigestAlgorithm::Sha512,
      identity_token: None,
    }
  }
}

/// Result of a Sigstore signing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
  pub certificate_identity: String,
  pub certificate_oidc_issuer: String,
  pub rekor_log_index: Option<u64>,
  pub bundle_block: SigstoreBundleBlock,
}

/// Sign a blob using Sigstore keyless (OIDC) signing.
///
/// This performs the following steps:
/// 1. Obtain identity token via OIDC flow (or use provided token)
/// 2. Generate ephemeral key pair
/// 3. Request short-lived certificate from Fulcio
/// 4. Sign the data
/// 5. Upload signature to Rekor transparency log
/// 6. Return bundle containing signature + certificate + transparency log proof
#[tracing::instrument(skip(data, options), fields(data_len = data.len()))]
pub async fn sign_blob(data: &[u8], options: &SignOptions) -> Result<SignResult> {
  tracing::info!("Starting Sigstore keyless signing");

  // Initialize signing context with configured endpoints
  let signing_ctx = sigstore::bundle::sign::SigningContext::async_production()
    .await
    .context("Failed to initialize Sigstore signing context")?;

  // Obtain identity token
  let identity_token = if let Some(token) = &options.identity_token {
    tracing::debug!("Using provided identity token");
    // Parse the raw JWT token
    sigstore::oauth::IdentityToken::from(
      openidconnect::IdToken::from_str(token).context("Failed to parse identity token")?,
    )
  } else {
    tracing::debug!("Starting interactive OIDC flow");
    obtain_identity_token(&options.endpoints)?
  };

  // Create signing session
  tracing::debug!("Creating signing session");
  let signing_session = signing_ctx
    .signer(identity_token)
    .await
    .context("Failed to create signing session")?;

  // Sign the data (need owned data for Cursor)
  tracing::debug!("Signing data");
  let signing_artifact = signing_session
    .sign(std::io::Cursor::new(data.to_vec()))
    .await
    .context("Signing failed")?;

  // Convert to bundle
  let bundle = signing_artifact.to_bundle();

  // Extract cert identity and issuer from bundle
  let (cert_identity, cert_issuer) = extract_bundle_info(&bundle)?;
  let rekor_log_index = bundle
    .verification_material
    .as_ref()
    .and_then(|vm| vm.tlog_entries.first())
    .map(|entry| entry.log_index as u64);

  // Compute digest for the bundle block
  let digest = compute_digest(options.digest_algorithm, data);
  let bundle_json = serde_json::to_vec(&bundle).context("Failed to serialize bundle to JSON")?;

  let bundle_block = SigstoreBundleBlock {
    version: 1,
    signed_range_len: data.len() as u64,
    digest_alg: options.digest_algorithm as u8,
    digest,
    bundle_json,
  };

  tracing::info!(
      cert_identity = %cert_identity,
      rekor_index = ?rekor_log_index,
      "Sigstore signing complete"
  );

  Ok(SignResult {
    certificate_identity: cert_identity,
    certificate_oidc_issuer: cert_issuer,
    rekor_log_index,
    bundle_block,
  })
}

/// Extract certificate identity and issuer from bundle.
fn extract_bundle_info(bundle: &sigstore::bundle::Bundle) -> Result<(String, String)> {
  use x509_cert::Certificate;
  use x509_cert::der::Decode;

  let vm = bundle
    .verification_material
    .as_ref()
    .ok_or_else(|| anyhow::anyhow!("Bundle does not contain verification material"))?;

  let cert_data = match &vm.content {
        Some(sigstore_protobuf_specs::dev::sigstore::bundle::v1::verification_material::Content::X509CertificateChain(chain)) => {
            chain
                .certificates
                .first()
                .ok_or_else(|| anyhow::anyhow!("Certificate chain is empty"))?
                .raw_bytes
                .as_slice()
        }
        _ => bail!("Bundle does not contain X509 certificate chain"),
    };

  // Parse certificate
  let cert = Certificate::from_der(cert_data).context("Failed to parse certificate")?;

  // Extract SAN for identity
  let san_ext = cert
    .tbs_certificate
    .extensions
    .as_ref()
    .and_then(|exts| {
      exts
        .iter()
        .find(|ext| ext.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME)
    })
    .ok_or_else(|| anyhow::anyhow!("Certificate does not contain Subject Alternative Name"))?;

  use x509_cert::ext::pkix::SubjectAltName;
  let san = SubjectAltName::from_der(san_ext.extn_value.as_bytes())
    .context("Failed to parse SAN extension")?;

  // Extract first email or URI from SAN
  use x509_cert::ext::pkix::name::GeneralName;
  let identity = san
    .0
    .iter()
    .find_map(|name| match name {
      GeneralName::Rfc822Name(email) => Some(email.to_string()),
      GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
      _ => None,
    })
    .ok_or_else(|| anyhow::anyhow!("No email or URI found in certificate SAN"))?;

  // Extract issuer from OIDC Issuer extension (OID 1.3.6.1.4.1.57264.1.1)
  let issuer_oid =
    const_oid::ObjectIdentifier::new("1.3.6.1.4.1.57264.1.1").expect("Invalid issuer OID");

  let issuer = cert
    .tbs_certificate
    .extensions
    .as_ref()
    .and_then(|exts| exts.iter().find(|ext| ext.extn_id == issuer_oid))
    .map(|ext| String::from_utf8_lossy(ext.extn_value.as_bytes()).to_string())
    .unwrap_or_else(|| "unknown".to_string());

  Ok((identity, issuer))
}

/// Perform interactive OIDC authorization flow.
fn obtain_identity_token(endpoints: &SigstoreEndpoints) -> Result<sigstore::oauth::IdentityToken> {
  tracing::debug!("Initiating OIDC authorization");

  let oidc_url = sigstore::oauth::openidflow::OpenIDAuthorize::new(
    &endpoints.oidc_client_id,
    &endpoints.oidc_client_secret,
    &endpoints.oidc_issuer,
    "http://localhost:8080",
  )
  .auth_url()
  .context("Failed to create OIDC authorization URL")?;

  // Open browser for user authorization
  webbrowser::open(oidc_url.0.as_ref()).context("Failed to open browser for OIDC authorization")?;

  tracing::debug!("Waiting for OIDC callback");
  let listener = sigstore::oauth::openidflow::RedirectListener::new(
    "127.0.0.1:8080",
    oidc_url.1, // client
    oidc_url.2, // nonce
    oidc_url.3, // pkce_verifier
  );

  let (_, token) = listener
    .redirect_listener()
    .context("Failed to obtain identity token")?;

  tracing::debug!("Identity token obtained");
  Ok(sigstore::oauth::IdentityToken::from(token))
}
