//! Sigstore bundle verification.

use anyhow::{Context, Result, bail};
use pdf_sign_core::{
  DigestAlgorithm, VerifiedSigstoreSignature, compute_digest, suffix::SigstoreBundleBlock,
};

/// Verification policy for Sigstore signatures.
#[derive(Debug, Clone)]
pub struct VerifyPolicy {
  /// Expected certificate identity (email, URI, etc.). Required by default.
  pub certificate_identity: Option<CertificateIdentityMatcher>,
  /// Expected OIDC issuer. Required by default.
  pub certificate_oidc_issuer: Option<OidcIssuerMatcher>,
}

#[derive(Debug, Clone)]
pub enum CertificateIdentityMatcher {
  Exact(String),
  Regexp(String),
}

#[derive(Debug, Clone)]
pub enum OidcIssuerMatcher {
  Exact(String),
  Regexp(String),
}

/// Options for Sigstore verification.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
  pub policy: VerifyPolicy,
  pub offline: bool,
}

/// Verify a Sigstore bundle block against the given data.
///
/// Returns verified signature information on success.
#[tracing::instrument(skip(data, bundle_block), fields(data_len = data.len()))]
pub async fn verify_blob(
  data: &[u8],
  bundle_block: &SigstoreBundleBlock,
  options: &VerifyOptions,
) -> Result<VerifiedSigstoreSignature> {
  tracing::info!("Starting Sigstore verification");

  // Validate version
  if bundle_block.version != 1 {
    bail!(
      "Unsupported Sigstore bundle version: {}",
      bundle_block.version
    );
  }

  // Validate signed range length
  if bundle_block.signed_range_len != data.len() as u64 {
    bail!(
      "Signed range length mismatch: bundle claims {}, data is {}",
      bundle_block.signed_range_len,
      data.len()
    );
  }

  // Validate digest
  let digest_alg =
    DigestAlgorithm::try_from(bundle_block.digest_alg).context("Unsupported digest algorithm")?;
  let computed_digest = compute_digest(digest_alg, data);
  if computed_digest != bundle_block.digest {
    bail!("Digest mismatch: embedded digest does not match computed digest");
  }
  tracing::debug!("Digest validated");

  // Parse bundle
  let bundle: sigstore::bundle::Bundle = serde_json::from_slice(&bundle_block.bundle_json)
    .context("Failed to parse Sigstore bundle JSON")?;

  // Extract identity information from bundle before verification
  let (cert_identity_raw, cert_issuer_raw) = extract_identity_from_bundle(&bundle)?;

  // Build verification policy from options, using extracted identity for regex matching
  let identity_policy =
    build_identity_policy(&options.policy, &cert_identity_raw, &cert_issuer_raw)?;

  // Initialize verifier
  tracing::debug!("Initializing verifier");
  let verifier = sigstore::bundle::verify::Verifier::production()
    .await
    .context("Failed to create Sigstore verifier")?;

  // Verify (need owned data for Cursor)
  tracing::debug!("Verifying bundle");
  verifier
    .verify(
      std::io::Cursor::new(data.to_vec()),
      bundle.clone(),
      &identity_policy,
      options.offline,
    )
    .await
    .context("Sigstore verification failed")?;

  // Extract display information from bundle
  let (cert_identity, cert_issuer) = extract_bundle_info(&bundle)?;
  let rekor_log_index = bundle
    .verification_material
    .as_ref()
    .and_then(|vm| vm.tlog_entries.first())
    .map(|entry| entry.log_index as u64);

  tracing::info!(
      cert_identity = %cert_identity,
      cert_issuer = %cert_issuer,
      rekor_index = ?rekor_log_index,
      "Sigstore verification successful"
  );

  Ok(VerifiedSigstoreSignature {
    certificate_identity: cert_identity,
    certificate_oidc_issuer: cert_issuer,
    rekor_log_index,
  })
}

fn build_identity_policy(
  policy: &VerifyPolicy,
  actual_identity: &str,
  actual_issuer: &str,
) -> Result<sigstore::bundle::verify::policy::Identity> {
  use sigstore::bundle::verify::policy;

  // Strict policy: require both identity and issuer
  let cert_identity = policy
    .certificate_identity
    .as_ref()
    .ok_or_else(|| anyhow::anyhow!("Certificate identity is required for verification"))?;

  let cert_issuer = policy
    .certificate_oidc_issuer
    .as_ref()
    .ok_or_else(|| anyhow::anyhow!("Certificate OIDC issuer is required for verification"))?;

  // Check if actual identity matches the matcher
  let identity_matches = match cert_identity {
    CertificateIdentityMatcher::Exact(expected) => actual_identity == expected,
    CertificateIdentityMatcher::Regexp(pattern) => {
      let re = regex::Regex::new(pattern).context("Invalid certificate identity regex pattern")?;
      re.is_match(actual_identity)
    }
  };

  if !identity_matches {
    bail!(
      "Certificate identity mismatch: found '{}', expected to match policy",
      actual_identity
    );
  }

  // Check if actual issuer matches the matcher
  let issuer_matches = match cert_issuer {
    OidcIssuerMatcher::Exact(expected) => actual_issuer == expected,
    OidcIssuerMatcher::Regexp(pattern) => {
      let re = regex::Regex::new(pattern).context("Invalid OIDC issuer regex pattern")?;
      re.is_match(actual_issuer)
    }
  };

  if !issuer_matches {
    bail!(
      "OIDC issuer mismatch: found '{}', expected to match policy",
      actual_issuer
    );
  }

  // If both match, create an exact Identity policy with the actual values
  // The sigstore library will verify these exact values against the certificate
  Ok(policy::Identity::new(actual_identity, actual_issuer))
}

/// Extract raw identity and issuer strings from bundle (for regex matching).
fn extract_identity_from_bundle(bundle: &sigstore::bundle::Bundle) -> Result<(String, String)> {
  use x509_cert::Certificate;
  use x509_cert::der::Decode;
  use x509_cert::ext::pkix::name::GeneralName;

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

  // Parse certificate to extract identity
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

  // Extract the actual string value (not debug format)
  let cert_identity = san
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

  let cert_issuer = cert
    .tbs_certificate
    .extensions
    .as_ref()
    .and_then(|exts| exts.iter().find(|ext| ext.extn_id == issuer_oid))
    .and_then(|ext| String::from_utf8(ext.extn_value.clone().into_bytes()).ok())
    .unwrap_or_else(|| "unknown".to_string());

  Ok((cert_identity, cert_issuer))
}

/// Extract display-friendly bundle info (for output).
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

  // Parse certificate to extract identity
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

  let cert_identity = san
    .0
    .first()
    .map(|name| format!("{:?}", name))
    .unwrap_or_else(|| "unknown".to_string());

  // Extract issuer from OIDC Issuer extension (OID 1.3.6.1.4.1.57264.1.1)
  let issuer_oid =
    const_oid::ObjectIdentifier::new("1.3.6.1.4.1.57264.1.1").expect("Invalid issuer OID");

  let cert_issuer = cert
    .tbs_certificate
    .extensions
    .as_ref()
    .and_then(|exts| exts.iter().find(|ext| ext.extn_id == issuer_oid))
    .and_then(|ext| String::from_utf8(ext.extn_value.clone().into_bytes()).ok())
    .unwrap_or_else(|| "unknown".to_string());

  Ok((cert_identity, cert_issuer))
}
