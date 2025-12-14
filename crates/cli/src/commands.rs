//! Unified verify command and challenge-response commands.

use anyhow::{Context, Result, bail};
use base64::Engine;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use pdf_sign_core::{
  split_pdf,
  suffix::{SuffixBlock, encode_suffix_block, parse_suffix_blocks},
};
use pdf_sign_gpg::{VerifyOptions as GpgVerifyOptions, load_cert};
use pdf_sign_sigstore::verify::{
  CertificateIdentityMatcher, OidcIssuerMatcher, VerifyOptions as SigstoreVerifyOptions,
  VerifyPolicy, verify_blob,
};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use crate::json::{SigstoreVerifiedSigJson, UnifiedVerifyJson, VerifySignatureJson};
use crate::util::format_bytes;

#[allow(clippy::too_many_arguments)]
pub fn verify_pdf(
  input: PathBuf,
  cert_spec: Vec<String>,
  certificate_identity: Option<String>,
  certificate_identity_regexp: Option<String>,
  certificate_oidc_issuer: Option<String>,
  certificate_oidc_issuer_regexp: Option<String>,
  offline: bool,
  json: bool,
) -> Result<()> {
  eprintln!("{}", style("==> Verifying PDF signatures").cyan().bold());

  let spinner = ProgressBar::new_spinner();
  spinner.set_style(
    ProgressStyle::default_spinner()
      .template("{spinner:.cyan} {msg}")
      .unwrap(),
  );
  spinner.enable_steady_tick(Duration::from_millis(80));
  spinner.set_message(format!(
    "Reading signed PDF {}",
    style(input.display()).cyan()
  ));

  let mut signed_data = Vec::new();
  let mut file = BufReader::new(
    File::open(&input)
      .with_context(|| format!("Failed to open signed PDF: {}", input.display()))?,
  );
  file.read_to_end(&mut signed_data)?;

  spinner.finish_with_message(format!(
    "[OK] Read PDF ({})",
    style(format_bytes(signed_data.len())).cyan()
  ));

  let (pdf_data, suffix) = split_pdf(&signed_data)?;
  let blocks = parse_suffix_blocks(suffix)?;

  if blocks.is_empty() {
    bail!("No signatures found after %%EOF marker");
  }

  eprintln!(
    "    Found {} signature block(s)",
    style(blocks.len()).cyan()
  );

  // Separate GPG and Sigstore blocks
  let mut gpg_sigs = Vec::new();
  let mut sigstore_blocks = Vec::new();

  for block in blocks {
    match block {
      SuffixBlock::OpenPgpSig(data) => gpg_sigs.push(data),
      SuffixBlock::SigstoreBundle(bundle) => sigstore_blocks.push(bundle),
    }
  }

  let mut gpg_verified = Vec::new();
  let mut sigstore_verified = Vec::new();

  // Verify GPG signatures if any
  if !gpg_sigs.is_empty() {
    eprintln!("    Verifying {} OpenPGP signature(s)...", gpg_sigs.len());

    let certs = cert_spec
      .iter()
      .map(|spec| load_cert(spec))
      .collect::<Result<Vec<_>>>()?;

    let options = GpgVerifyOptions { certs };
    let verify_result = pdf_sign_gpg::verify::verify_signatures(pdf_data, &gpg_sigs, &options)?;

    gpg_verified = verify_result.verified;
    eprintln!(
      "      {} {} OpenPGP signature(s)",
      style("[OK]").green().bold(),
      gpg_verified.len()
    );
  }

  // Verify Sigstore signatures if any
  if !sigstore_blocks.is_empty() {
    eprintln!(
      "    Verifying {} Sigstore signature(s)...",
      sigstore_blocks.len()
    );

    // Build policy if identity constraints provided
    let has_sigstore_constraints = certificate_identity.is_some()
      || certificate_identity_regexp.is_some()
      || certificate_oidc_issuer.is_some()
      || certificate_oidc_issuer_regexp.is_some();

    if !has_sigstore_constraints {
      bail!(
        "Sigstore signatures found, but no verification policy provided.\n\
                 Please specify --certificate-identity and --certificate-oidc-issuer\n\
                 (or their regexp variants) to verify Sigstore signatures."
      );
    }

    let cert_identity_matcher = match (certificate_identity, certificate_identity_regexp) {
      (Some(exact), None) => Some(CertificateIdentityMatcher::Exact(exact)),
      (None, Some(re)) => Some(CertificateIdentityMatcher::Regexp(re)),
      _ => None,
    };

    let cert_issuer_matcher = match (certificate_oidc_issuer, certificate_oidc_issuer_regexp) {
      (Some(exact), None) => Some(OidcIssuerMatcher::Exact(exact)),
      (None, Some(re)) => Some(OidcIssuerMatcher::Regexp(re)),
      _ => None,
    };

    let policy = VerifyPolicy {
      certificate_identity: cert_identity_matcher,
      certificate_oidc_issuer: cert_issuer_matcher,
    };

    let options = SigstoreVerifyOptions { policy, offline };

    let rt = tokio::runtime::Runtime::new()?;

    for bundle_block in &sigstore_blocks {
      let result = rt.block_on(verify_blob(pdf_data, bundle_block, &options))?;
      sigstore_verified.push(result);
    }

    eprintln!(
      "      {} {} Sigstore signature(s)",
      style("[OK]").green().bold(),
      sigstore_verified.len()
    );
  }

  eprintln!(
    "\n{} {}",
    style("[VALID]").green().bold(),
    style("All signatures verified").green()
  );

  // Display results
  if !gpg_verified.is_empty() {
    eprintln!("\n    OpenPGP signatures:");
    for (i, sig) in gpg_verified.iter().enumerate() {
      eprintln!(
        "      {}. Fingerprint: {}",
        i + 1,
        style(&sig.key_fingerprint).cyan()
      );
      for uid in &sig.uids {
        eprintln!("         Identity: {}", style(uid).cyan());
      }
    }
  }

  if !sigstore_verified.is_empty() {
    eprintln!("\n    Sigstore signatures:");
    for (i, sig) in sigstore_verified.iter().enumerate() {
      eprintln!(
        "      {}. Identity: {}",
        i + 1,
        style(&sig.certificate_identity).cyan()
      );
      eprintln!(
        "         Issuer: {}",
        style(&sig.certificate_oidc_issuer).cyan()
      );
      if let Some(idx) = sig.rekor_log_index {
        eprintln!("         Rekor: {}", style(format!("index {}", idx)).cyan());
      }
    }
  }

  if json {
    let gpg_sigs: Vec<VerifySignatureJson> = gpg_verified
      .into_iter()
      .map(|v| VerifySignatureJson {
        key_fingerprint: v.key_fingerprint,
        uids: v.uids,
        cert_source: v.source,
      })
      .collect();

    let sigstore_sigs: Vec<SigstoreVerifiedSigJson> = sigstore_verified
      .into_iter()
      .map(|v| SigstoreVerifiedSigJson {
        certificate_identity: v.certificate_identity,
        certificate_oidc_issuer: v.certificate_oidc_issuer,
        rekor_log_index: v.rekor_log_index,
      })
      .collect();

    let payload = UnifiedVerifyJson {
      status: "ok",
      command: "verify",
      input: input.display().to_string(),
      openpgp_signatures: gpg_sigs,
      sigstore_signatures: sigstore_sigs,
    };
    println!("{}", serde_json::to_string(&payload)?);
  } else {
    // Only print "OK" when stdout is piped (for pipeline composition)
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
      println!("OK");
    }
  }

  Ok(())
}

/// Prepare a signing challenge for remote/air-gapped GPG signing.
pub fn prepare_challenge(
  input: PathBuf,
  key_spec: String,
  output: Option<PathBuf>,
  embed_uid: bool,
  json: bool,
) -> Result<()> {
  eprintln!("{}", style("==> Preparing signing challenge").cyan().bold());

  let spinner = ProgressBar::new_spinner();
  spinner.set_style(
    ProgressStyle::default_spinner()
      .template("{spinner:.cyan} {msg}")
      .unwrap(),
  );
  spinner.enable_steady_tick(Duration::from_millis(80));

  spinner.set_message(format!("Reading PDF {}", style(input.display()).cyan()));
  let mut pdf_data = Vec::new();
  let mut file = BufReader::new(
    File::open(&input).with_context(|| format!("Failed to open PDF: {}", input.display()))?,
  );
  file.read_to_end(&mut pdf_data)?;
  spinner.finish_with_message(format!(
    "[OK] Read PDF ({})",
    style(format_bytes(pdf_data.len())).cyan()
  ));

  let (clean_pdf, _suffix) = split_pdf(&pdf_data)?;

  // Load certificate
  let cert = load_cert(&key_spec)?;
  let fingerprint = cert.fingerprint();
  let uids: Vec<_> = cert
    .userids()
    .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string())
    .collect();

  eprintln!(
    "    Using key: {} ({})",
    style(&fingerprint).cyan(),
    style(uids.join(", ")).dim()
  );

  // Prepare challenge
  let options = pdf_sign_gpg::challenge::ChallengeOptions { embed_uid };
  let challenge = pdf_sign_gpg::challenge::prepare_challenge(clean_pdf, &cert, &options)?;

  // Create challenge JSON with helper command
  let data_base64 = base64::engine::general_purpose::STANDARD.encode(&challenge.data_to_sign);
  let gpg_command = format!(
    "echo '{}' | base64 -d | gpg --detach-sign --armor -u {} > signature.asc",
    data_base64, fingerprint
  );

  #[derive(serde::Serialize)]
  struct ChallengeJson {
    version: u32,
    fingerprint: String,
    data_base64: String,
    gpg_command: String,
    created_at: String,
    embed_uid: bool,
  }

  let challenge_json = ChallengeJson {
    version: challenge.version,
    fingerprint: challenge.fingerprint.clone(),
    data_base64,
    gpg_command,
    created_at: challenge.created_at.clone(),
    embed_uid,
  };

  let json_output = serde_json::to_string_pretty(&challenge_json)?;

  if let Some(output_path) = output {
    let mut out = BufWriter::new(
      File::create(&output_path)
        .with_context(|| format!("Failed to create output file: {}", output_path.display()))?,
    );
    writeln!(out, "{}", json_output)?;
    out.flush()?;

    eprintln!(
      "\n{} {}",
      style("[SUCCESS]").green().bold(),
      style("Challenge prepared").cyan()
    );
    eprintln!(
      "    Challenge file: {}",
      style(output_path.display()).cyan()
    );

    if !json {
      println!("{}", output_path.display());
    }
  } else {
    // Output to stdout
    println!("{}", json_output);
  }

  if !json {
    eprintln!("\n    Next steps:");
    eprintln!("    1. Copy the challenge to the signing machine");
    eprintln!("    2. Run the gpg_command shown above (or equivalent)");
    eprintln!("    3. Use 'pdf-sign apply-response' with the returned signature");
  }

  Ok(())
}

/// Apply a signature response to complete challenge-response signing.
pub fn apply_response(
  input: PathBuf,
  challenge_path: PathBuf,
  signature_path: PathBuf,
  output: Option<PathBuf>,
  json_output: bool,
) -> Result<()> {
  eprintln!("{}", style("==> Applying signature response").cyan().bold());

  let spinner = ProgressBar::new_spinner();
  spinner.set_style(
    ProgressStyle::default_spinner()
      .template("{spinner:.cyan} {msg}")
      .unwrap(),
  );
  spinner.enable_steady_tick(Duration::from_millis(80));

  // Read PDF
  spinner.set_message(format!("Reading PDF {}", style(input.display()).cyan()));
  let mut pdf_data = Vec::new();
  let mut file = BufReader::new(
    File::open(&input).with_context(|| format!("Failed to open PDF: {}", input.display()))?,
  );
  file.read_to_end(&mut pdf_data)?;
  spinner.finish_with_message(format!(
    "[OK] Read PDF ({})",
    style(format_bytes(pdf_data.len())).cyan()
  ));

  let (clean_pdf, suffix) = split_pdf(&pdf_data)?;
  let existing_blocks = parse_suffix_blocks(suffix)?;

  // Read challenge
  let challenge_data = std::fs::read_to_string(&challenge_path)
    .with_context(|| format!("Failed to read challenge: {}", challenge_path.display()))?;

  #[derive(serde::Deserialize)]
  struct ChallengeJson {
    version: u32,
    fingerprint: String,
    data_base64: String,
    created_at: String,
    embed_uid: bool,
  }

  let challenge_json: ChallengeJson =
    serde_json::from_str(&challenge_data).context("Failed to parse challenge JSON")?;

  // Reconstruct Challenge
  let data_to_sign = base64::engine::general_purpose::STANDARD
    .decode(&challenge_json.data_base64)
    .context("Failed to decode challenge data")?;

  let challenge = pdf_sign_gpg::challenge::Challenge {
    version: challenge_json.version,
    data_to_sign,
    fingerprint: challenge_json.fingerprint.clone(),
    created_at: challenge_json.created_at,
    options: pdf_sign_gpg::challenge::ChallengeOptions {
      embed_uid: challenge_json.embed_uid,
    },
  };

  // Read signature
  let signature_armored = std::fs::read_to_string(&signature_path)
    .with_context(|| format!("Failed to read signature: {}", signature_path.display()))?;

  // Load certificate
  let cert = load_cert(&challenge.fingerprint)?;

  // Apply response
  spinner.set_message("Validating and applying signature...");
  let sign_result = pdf_sign_gpg::challenge::apply_response(&challenge, &signature_armored, &cert)?;

  spinner.finish_with_message(format!(
    "[OK] Applied signature ({})",
    style(format_bytes(sign_result.signature_data.len())).cyan()
  ));

  // Determine output path
  let output_path = match output {
    Some(p) => p,
    None => {
      let mut p = input.clone();
      let stem = p.file_stem().context("Invalid input path")?;
      let mut name = stem.to_os_string();
      name.push("_signed.pdf");
      p.set_file_name(name);
      p
    }
  };

  // Write signed PDF
  spinner.set_message(format!(
    "Writing signed PDF to {}",
    style(output_path.display()).cyan()
  ));

  let mut out = BufWriter::new(
    File::create(&output_path)
      .with_context(|| format!("Failed to create output file: {}", output_path.display()))?,
  );

  out.write_all(clean_pdf)?;
  out.write_all(b"\n")?;

  // Write existing blocks
  for block in &existing_blocks {
    let encoded = encode_suffix_block(block);
    out.write_all(&encoded)?;
  }

  // Write new signature
  out.write_all(&sign_result.signature_data)?;
  out.flush()?;

  eprintln!(
    "\n{} {}",
    style("[SUCCESS]").green().bold(),
    style("Signature applied successfully").cyan()
  );

  if json_output {
    #[derive(serde::Serialize)]
    struct ApplyResponseJson {
      status: &'static str,
      command: &'static str,
      input: String,
      output: String,
      key_fingerprint: String,
      uids: Vec<String>,
    }

    let payload = ApplyResponseJson {
      status: "ok",
      command: "apply-response",
      input: input.display().to_string(),
      output: output_path.display().to_string(),
      key_fingerprint: sign_result.fingerprint,
      uids: sign_result.uids,
    };
    println!("{}", serde_json::to_string(&payload)?);
  } else {
    println!("{}", output_path.display());
  }

  Ok(())
}
