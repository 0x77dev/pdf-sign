//! Unified sign command with backend selection.

use anyhow::{Context, Result};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use pdf_sign_core::{
  DigestAlgorithm, encode_sri, split_pdf,
  suffix::{SuffixBlock, encode_suffix_block, parse_suffix_blocks},
};
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::json::{SignJson, SigstoreSignJson};
use crate::util::format_bytes;

fn default_signed_output_path(input: &Path) -> Result<PathBuf> {
  let mut p = input.to_path_buf();
  let stem = p
    .file_stem()
    .context("Input path must include a file name (cannot derive default output path)")?;
  let mut name: OsString = stem.to_os_string();
  name.push("_signed.pdf");
  p.set_file_name(name);
  Ok(p)
}

pub fn sign_gpg(
  input: PathBuf,
  output: Option<PathBuf>,
  key_spec: String,
  embed_uid: bool,
  json: bool,
) -> Result<()> {
  eprintln!("{}", style("==> Signing PDF with GPG agent").cyan().bold());

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

  let (clean_pdf, suffix) = split_pdf(&pdf_data)?;
  let existing_blocks = parse_suffix_blocks(suffix)?;

  let existing_pgp_sigs: Vec<_> = existing_blocks
    .iter()
    .filter_map(|b| match b {
      SuffixBlock::OpenPgpSig(data) => Some(data.clone()),
      _ => None,
    })
    .collect();

  let cert = pdf_sign_gpg::load_cert(&key_spec)?;

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

  if embed_uid && cert.userids().next().is_none() {
    eprintln!(
      "{} {}",
      style("Warning:").yellow().bold(),
      style("No UID found to embed.").dim()
    );
  }

  let spinner = ProgressBar::new_spinner();
  spinner.set_style(
    ProgressStyle::default_spinner()
      .template("{spinner:.cyan} {msg}")
      .unwrap(),
  );
  spinner.enable_steady_tick(Duration::from_millis(80));
  spinner.set_message("Connecting to GPG agent...");

  let rt = tokio::runtime::Runtime::new()?;
  let options = pdf_sign_gpg::SignOptions { embed_uid };
  let sign_result = rt.block_on(pdf_sign_gpg::sign::create_signature(
    clean_pdf, &cert, &options,
  ))?;

  spinner.finish_with_message(format!(
    "[OK] Created signature ({})",
    style(format_bytes(sign_result.signature_data.len())).cyan()
  ));

  let output_path = match output {
    Some(p) => p,
    None => default_signed_output_path(&input)?,
  };

  let spinner = ProgressBar::new_spinner();
  spinner.set_style(
    ProgressStyle::default_spinner()
      .template("{spinner:.cyan} {msg}")
      .unwrap(),
  );
  spinner.enable_steady_tick(Duration::from_millis(80));
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

  for sig in &existing_pgp_sigs {
    out.write_all(sig)?;
    if !sig.ends_with(b"\n") {
      out.write_all(b"\n")?;
    }
  }
  out.write_all(&sign_result.signature_data)?;
  out.flush()?;

  spinner.finish_and_clear();

  eprintln!(
    "\n{} {}",
    style("[SUCCESS]").green().bold(),
    style("Signed successfully").cyan()
  );

  if json {
    let payload = SignJson {
      status: "ok",
      command: "sign",
      input: input.display().to_string(),
      output: output_path.display().to_string(),
      key_fingerprint: sign_result.fingerprint,
      uids: sign_result.uids,
      embed_uid,
    };
    println!("{}", serde_json::to_string(&payload)?);
  } else {
    println!("{}", output_path.display());
  }

  Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn sign_sigstore(
  input: PathBuf,
  output: Option<PathBuf>,
  oidc_issuer: Option<String>,
  fulcio_url: Option<String>,
  rekor_url: Option<String>,
  oidc_client_id: Option<String>,
  oidc_client_secret: Option<String>,
  identity_token: Option<String>,
  digest_algorithm: String,
  json: bool,
) -> Result<()> {
  eprintln!(
    "{}",
    style("==> Signing PDF with Sigstore (keyless OIDC)")
      .cyan()
      .bold()
  );

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

  let (clean_pdf, suffix) = split_pdf(&pdf_data)?;
  let existing_blocks = parse_suffix_blocks(suffix)?;

  let digest_alg = DigestAlgorithm::from_name(&digest_algorithm)?;

  let endpoints = pdf_sign_sigstore::SigstoreEndpoints {
    oidc_issuer: oidc_issuer.unwrap_or_else(|| pdf_sign_sigstore::DEFAULT_OIDC_ISSUER.to_string()),
    fulcio_url: fulcio_url.unwrap_or_else(|| pdf_sign_sigstore::DEFAULT_FULCIO_URL.to_string()),
    rekor_url: rekor_url.unwrap_or_else(|| pdf_sign_sigstore::DEFAULT_REKOR_URL.to_string()),
    oidc_client_id: oidc_client_id
      .unwrap_or_else(|| pdf_sign_sigstore::DEFAULT_OIDC_CLIENT_ID.to_string()),
    oidc_client_secret: oidc_client_secret.unwrap_or_default(),
  };

  eprintln!("    OIDC Issuer: {}", style(&endpoints.oidc_issuer).dim());
  eprintln!("    Fulcio: {}", style(&endpoints.fulcio_url).dim());
  eprintln!("    Rekor: {}", style(&endpoints.rekor_url).dim());

  if identity_token.is_none() {
    eprintln!(
      "\n{}",
      style("Your browser will open for OIDC authentication...").yellow()
    );
  }

  spinner.set_message("Performing keyless signing...");

  let rt = tokio::runtime::Runtime::new()?;
  let sign_options = pdf_sign_sigstore::sign::SignOptions {
    endpoints,
    digest_algorithm: digest_alg,
    identity_token,
  };

  let sign_result = rt.block_on(pdf_sign_sigstore::sign::sign_blob(clean_pdf, &sign_options))?;

  spinner.finish_with_message(format!(
    "[OK] Signed with Sigstore (Rekor index: {})",
    style(
      sign_result
        .rekor_log_index
        .map(|i| i.to_string())
        .unwrap_or_else(|| "N/A".to_string())
    )
    .cyan()
  ));

  let output_path = match output {
    Some(p) => p,
    None => default_signed_output_path(&input)?,
  };

  let spinner = ProgressBar::new_spinner();
  spinner.set_style(
    ProgressStyle::default_spinner()
      .template("{spinner:.cyan} {msg}")
      .unwrap(),
  );
  spinner.enable_steady_tick(Duration::from_millis(80));
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

  for block in &existing_blocks {
    let encoded = encode_suffix_block(block);
    out.write_all(&encoded)?;
  }

  let new_block = SuffixBlock::SigstoreBundle(sign_result.bundle_block.clone());
  let encoded = encode_suffix_block(&new_block);
  out.write_all(&encoded)?;
  out.flush()?;

  spinner.finish_and_clear();

  eprintln!(
    "\n{} {}",
    style("[SUCCESS]").green().bold(),
    style("Signed successfully").cyan()
  );

  let digest_sri = encode_sri(digest_alg, &sign_result.bundle_block.digest);

  if json {
    let payload = SigstoreSignJson {
      status: "ok",
      command: "sign",
      input: input.display().to_string(),
      output: output_path.display().to_string(),
      certificate_identity: sign_result.certificate_identity,
      certificate_oidc_issuer: sign_result.certificate_oidc_issuer,
      rekor_log_index: sign_result.rekor_log_index,
      digest_sri,
    };
    println!("{}", serde_json::to_string(&payload)?);
  } else {
    println!("{}", output_path.display());
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn default_output_path_normal() {
    let input = PathBuf::from("/tmp/document.pdf");
    let out = default_signed_output_path(&input).unwrap();
    assert_eq!(out, PathBuf::from("/tmp/document_signed.pdf"));
  }

  #[test]
  fn default_output_path_hidden_dotfile_like_pdf() {
    let input = PathBuf::from("/tmp/.pdf");
    let out = default_signed_output_path(&input).unwrap();
    assert_eq!(out, PathBuf::from("/tmp/.pdf_signed.pdf"));
  }

  #[test]
  fn default_output_path_root_has_no_filename() {
    let input = PathBuf::from("/");
    let err = default_signed_output_path(&input).unwrap_err();
    assert!(
      err
        .to_string()
        .contains("cannot derive default output path"),
      "unexpected error: {err}"
    );
  }
}
