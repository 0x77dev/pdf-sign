#!/usr/bin/env nix-shell
//! ```cargo
//! [dependencies]
//! sequoia-openpgp = { version = "2", default-features = false, features = ["crypto-nettle"] }
//! sequoia-gpg-agent = "0.6"
//! tokio = { version = "1", features = ["full"] }
//! anyhow = "1.0"
//! clap = { version = "4.5", features = ["derive"] }
//! indicatif = "0.17"
//! console = "0.15"
//! ```
/*
#!nix-shell -i rust-script -p rustc -p rust-script -p cargo -p pkg-config -p nettle -p gmp -p gnupg
*/

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::cert::prelude::*;
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::*;
use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "pdf-sign",
    about = "Secure PDF signing with GPG/YubiKey",
    long_about = "Sign and verify PDFs using GPG agent with hardware token support (YubiKey, smartcards).\nAll signing operations are delegated to gpg-agent for maximum security."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign a PDF file using GPG agent
    Sign {
        /// Path to the PDF file to sign
        input: PathBuf,
        
        /// Output path for signed PDF (default: <input>_signed.pdf)
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// Key specification: file path (.asc), key ID (0xABCD1234), fingerprint, or email
        #[arg(short, long)]
        key: String,
    },
    /// Verify a signed PDF file
    Verify {
        /// Path to the signed PDF file
        input: PathBuf,
        
        /// Key specification: file path (.asc), key ID (0xABCD1234), fingerprint, or email
        #[arg(short, long)]
        cert: String,
    },
}

struct Helper {
    cert: Cert,
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    result.map_err(openpgp::Error::from)?;
                    return Ok(());
                }
            }
        }
        Err(openpgp::Error::InvalidOperation("No valid signature".into()).into())
    }
}

fn find_eof_offset(data: &[u8]) -> Result<usize> {
    data.windows(5)
        .rposition(|w| w == b"%%EOF")
        .map(|pos| pos + 5)
        .context("PDF does not contain %%EOF marker")
}

/// Load certificate from file path or key ID
fn load_cert(key_spec: &str) -> Result<Cert> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    
    // Check if it's a file path
    let path = Path::new(key_spec);
    if path.exists() {
        spinner.set_message(format!("Loading certificate from {}", style(key_spec).cyan()));
        let result = Cert::from_bytes(&std::fs::read(path)?)
            .context(format!("Failed to load certificate from file: {}", key_spec));
        spinner.finish_and_clear();
        return result;
    }
    
    // Otherwise, treat as key ID and export from GPG
    spinner.set_message(format!("Fetching key {} from GPG", style(key_spec).cyan()));
    
    let output = Command::new("gpg")
        .args(&["--export", key_spec])
        .output()
        .context("Failed to execute gpg --export (is GPG installed?)")?;
    
    if !output.status.success() {
        spinner.finish_and_clear();
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("GPG export failed: {}", stderr);
    }
    
    if output.stdout.is_empty() {
        spinner.finish_and_clear();
        bail!(
            "No key found for '{}'. Try:\n  \
             {} Key ID: {} or {}\n  \
             {} Fingerprint: {}\n  \
             {} Email: {}\n  \
             {} Or provide a .asc file path",
            style(key_spec).yellow(),
            style("•").dim(),
            style("0xABCD1234").cyan(),
            style("ABCD1234").cyan(),
            style("•").dim(),
            style("AABBCCDDEEFF...").cyan(),
            style("•").dim(),
            style("user@example.com").cyan(),
            style("•").dim(),
        );
    }
    
    // Parse as keyring (may contain multiple certificates)
    let parser = openpgp::cert::CertParser::from_bytes(&output.stdout)?;
    
    // Collect all certificates to check for multiple matches
    let certs: Vec<_> = parser.collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificates")?;
    
    spinner.finish_and_clear();
    
    if certs.is_empty() {
        bail!("No valid certificate found for: {}", key_spec);
    }
    
    if certs.len() > 1 {
        eprintln!("{} {}", 
            style("Warning:").yellow().bold(),
            format!("Multiple keys found for '{}'. Using the first one.", style(key_spec).cyan())
        );
        eprintln!("\n{}  Keys found:", style("ℹ").cyan());
        for (i, cert) in certs.iter().enumerate() {
            let fingerprint = cert.fingerprint();
            let uids: Vec<_> = cert.userids().map(|uid| {
                String::from_utf8_lossy(uid.userid().value()).to_string()
            }).collect();
            eprintln!("  {} {}. {} ({})", 
                style("•").dim(),
                i + 1, 
                style(&fingerprint).cyan(),
                style(uids.join(", ")).dim()
            );
        }
        eprintln!("\n{}  To avoid ambiguity, specify the exact fingerprint:",
            style("→").cyan()
        );
        eprintln!("    {} {}",
            style("--key").green(),
            style(&certs[0].fingerprint()).cyan()
        );
        eprintln!();
    }
    
    Ok(certs.into_iter().next().unwrap())
}

fn format_bytes(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if (bytes as f64) < MB {
        format!("{:.1} KB", bytes as f64 / KB)
    } else {
        format!("{:.2} MB", bytes as f64 / MB)
    }
}

fn sign_pdf(input: PathBuf, output: Option<PathBuf>, key_spec: String) -> Result<()> {
    eprintln!("{}", 
        style("==> Signing PDF with GPG agent").cyan().bold()
    );
    
    // Read PDF with progress
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    
    spinner.set_message(format!("Reading PDF {}", style(input.display()).cyan()));
    let mut pdf_data = Vec::new();
    let mut file = BufReader::new(File::open(&input)
        .context(format!("Failed to open PDF: {}", input.display()))?);
    file.read_to_end(&mut pdf_data)?;
    spinner.finish_with_message(format!(
        "[OK] Read PDF ({})",
        style(format_bytes(pdf_data.len())).cyan()
    ));

    let eof_offset = find_eof_offset(&pdf_data)?;
    let clean_pdf = &pdf_data[..eof_offset];

    // Load certificate
    let cert = load_cert(&key_spec)?;
    
    // Display key info
    let fingerprint = cert.fingerprint();
    let uids: Vec<_> = cert.userids()
        .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string())
        .collect();
    
    eprintln!("    Using key: {} ({})",
        style(&fingerprint).cyan(),
        style(uids.join(", ")).dim()
    );
    
    let policy = StandardPolicy::new();

    // Find signing-capable key
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

    // Create detached signature using GPG agent
    let mut signature_data = Vec::new();
    
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner.set_message("Connecting to GPG agent...");
    
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use sequoia_gpg_agent as agent;
        
        // Connect to GPG agent
        let ctx = agent::Context::new()
            .context("Failed to create GPG agent context")?;
        let agent = agent::Agent::connect(&ctx).await
            .context("Failed to connect to GPG agent - is gpg-agent running?")?;
        
        spinner.set_message(format!(
            "{}Waiting for hardware token (PIN/touch may be required)...",
            style("→").cyan()
        ));
        
        // Get keypair that delegates to agent (triggers PIN/touch prompt)
        let keypair = agent.keypair(&valid_key)
            .context("Failed to get keypair from agent - is the key available on your token?")?;

        spinner.set_message("Creating signature...");
        
        // Create armored detached signature
        let mut armor_writer = armor::Writer::new(&mut signature_data, armor::Kind::Signature)?;
        let message = Message::new(&mut armor_writer);
        let mut signer = Signer::new(message, keypair)?.detached().build()?;
        signer.write_all(clean_pdf)?;
        signer.finalize()?;
        armor_writer.finalize()?;
        
        Ok::<(), anyhow::Error>(())
    })?;
    
    spinner.finish_with_message(format!("[OK] Created signature ({})", style(format_bytes(signature_data.len())).cyan()));

    // Write signed PDF
    let output_path = output.unwrap_or_else(|| {
        let mut p = input.clone();
        let stem = p.file_stem().unwrap().to_str().unwrap();
        p.set_file_name(format!("{}_signed.pdf", stem));
        p
    });

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner.set_message(format!("Writing signed PDF to {}", style(output_path.display()).cyan()));

    let mut out = BufWriter::new(File::create(&output_path)
        .context(format!("Failed to create output file: {}", output_path.display()))?);
    out.write_all(clean_pdf)?;
    out.write_all(b"\n")?;
    out.write_all(&signature_data)?;
    out.flush()?;
    
    spinner.finish_and_clear();

    eprintln!("\n{} {}",
        style("[SUCCESS]").green().bold(),
        style("Signed successfully").cyan()
    );
    
    // Output the path to stdout for shell piping/scripting
    println!("{}", output_path.display());
    
    Ok(())
}

fn verify_pdf(input: PathBuf, cert_spec: String) -> Result<()> {
    eprintln!("{}",
        style("==> Verifying PDF signature").cyan().bold()
    );
    
    // Read signed PDF
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner.set_message(format!("Reading signed PDF {}", style(input.display()).cyan()));
    
    let mut signed_data = Vec::new();
    let mut file = BufReader::new(File::open(&input)
        .context(format!("Failed to open signed PDF: {}", input.display()))?);
    file.read_to_end(&mut signed_data)?;
    
    spinner.finish_with_message(format!("[OK] Read PDF ({})", style(format_bytes(signed_data.len())).cyan()));

    let eof_offset = find_eof_offset(&signed_data)?;
    let pdf_data = &signed_data[..eof_offset];
    let sig_data = &signed_data[eof_offset + 1..];

    if !sig_data.starts_with(b"-----BEGIN PGP SIGNATURE-----") {
        bail!("No PGP signature found after %%EOF marker");
    }
    
    eprintln!("    Found signature ({})",
        style(format_bytes(sig_data.len())).cyan()
    );

    // Load verification certificate
    let cert = load_cert(&cert_spec)?;
    
    let policy = StandardPolicy::new();
    
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner.set_message("Verifying signature...");

    let helper = Helper { cert: cert.clone() };

    // Verify detached signature
    let mut verifier = DetachedVerifierBuilder::from_bytes(sig_data)?
        .with_policy(&policy, None, helper)?;

    verifier.verify_bytes(pdf_data)
        .context("Signature verification failed")?;
    
    spinner.finish_and_clear();

    // Display verification results to stderr
    eprintln!("\n{} {}",
        style("[VALID]").green().bold(),
        style("Signature verified").green()
    );
    
    let fingerprint = cert.fingerprint();
    let uids: Vec<_> = cert.userids()
        .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string())
        .collect();
    
    eprintln!("\n    Signer Details:");
    eprintln!("      Fingerprint: {}", 
        style(&fingerprint).cyan()
    );
    
    for uid in uids {
        eprintln!("      Identity: {}",
            style(&uid).cyan()
        );
    }
    
    // Show key capabilities
    let signing_keys: Vec<_> = cert.keys()
        .with_policy(&policy, None)
        .alive()
        .revoked(false)
        .for_signing()
        .collect();
    
    if !signing_keys.is_empty() {
        eprintln!("      Signing keys: {}",
            style(signing_keys.len()).cyan()
        );
    }
    
    // Output "OK" to stdout for shell scripting (exit code 0 = success)
    println!("OK");
    
    Ok(())
}

fn main() -> Result<()> {
    let result = match Cli::parse().command {
        Commands::Sign { input, output, key } => sign_pdf(input, output, key),
        Commands::Verify { input, cert } => verify_pdf(input, cert),
    };

    if let Err(e) = &result {
        eprintln!("\n{} {}", 
            style("[ERROR]").red().bold(),
            style(&e).red()
        );
        
        for (i, cause) in e.chain().skip(1).enumerate() {
            if i == 0 {
                eprintln!("\n    Caused by:");
            }
            eprintln!("      - {}", style(cause).red());
        }
        eprintln!();
    }

    result
}
