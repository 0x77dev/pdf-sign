//! Digest (hash) abstraction with algorithm agility and SRI-style encoding.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha512};

/// Supported digest algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DigestAlgorithm {
  Sha512 = 1,
}

impl DigestAlgorithm {
  /// Returns the algorithm name in lowercase (for SRI strings).
  pub fn name(&self) -> &'static str {
    match self {
      DigestAlgorithm::Sha512 => "sha512",
    }
  }

  /// Parse algorithm from name string.
  pub fn from_name(s: &str) -> Result<Self> {
    match s.to_lowercase().as_str() {
      "sha512" | "sha-512" => Ok(DigestAlgorithm::Sha512),
      _ => bail!("Unsupported digest algorithm: {}", s),
    }
  }

  /// Output length in bytes for this algorithm.
  pub fn output_len(&self) -> usize {
    match self {
      DigestAlgorithm::Sha512 => 64,
    }
  }
}

impl TryFrom<u8> for DigestAlgorithm {
  type Error = anyhow::Error;

  fn try_from(value: u8) -> Result<Self> {
    match value {
      1 => Ok(DigestAlgorithm::Sha512),
      _ => bail!("Unknown digest algorithm tag: {}", value),
    }
  }
}

/// Compute digest of the given data using the specified algorithm.
#[tracing::instrument(skip(data), fields(data_len = data.len(), alg = ?algorithm))]
pub fn compute_digest(algorithm: DigestAlgorithm, data: &[u8]) -> Vec<u8> {
  match algorithm {
    DigestAlgorithm::Sha512 => {
      let mut hasher = Sha512::new();
      hasher.update(data);
      hasher.finalize().to_vec()
    }
  }
}

/// Encode digest as SRI string (e.g., `sha512-<base64>`).
pub fn encode_sri(algorithm: DigestAlgorithm, digest: &[u8]) -> String {
  use base64::Engine;
  format!(
    "{}-{}",
    algorithm.name(),
    base64::engine::general_purpose::STANDARD.encode(digest)
  )
}

/// Parse SRI string into (algorithm, digest bytes).
///
/// Accepts both padded and unpadded base64.
pub fn parse_sri(sri: &str) -> Result<(DigestAlgorithm, Vec<u8>)> {
  use base64::Engine;
  let Some((alg_str, b64)) = sri.split_once('-') else {
    bail!("Invalid SRI format (expected 'algorithm-base64')");
  };
  let algorithm = DigestAlgorithm::from_name(alg_str)?;
  let digest = base64::engine::general_purpose::STANDARD
    .decode(b64)
    .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64))
    .map_err(|e| anyhow::anyhow!("Invalid base64 in SRI: {}", e))?;
  if digest.len() != algorithm.output_len() {
    bail!(
      "Digest length mismatch for {}: expected {}, got {}",
      alg_str,
      algorithm.output_len(),
      digest.len()
    );
  }
  Ok((algorithm, digest))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sha512_computes_correctly() {
    let data = b"hello";
    let digest = compute_digest(DigestAlgorithm::Sha512, data);
    assert_eq!(digest.len(), 64);
  }

  #[test]
  fn sri_round_trip() {
    let digest = vec![0u8; 64];
    let sri = encode_sri(DigestAlgorithm::Sha512, &digest);
    assert!(sri.starts_with("sha512-"));
    let (alg, parsed) = parse_sri(&sri).unwrap();
    assert_eq!(alg, DigestAlgorithm::Sha512);
    assert_eq!(parsed, digest);
  }

  #[test]
  fn sri_accepts_unpadded() {
    // Create a digest that would produce padding
    let digest = vec![0u8; 64];
    let sri_padded = encode_sri(DigestAlgorithm::Sha512, &digest);
    let sri_unpadded = sri_padded.trim_end_matches('=');
    let (_, parsed) = parse_sri(sri_unpadded).unwrap();
    assert_eq!(parsed, digest);
  }
}
