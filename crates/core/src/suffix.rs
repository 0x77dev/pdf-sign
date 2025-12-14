//! Suffix block parsing and encoding (OpenPGP and Sigstore blocks).

use anyhow::{Context, Result};
use bilrost::Message;

const PGP_SIG_BEGIN: &[u8] = b"-----BEGIN PGP SIGNATURE-----";
const PGP_SIG_END: &[u8] = b"-----END PGP SIGNATURE-----";
const SIGSTORE_BEGIN: &[u8] = b"-----BEGIN PDF-SIGN SIGSTORE-----";
const SIGSTORE_END: &[u8] = b"-----END PDF-SIGN SIGSTORE-----";

/// A suffix block appended after the PDF's `%%EOF`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuffixBlock {
  /// OpenPGP ASCII-armored signature.
  OpenPgpSig(Vec<u8>),
  /// Sigstore bundle (bilrost-encoded).
  SigstoreBundle(SigstoreBundleBlock),
}

/// Sigstore bundle block payload (bilrost message).
#[derive(Debug, Clone, PartialEq, Eq, Message, serde::Serialize, serde::Deserialize)]
pub struct SigstoreBundleBlock {
  #[bilrost(encoding(varint), tag(1))]
  pub version: u32,
  #[bilrost(encoding(varint), tag(2))]
  pub signed_range_len: u64,
  #[bilrost(encoding(varint), tag(3))]
  pub digest_alg: u8,
  #[bilrost(encoding(plainbytes), tag(4))]
  pub digest: Vec<u8>,
  #[bilrost(encoding(plainbytes), tag(5))]
  pub bundle_json: Vec<u8>,
}

/// Parse all suffix blocks from the given suffix data.
///
/// Returns blocks in the order they appear.
#[tracing::instrument(skip(data), fields(data_len = data.len()))]
pub fn parse_suffix_blocks(data: &[u8]) -> Result<Vec<SuffixBlock>> {
  let mut blocks = Vec::new();
  let mut i = 0;

  while i < data.len() {
    // Try OpenPGP block
    if let Some(begin) = find_subslice(data, PGP_SIG_BEGIN, i)
      && let Some(end) = find_subslice(data, PGP_SIG_END, begin)
    {
      let mut end_pos = end + PGP_SIG_END.len();
      // Include trailing newline
      if end_pos < data.len() && data[end_pos] == b'\r' {
        end_pos += 1;
        if end_pos < data.len() && data[end_pos] == b'\n' {
          end_pos += 1;
        }
      } else if end_pos < data.len() && data[end_pos] == b'\n' {
        end_pos += 1;
      }
      blocks.push(SuffixBlock::OpenPgpSig(data[begin..end_pos].to_vec()));
      i = end_pos;
      continue;
    }

    // Try Sigstore block
    if let Some(begin) = find_subslice(data, SIGSTORE_BEGIN, i)
      && let Some(end) = find_subslice(data, SIGSTORE_END, begin)
    {
      let body_start = begin + SIGSTORE_BEGIN.len();
      let body = &data[body_start..end];
      let body_str = std::str::from_utf8(body).context("Sigstore block body is not valid UTF-8")?;

      // Remove all whitespace (newlines, spaces) before decoding
      let body_cleaned: String = body_str.chars().filter(|c| !c.is_whitespace()).collect();

      use base64::Engine;
      let decoded = base64::engine::general_purpose::STANDARD
        .decode(&body_cleaned)
        .context("Failed to decode base64 in Sigstore block")?;

      let bundle = SigstoreBundleBlock::decode(&decoded[..])
        .map_err(|e| anyhow::anyhow!("Failed to decode bilrost payload: {}", e))?;

      blocks.push(SuffixBlock::SigstoreBundle(bundle));
      i = end + SIGSTORE_END.len();
      continue;
    }

    // Skip to next line or end
    if let Some(newline_pos) = data[i..].iter().position(|&b| b == b'\n') {
      i += newline_pos + 1;
    } else {
      break;
    }
  }

  Ok(blocks)
}

/// Encode a suffix block into bytes suitable for appending to a PDF.
#[tracing::instrument(skip(block), fields(block_type = ?std::mem::discriminant(block)))]
pub fn encode_suffix_block(block: &SuffixBlock) -> Vec<u8> {
  match block {
    SuffixBlock::OpenPgpSig(data) => data.clone(),
    SuffixBlock::SigstoreBundle(bundle) => {
      use base64::Engine;
      let encoded = bundle.encode_to_vec();
      let b64 = base64::engine::general_purpose::STANDARD.encode(&encoded);

      let mut out = Vec::new();
      out.extend_from_slice(SIGSTORE_BEGIN);
      out.push(b'\n');
      // Wrap base64 at 76 columns
      for chunk in b64.as_bytes().chunks(76) {
        out.extend_from_slice(chunk);
        out.push(b'\n');
      }
      out.extend_from_slice(SIGSTORE_END);
      out.push(b'\n');
      out
    }
  }
}

fn find_subslice(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
  if needle.is_empty() || start >= haystack.len() {
    return None;
  }
  haystack[start..]
    .windows(needle.len())
    .position(|w| w == needle)
    .map(|pos| start + pos)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_pgp_block() {
    let sig = b"-----BEGIN PGP SIGNATURE-----\nVersion: Test\n\nabc\n-----END PGP SIGNATURE-----\n";
    let blocks = parse_suffix_blocks(sig).unwrap();
    assert_eq!(blocks.len(), 1);
    match &blocks[0] {
      SuffixBlock::OpenPgpSig(data) => assert_eq!(data.as_slice(), sig),
      _ => panic!("Expected OpenPgpSig"),
    }
  }

  #[test]
  fn round_trip_sigstore_block() {
    let bundle = SigstoreBundleBlock {
      version: 1,
      signed_range_len: 1234,
      digest_alg: 1,
      digest: vec![0u8; 64],
      bundle_json: b"{\"test\":true}".to_vec(),
    };
    let block = SuffixBlock::SigstoreBundle(bundle.clone());
    let encoded = encode_suffix_block(&block);

    let parsed = parse_suffix_blocks(&encoded).unwrap();
    assert_eq!(parsed.len(), 1);
    match &parsed[0] {
      SuffixBlock::SigstoreBundle(parsed_bundle) => {
        assert_eq!(parsed_bundle, &bundle);
      }
      _ => panic!("Expected SigstoreBundle"),
    }
  }
}
