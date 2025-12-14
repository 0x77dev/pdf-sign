//! PDF byte-range extraction and splitting logic.

use anyhow::{Context, Result};

/// Find the offset immediately after the last `%%EOF` marker in the PDF.
///
/// Returns the byte position right after `%%EOF` (the start of any appended suffix data).
#[tracing::instrument(skip(data), fields(data_len = data.len()))]
pub fn find_eof_offset(data: &[u8]) -> Result<usize> {
  data
    .windows(5)
    .rposition(|w| w == b"%%EOF")
    .map(|pos| pos + 5)
    .context("PDF does not contain %%EOF marker")
}

/// Split PDF data into clean bytes (up to last `%%EOF`) and suffix data.
///
/// Returns `(clean_pdf, suffix_data)`.
#[tracing::instrument(skip(data), fields(data_len = data.len()))]
pub fn split_pdf(data: &[u8]) -> Result<(&[u8], &[u8])> {
  let eof_offset = find_eof_offset(data)?;
  Ok((&data[..eof_offset], &data[eof_offset..]))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn finds_eof_marker() {
    let pdf = b"%%PDF-1.4\n...content...%%EOF";
    assert_eq!(find_eof_offset(pdf).unwrap(), pdf.len());
  }

  #[test]
  fn finds_last_eof_when_multiple() {
    let pdf = b"%%PDF-1.4\n%%EOF\nextra%%EOF";
    assert_eq!(find_eof_offset(pdf).unwrap(), pdf.len());
  }

  #[test]
  fn splits_correctly() {
    let data = b"%%PDF-1.4\ncontent%%EOFsuffix";
    let (clean, suffix) = split_pdf(data).unwrap();
    assert_eq!(clean, b"%%PDF-1.4\ncontent%%EOF");
    assert_eq!(suffix, b"suffix");
  }
}
