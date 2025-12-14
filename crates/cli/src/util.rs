//! CLI utility functions.

pub fn format_bytes(bytes: usize) -> String {
  const KB: f64 = 1024.0;
  const MB: f64 = KB * 1024.0;
  const KB_TO_MB_ROUNDING_THRESHOLD: usize = 1_048_525;

  if bytes < 1024 {
    format!("{} B", bytes)
  } else if bytes < KB_TO_MB_ROUNDING_THRESHOLD {
    format!("{:.1} KB", bytes as f64 / KB)
  } else {
    format!("{:.2} MB", bytes as f64 / MB)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn never_displays_1024_kb_due_to_rounding() {
    for bytes in 1_048_560..1_048_576 {
      let s = format_bytes(bytes);
      assert!(
        !s.contains("KB") || !s.contains("1024.0"),
        "unexpected formatting for {bytes}: {s}"
      );
    }
  }

  #[test]
  fn boundary_at_rounding_threshold() {
    assert!(format_bytes(1_048_524).ends_with("KB"));
    assert!(format_bytes(1_048_525).ends_with("MB"));
    assert_eq!(format_bytes(1_048_576), "1.00 MB");
  }
}
