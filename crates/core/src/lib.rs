//! Core PDF signing primitives: PDF splitting, suffix block parsing/encoding, and digest abstraction.
//!
//! This crate provides the foundational building blocks for pdf-sign, with no CLI or UI dependencies.

pub mod digest;
pub mod pdf;
pub mod suffix;
pub mod types;

pub use digest::{DigestAlgorithm, compute_digest, encode_sri, parse_sri};
pub use pdf::{find_eof_offset, split_pdf};
pub use suffix::{SuffixBlock, encode_suffix_block, parse_suffix_blocks};
pub use types::*;
