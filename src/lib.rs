#[cfg(feature = "free")]
pub mod free;

use std::fs::File;

/// Estimate Bloom filter size based on file length.
///
/// Returns at least 1 to avoid zero-capacity filters.
pub fn estimate_bloom_size(file: &File) -> usize {
    file
        .metadata()
        .map(|m| std::cmp::max(1, (m.len() / 32) as usize))
        .unwrap_or(1)
}
