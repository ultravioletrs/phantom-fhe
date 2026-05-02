//! Literal CKKS bootstrapping parameter presets.

/// Serializable-friendly literal bootstrap parameter description.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BootstrapParamsLiteral {
    /// Desired post-bootstrap level.
    pub target_level: usize,
    /// Desired post-bootstrap precision in bits.
    pub target_precision_bits: f64,
    /// Sparse slot count.
    pub sparse_slot_count: usize,
    /// Preferred batch size.
    pub batch_size: usize,
}
