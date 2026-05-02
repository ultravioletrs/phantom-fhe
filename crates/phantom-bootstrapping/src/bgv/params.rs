//! Reserved BGV bootstrapping parameters.

/// Placeholder for future BGV centralized bootstrapping parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootstrapParams {
    experimental: bool,
}

impl BootstrapParams {
    /// Creates a reserved experimental parameter marker.
    pub const fn experimental() -> Self {
        Self { experimental: true }
    }

    /// Returns whether this marker is experimental.
    pub const fn is_experimental(&self) -> bool {
        self.experimental
    }
}
