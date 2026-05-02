//! Automorphism key markers.

/// Automorphism key marker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomorphismKey {
    element: usize,
}

impl AutomorphismKey {
    /// Creates an automorphism key marker.
    pub const fn new(element: usize) -> Self {
        Self { element }
    }

    /// Returns the automorphism element.
    pub const fn element(&self) -> usize {
        self.element
    }
}
