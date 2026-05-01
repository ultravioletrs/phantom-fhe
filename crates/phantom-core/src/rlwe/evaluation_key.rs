//! Evaluation key placeholders.

/// Generic evaluation key container.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvaluationKey {
    relin: Option<RelinearizationKey>,
    galois: Vec<GaloisKey>,
}

impl EvaluationKey {
    /// Creates an evaluation key container.
    pub fn new(relin: Option<RelinearizationKey>, galois: Vec<GaloisKey>) -> Self {
        Self { relin, galois }
    }

    /// Returns the relinearization key, if any.
    pub const fn relinearization_key(&self) -> Option<&RelinearizationKey> {
        self.relin.as_ref()
    }

    /// Returns Galois keys.
    pub fn galois_keys(&self) -> &[GaloisKey] {
        &self.galois
    }
}

/// Relinearization key placeholder.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelinearizationKey;

/// Galois key placeholder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GaloisKey {
    element: usize,
}

impl GaloisKey {
    /// Creates a Galois key marker.
    pub const fn new(element: usize) -> Self {
        Self { element }
    }

    /// Returns the Galois element.
    pub const fn element(&self) -> usize {
        self.element
    }
}
