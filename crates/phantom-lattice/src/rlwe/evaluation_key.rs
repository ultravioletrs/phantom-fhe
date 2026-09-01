//! Evaluation key placeholders.

use crate::rlwe::KeySwitchKey;

/// Generic evaluation key container.
#[derive(Clone, Debug, Default)]
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

/// Relinearization key: either the identity-preserving placeholder (no real
/// cryptographic content - [`RelinearizationKey::placeholder`], what every
/// scheme crate above this layer still gets from
/// `KeyGenerator::generate_relinearization_key`) or a real RNS hybrid
/// key-switching key from `s²` to `s`
/// ([`RelinearizationKey::from_key_switch_key`], produced by
/// `KeyGenerator::generate_hybrid_relinearization_key`). Kept as one type
/// with two states, rather than two separate types, so
/// [`crate::rlwe::Evaluator::relinearize`] has a single key parameter that
/// works either way - real key-switching when a real key is supplied,
/// today's identity behavior otherwise, with zero change for any existing
/// caller that only ever constructs the placeholder.
#[derive(Clone, Debug, Default)]
pub struct RelinearizationKey {
    key_switch_key: Option<KeySwitchKey>,
}

impl RelinearizationKey {
    /// The identity-preserving placeholder (no real cryptographic content).
    pub const fn placeholder() -> Self {
        Self {
            key_switch_key: None,
        }
    }

    /// Wraps a real RNS hybrid key-switching key (`s² -> s`).
    pub const fn from_key_switch_key(key_switch_key: KeySwitchKey) -> Self {
        Self {
            key_switch_key: Some(key_switch_key),
        }
    }

    /// Returns the real key-switching key, if this isn't the placeholder.
    pub fn key_switch_key(&self) -> Option<&KeySwitchKey> {
        self.key_switch_key.as_ref()
    }
}

/// Galois key: either the identity-preserving placeholder (no real
/// cryptographic content - [`GaloisKey::new`], what every scheme crate
/// above this layer still gets from `KeyGenerator::generate_galois_keys`)
/// or a real RNS hybrid key-switching key from `σ_element(s)` to `s`
/// ([`GaloisKey::from_key_switch_key`], produced by
/// `KeyGenerator::generate_hybrid_galois_key`). Same two-state shape as
/// [`RelinearizationKey`], for the same reason: every existing caller that
/// only ever constructs the placeholder keeps compiling and behaving
/// identically.
#[derive(Clone, Debug)]
pub struct GaloisKey {
    element: usize,
    key_switch_key: Option<KeySwitchKey>,
}

impl GaloisKey {
    /// Creates the identity-preserving placeholder Galois key marker for
    /// `element`.
    pub const fn new(element: usize) -> Self {
        Self {
            element,
            key_switch_key: None,
        }
    }

    /// Wraps a real RNS hybrid key-switching key (`σ_element(s) -> s`).
    pub const fn from_key_switch_key(element: usize, key_switch_key: KeySwitchKey) -> Self {
        Self {
            element,
            key_switch_key: Some(key_switch_key),
        }
    }

    /// Returns the Galois element.
    pub const fn element(&self) -> usize {
        self.element
    }

    /// Returns the real key-switching key, if this isn't the placeholder.
    pub fn key_switch_key(&self) -> Option<&KeySwitchKey> {
        self.key_switch_key.as_ref()
    }
}
