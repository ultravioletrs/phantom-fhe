//! RNS polynomial storage.

use crate::{Ring, RingError};

/// Polynomial in RNS representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poly {
    degree: usize,
    coeffs: Vec<Vec<u64>>,
}

impl Poly {
    /// Creates a zero polynomial with `moduli_count` RNS components.
    pub fn zero(degree: usize, moduli_count: usize) -> Self {
        Self {
            degree,
            coeffs: vec![vec![0; degree]; moduli_count],
        }
    }

    /// Creates a polynomial from raw RNS coefficients.
    pub fn from_coeffs(coeffs: Vec<Vec<u64>>) -> crate::Result<Self> {
        let degree = coeffs.first().map_or(0, Vec::len);
        if degree == 0 || coeffs.iter().any(|c| c.len() != degree) {
            return Err(RingError::DimensionMismatch);
        }
        Ok(Self { degree, coeffs })
    }

    /// Creates a zero polynomial matching `ring`.
    pub fn zero_for(ring: &Ring) -> Self {
        Self::zero(ring.degree(), ring.moduli().len())
    }

    /// Returns the polynomial degree.
    pub const fn degree(&self) -> usize {
        self.degree
    }

    /// Returns all RNS coefficients.
    pub fn coeffs(&self) -> &[Vec<u64>] {
        &self.coeffs
    }

    /// Returns mutable RNS coefficients.
    pub fn coeffs_mut(&mut self) -> &mut [Vec<u64>] {
        &mut self.coeffs
    }

    /// Returns one RNS component.
    pub fn component(&self, index: usize) -> Option<&[u64]> {
        self.coeffs.get(index).map(Vec::as_slice)
    }

    /// Returns one mutable RNS component.
    pub fn component_mut(&mut self, index: usize) -> Option<&mut [u64]> {
        self.coeffs.get_mut(index).map(Vec::as_mut_slice)
    }

    /// Returns the number of RNS components.
    pub fn moduli_count(&self) -> usize {
        self.coeffs.len()
    }
}
