//! Ring context and polynomial operations.

use crate::modulus::Modulus;
use crate::ntt::table::NttTable;
use crate::poly::Poly;
use crate::reduce::{add_mod, mul_mod, neg_mod, sub_mod, BarrettReducer};
use crate::{Degree, Result, RingError};

/// RNS polynomial ring context.
#[derive(Clone, Debug)]
pub struct Ring {
    degree: Degree,
    moduli: Vec<Modulus>,
    /// One precomputed [`BarrettReducer`] per modulus, for the multiplication
    /// hot paths below - `BarrettReducer` supports the full 64-bit modulus
    /// range, so this is `None` only if `BarrettReducer::new` itself ever
    /// rejects a modulus (currently just `modulus < 2`, which a valid
    /// [`Modulus`] can never be); kept as `Option` defensively rather than
    /// assuming that invariant here too. Falls back to the widened-`u128`
    /// path in [`mul_mod`] on `None`. Computed once here so every `*_mul*`
    /// call reuses the same precomputed constant rather than re-deriving it
    /// per coefficient.
    reducers: Vec<Option<BarrettReducer>>,
    /// One precomputed [`NttTable`] per modulus, for [`mul`](Self::mul) -
    /// `None` for moduli that don't support a negacyclic NTT at this ring's
    /// degree (see [`Modulus::supports_ntt`]), which fall back to
    /// [`schoolbook_mul`](Self::schoolbook_mul) instead. Computed once here
    /// (a primitive-root search) rather than per multiplication.
    ntt_tables: Vec<Option<NttTable>>,
}

impl Ring {
    /// Creates a validated ring context.
    pub fn new(degree: Degree, moduli: Vec<Modulus>) -> Result<Self> {
        if moduli.is_empty() {
            return Err(RingError::DimensionMismatch);
        }
        let reducers = moduli
            .iter()
            .map(|modulus| BarrettReducer::new(modulus.value()).ok())
            .collect();
        let ntt_tables = moduli
            .iter()
            .map(|modulus| NttTable::new(degree.get(), *modulus).ok())
            .collect();
        Ok(Self {
            degree,
            moduli,
            reducers,
            ntt_tables,
        })
    }

    /// Creates a ring and validates all moduli for negacyclic NTT.
    pub fn new_ntt(degree: Degree, moduli: Vec<Modulus>) -> Result<Self> {
        for modulus in &moduli {
            if !modulus.supports_ntt(degree.get()) {
                return Err(RingError::InvalidNttModulus {
                    modulus: modulus.value(),
                    two_n: 2 * degree.get(),
                });
            }
        }
        Self::new(degree, moduli)
    }

    /// Returns the ring degree.
    pub fn degree(&self) -> usize {
        self.degree.get()
    }

    /// Returns the RNS moduli.
    pub fn moduli(&self) -> &[Modulus] {
        &self.moduli
    }

    /// Allocates a zero polynomial.
    pub fn zero(&self) -> Poly {
        Poly::zero_for(self)
    }

    /// Checks that a polynomial matches this ring.
    pub fn check_poly(&self, poly: &Poly) -> Result<()> {
        if poly.degree() != self.degree() || poly.moduli_count() != self.moduli.len() {
            return Err(RingError::DimensionMismatch);
        }
        Ok(())
    }

    /// Multiplies two residues modulo the `j`-th modulus, using the
    /// precomputed [`BarrettReducer`] for that modulus when available.
    ///
    /// Correct for any `u64` inputs, matching [`mul_mod`]'s unconditional
    /// correctness - `BarrettReducer::reduce`'s precondition (`a*b <
    /// modulus^2`) only holds when both operands are already properly
    /// reduced, which nothing in `Poly`'s type enforces, so this checks that
    /// before taking the fast path rather than assuming it.
    fn mul_residue(&self, j: usize, a: u64, b: u64) -> u64 {
        let modulus = self.moduli[j].value();
        match self.reducers[j] {
            Some(reducer) if a < modulus && b < modulus => reducer.reduce(a as u128 * b as u128),
            _ => mul_mod(a, b, modulus),
        }
    }

    /// Adds `rhs` into `lhs`.
    pub fn add_assign(&self, lhs: &mut Poly, rhs: &Poly) -> Result<()> {
        self.check_poly(lhs)?;
        self.check_poly(rhs)?;
        for (j, modulus) in self.moduli.iter().enumerate() {
            let q = modulus.value();
            for i in 0..self.degree() {
                lhs.coeffs_mut()[j][i] = add_mod(lhs.coeffs()[j][i], rhs.coeffs()[j][i], q);
            }
        }
        Ok(())
    }

    /// Returns `lhs + rhs`.
    pub fn add(&self, lhs: &Poly, rhs: &Poly) -> Result<Poly> {
        let mut out = lhs.clone();
        self.add_assign(&mut out, rhs)?;
        Ok(out)
    }

    /// Subtracts `rhs` from `lhs`.
    pub fn sub_assign(&self, lhs: &mut Poly, rhs: &Poly) -> Result<()> {
        self.check_poly(lhs)?;
        self.check_poly(rhs)?;
        for (j, modulus) in self.moduli.iter().enumerate() {
            let q = modulus.value();
            for i in 0..self.degree() {
                lhs.coeffs_mut()[j][i] = sub_mod(lhs.coeffs()[j][i], rhs.coeffs()[j][i], q);
            }
        }
        Ok(())
    }

    /// Returns `lhs - rhs`.
    pub fn sub(&self, lhs: &Poly, rhs: &Poly) -> Result<Poly> {
        let mut out = lhs.clone();
        self.sub_assign(&mut out, rhs)?;
        Ok(out)
    }

    /// Negates a polynomial in place.
    pub fn neg_assign(&self, poly: &mut Poly) -> Result<()> {
        self.check_poly(poly)?;
        for (j, modulus) in self.moduli.iter().enumerate() {
            let q = modulus.value();
            for coeff in &mut poly.coeffs_mut()[j] {
                *coeff = neg_mod(*coeff, q);
            }
        }
        Ok(())
    }

    /// Returns `-poly`.
    pub fn neg(&self, poly: &Poly) -> Result<Poly> {
        let mut out = poly.clone();
        self.neg_assign(&mut out)?;
        Ok(out)
    }

    /// Multiplies each coefficient by `scalar`.
    pub fn scalar_mul_assign(&self, poly: &mut Poly, scalar: u64) -> Result<()> {
        self.check_poly(poly)?;
        for (j, modulus) in self.moduli.iter().enumerate() {
            let scalar = scalar % modulus.value();
            for coeff in &mut poly.coeffs_mut()[j] {
                *coeff = self.mul_residue(j, *coeff, scalar);
            }
        }
        Ok(())
    }

    /// Returns `poly * scalar`.
    pub fn scalar_mul(&self, poly: &Poly, scalar: u64) -> Result<Poly> {
        let mut out = poly.clone();
        self.scalar_mul_assign(&mut out, scalar)?;
        Ok(out)
    }

    /// Coefficient-wise multiplication.
    pub fn coeffwise_mul(&self, lhs: &Poly, rhs: &Poly) -> Result<Poly> {
        self.check_poly(lhs)?;
        self.check_poly(rhs)?;
        let mut out = self.zero();
        for j in 0..self.moduli.len() {
            for i in 0..self.degree() {
                out.coeffs_mut()[j][i] =
                    self.mul_residue(j, lhs.coeffs()[j][i], rhs.coeffs()[j][i]);
            }
        }
        Ok(out)
    }

    /// Negacyclic polynomial multiplication, using the O(N log N) NTT for
    /// any RNS component whose modulus supports it at this ring's degree,
    /// and falling back to [`schoolbook_mul`](Self::schoolbook_mul)'s O(N²)
    /// approach per-component otherwise. This is the multiplication to call
    /// for anything except tests that specifically want the reference
    /// implementation.
    ///
    /// The NTT path allocates exactly one scratch buffer (reused across every
    /// RNS component, not just once per call) rather than the four
    /// allocations - two per operand's forward transform, two more inside the
    /// inverse transform - an earlier version needed: `lhs`'s transform and
    /// the final product are both written directly into `out`'s own
    /// already-allocated component, and only `rhs`'s transform needs
    /// separate scratch space.
    pub fn mul(&self, lhs: &Poly, rhs: &Poly) -> Result<Poly> {
        self.check_poly(lhs)?;
        self.check_poly(rhs)?;
        let n = self.degree();
        let mut out = self.zero();
        let mut scratch = vec![0u64; n];
        for j in 0..self.moduli.len() {
            match &self.ntt_tables[j] {
                Some(table) => {
                    let a: &mut [u64] = &mut out.coeffs_mut()[j];
                    crate::ntt::cpu::forward_component_into(&lhs.coeffs()[j], table, a);
                    crate::ntt::cpu::forward_component_into(&rhs.coeffs()[j], table, &mut scratch);
                    for i in 0..n {
                        a[i] = self.mul_residue(j, a[i], scratch[i]);
                    }
                    crate::ntt::cpu::inverse_transform_in_place(a, table);
                }
                None => self.schoolbook_mul_component(j, lhs, rhs, &mut out),
            }
        }
        Ok(out)
    }

    /// Schoolbook (O(N²)) negacyclic multiplication. Always correct
    /// regardless of whether this ring's moduli support an NTT; kept as the
    /// reference implementation for tests to check [`mul`](Self::mul)'s NTT
    /// path against, and as [`mul`](Self::mul)'s own fallback for unsupported moduli.
    pub fn schoolbook_mul(&self, lhs: &Poly, rhs: &Poly) -> Result<Poly> {
        self.check_poly(lhs)?;
        self.check_poly(rhs)?;
        let mut out = self.zero();
        for j in 0..self.moduli.len() {
            self.schoolbook_mul_component(j, lhs, rhs, &mut out);
        }
        Ok(out)
    }

    fn schoolbook_mul_component(&self, j: usize, lhs: &Poly, rhs: &Poly, out: &mut Poly) {
        let n = self.degree();
        let q = self.moduli[j].value();
        for a in 0..n {
            for b in 0..n {
                let prod = self.mul_residue(j, lhs.coeffs()[j][a], rhs.coeffs()[j][b]);
                let idx = a + b;
                if idx < n {
                    out.coeffs_mut()[j][idx] = add_mod(out.coeffs()[j][idx], prod, q);
                } else {
                    let idx = idx - n;
                    out.coeffs_mut()[j][idx] = sub_mod(out.coeffs()[j][idx], prod, q);
                }
            }
        }
    }
}
