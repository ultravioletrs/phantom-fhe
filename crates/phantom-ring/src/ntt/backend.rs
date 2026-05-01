//! NTT backend trait.

use crate::{Poly, Result, Ring};

/// Backend for in-place negacyclic NTT operations.
pub trait NttBackend {
    /// Forward NTT.
    fn forward(&self, ring: &Ring, poly: &mut Poly) -> Result<()>;

    /// Inverse NTT.
    fn inverse(&self, ring: &Ring, poly: &mut Poly) -> Result<()>;
}
