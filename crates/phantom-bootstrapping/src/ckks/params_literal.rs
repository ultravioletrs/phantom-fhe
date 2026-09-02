//! Literal CKKS bootstrapping parameter descriptions.

use phantom_schemes::ckks::CkksParams;

use super::BootstrapParams;
use crate::Result;

/// A plain-old-data, `Copy`-able description of [`BootstrapParams`]' own
/// tunable fields - useful for defining a fixed configuration as a `const`
/// (the builder's methods take `self` by value but aren't `const fn` all
/// the way through `build`, since validation needs `ckks_params`) or for
/// storing/transmitting a bootstrap configuration decoupled from any
/// particular [`CkksParams`] until [`Self::build`] is called against one.
/// Call [`Self::build`] to turn this into validated [`BootstrapParams`] -
/// the same validation [`BootstrapParams::new`] itself runs, so an invalid
/// literal (e.g. `target_level` above `ckks_params.initial_level()`) is
/// still rejected at that point, not silently accepted.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BootstrapParamsLiteral {
    /// Desired post-bootstrap level - how many CKKS levels remain for
    /// circuit evaluation to spend before the *next* bootstrap is needed.
    /// Consumed by [`super::Bootstrapper::bootstrap`]'s own
    /// `refresh_metadata` step, which sets the output ciphertext's level to
    /// exactly this. Must not exceed the target [`CkksParams::initial_level`]
    /// (checked by [`BootstrapParams::new`]) - the higher this is, the more
    /// RNS moduli a real (non-scaffold) deployment's parameter set would
    /// need to carry all the way through bootstrapping just to have this
    /// many left afterward.
    pub target_level: usize,
    /// Desired post-bootstrap precision in bits - the precision
    /// [`super::Bootstrapper::bootstrap`]'s `refresh_metadata` step resets
    /// the output ciphertext's [`phantom_schemes::ckks::Precision`]
    /// estimate to, standing in for the real precision loss a genuine
    /// EvalMod polynomial approximation would introduce (see
    /// [`super::EvalMod`]'s own module doc comment for what that
    /// approximates). A real deployment would derive this from the actual
    /// EvalMod polynomial's own degree/error, not choose it freely; on this
    /// still-transparent-slot scaffold it's simply asserted.
    pub target_precision_bits: f64,
    /// Per-ciphertext slot allotment [`super::Packer`]/[`super::Unpacker`]
    /// use to interleave [`Self::batch_size`] independent ciphertexts into
    /// (or back out of) one packed ciphertext - **not** consumed by
    /// [`super::Bootstrapper::bootstrap`] itself, which operates on
    /// whatever slot count its input actually has (checked against the
    /// full [`CkksParams::slot_count`], not this). Must be in
    /// `1..=ckks_params.slot_count()` (checked by [`BootstrapParams::new`]).
    pub sparse_slot_count: usize,
    /// Preferred number of ciphertexts [`super::Bootstrapper::bootstrap_batch`],
    /// [`super::Packer`], and [`super::Unpacker`] expect to handle together.
    pub batch_size: usize,
    /// The assumed "raised modulus" [`super::EvalMod::reduce_mod_q`]
    /// reduces against - see that method's own doc comment for what this
    /// represents and why a real (non-scaffold) deployment would size it
    /// from the bootstrapping ciphertext's own lowest RNS modulus rather
    /// than choose it freely.
    pub raise_modulus: f64,
}

impl BootstrapParamsLiteral {
    /// Builds validated [`BootstrapParams`] for `ckks_params` from this
    /// literal description - the same validation [`BootstrapParams::new`]
    /// always runs (a literal built against the wrong [`CkksParams`], e.g.
    /// one whose `initial_level()` is smaller than [`Self::target_level`],
    /// is rejected here, not silently accepted).
    pub fn build(self, ckks_params: CkksParams) -> Result<BootstrapParams> {
        BootstrapParams::new(
            ckks_params,
            self.target_level,
            self.target_precision_bits,
            self.sparse_slot_count,
            self.batch_size,
            self.raise_modulus,
        )
    }
}
