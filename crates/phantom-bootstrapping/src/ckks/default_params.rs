//! Default CKKS bootstrapping parameter helpers.

use phantom_schemes::ckks::CkksParams;

use super::BootstrapParams;
use crate::Result;

/// Builds conservative default bootstrapping parameters for a CKKS context.
pub fn default_bootstrap_params(ckks_params: CkksParams) -> Result<BootstrapParams> {
    BootstrapParams::builder(ckks_params)
        .target_precision_bits(20.0)
        .batch_size(1)
        .build()
}
