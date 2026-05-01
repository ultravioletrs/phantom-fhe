//! Ring-GSW scaffolding and external-product interfaces.

pub mod ciphertext;
pub mod decomposition;
pub mod external_product;
pub mod key;
pub mod params;

pub use ciphertext::RgswCiphertext;
pub use decomposition::{GadgetDecomposition, GadgetDecompositionParams};
pub use external_product::external_product;
pub use key::RgswKey;
pub use params::RgswParams;
