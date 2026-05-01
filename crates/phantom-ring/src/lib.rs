//! RNS polynomial ring arithmetic for `phantom-fhe`.

pub mod error;
pub mod modulus;
pub mod ntt;
pub mod poly;
pub mod reduce;
pub mod ring;
pub mod rns;
pub mod sampling;
pub mod types;

pub use error::{Result, RingError};
pub use modulus::Modulus;
pub use poly::Poly;
pub use ring::Ring;
pub use rns::RnsBasis;
pub use types::{Degree, Level};
