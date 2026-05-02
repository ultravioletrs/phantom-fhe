//! Generic RLWE primitives.

pub mod automorphism;
pub mod ciphertext;
pub mod decryptor;
pub mod encryptor;
pub mod evaluation_key;
pub mod evaluator;
pub mod keygen;
pub mod keyswitch;
pub mod params;
pub mod plaintext;
pub mod public_key;
pub mod relinearization;
pub mod repacking;
pub mod secret_key;

pub use automorphism::AutomorphismKey;
pub use ciphertext::Ciphertext;
pub use decryptor::Decryptor;
pub use encryptor::Encryptor;
pub use evaluation_key::{EvaluationKey, GaloisKey, RelinearizationKey};
pub use evaluator::Evaluator;
pub use keygen::{KeyGenerator, SecretDistribution};
pub use keyswitch::key_switch_identity;
pub use params::RlweParams;
pub use plaintext::Plaintext;
pub use public_key::PublicKey;
pub use secret_key::SecretKey;
