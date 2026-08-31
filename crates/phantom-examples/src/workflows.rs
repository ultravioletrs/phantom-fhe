//! Small, deterministic examples that run on development parameters.

use std::error::Error;
use std::fmt;

use phantom_bootstrapping::ckks::{
    default_bootstrap_params, BootstrapKeyGenerator, BootstrapParams, Bootstrapper,
};
use phantom_circuits::bgv::PolynomialEvaluator as BgvPolynomialEvaluator;
use phantom_circuits::ckks::{DftDirection, DftEvaluator, InverseEvaluator};
use phantom_multiparty::common::{
    ParticipantId, ParticipantSet, ProtocolKind, SessionId, SessionState, ShareAggregator,
    ShareKind,
};
use phantom_multiparty::mpbgv;
use phantom_multiparty::mpckks;
use phantom_ring::{Degree, Modulus, Ring};
use phantom_schemes::bfv::{BfvContext, BfvParams};
use phantom_schemes::bgv::{BgvContext, BgvParams};
use phantom_schemes::ckks::{CkksContext, CkksParams, Complex64};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Error type used by the runnable examples.
#[derive(Debug)]
pub struct ExampleError(String);

impl ExampleError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ExampleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ExampleError {}

/// Compact output displayed by each example binary.
#[derive(Clone, Debug, PartialEq)]
pub struct ExampleOutput {
    /// Human-readable workflow name.
    pub name: &'static str,
    /// Values produced by the workflow.
    pub values: Vec<String>,
}

impl ExampleOutput {
    fn new(name: &'static str, values: impl IntoIterator<Item = impl ToString>) -> Self {
        Self {
            name,
            values: values.into_iter().map(|value| value.to_string()).collect(),
        }
    }
}

impl fmt::Display for ExampleOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.values.join(", "))
    }
}

/// Runs a BFV encrypt/decrypt round trip.
pub fn bfv_basic() -> Result<ExampleOutput, ExampleError> {
    let ctx = BfvContext::new(bfv_params()?);
    let mut rng = rng(1);
    let keys = ctx.keygen()?.generate_keypair(&mut rng)?;
    let encoder = ctx.encoder();
    let plaintext = encoder.encode_i64(&[-2, 3, 5, -6])?;
    let ciphertext = ctx.encryptor(keys.public)?.encrypt(&plaintext, &mut rng)?;
    let decrypted = ctx.decryptor(keys.secret)?.decrypt(&ciphertext)?;
    Ok(ExampleOutput::new(
        "bfv_basic",
        encoder.decode_i64(&decrypted)?[..4].iter(),
    ))
}

/// Demonstrates BFV batched unsigned slots.
pub fn bfv_batching() -> Result<ExampleOutput, ExampleError> {
    let ctx = BfvContext::new(bfv_params()?);
    let encoder = ctx.encoder();
    let decoded = encoder.decode_u64(&encoder.encode_u64(&[1, 18, 34, 8])?)?;
    Ok(ExampleOutput::new("bfv_batching", decoded[..4].iter()))
}

/// Demonstrates BFV rotation.
pub fn bfv_rotation() -> Result<ExampleOutput, ExampleError> {
    let ctx = BfvContext::new(bfv_params()?);
    let mut rng = rng(2);
    let keys = ctx.keygen()?.generate_keypair(&mut rng)?;
    let encoder = ctx.encoder();
    let plaintext = encoder.encode_u64(&[1, 2, 3, 4])?;
    let ciphertext = ctx.encryptor(keys.public)?.encrypt(&plaintext, &mut rng)?;
    let rotated = ctx.evaluator()?.rotate_slots(&ciphertext, 1)?;
    let decrypted = ctx.decryptor(keys.secret)?.decrypt(&rotated)?;
    Ok(ExampleOutput::new(
        "bfv_rotation",
        encoder.decode_u64(&decrypted)?[..4].iter(),
    ))
}

/// Runs a BGV encrypt/decrypt round trip.
pub fn bgv_basic() -> Result<ExampleOutput, ExampleError> {
    let ctx = BgvContext::new(bgv_params()?);
    let mut rng = rng(3);
    let keys = ctx.keygen()?.generate_keypair(&mut rng)?;
    let encoder = ctx.encoder();
    let plaintext = encoder.encode_u64(&[3, 4, 5, 6])?;
    let ciphertext = ctx.encryptor(keys.public)?.encrypt(&plaintext, &mut rng)?;
    let decrypted = ctx.decryptor(keys.secret)?.decrypt(&ciphertext)?;
    Ok(ExampleOutput::new(
        "bgv_basic",
        encoder.decode_u64(&decrypted)?[..4].iter(),
    ))
}

/// Evaluates a small BGV polynomial over slots.
pub fn bgv_polynomial() -> Result<ExampleOutput, ExampleError> {
    let params = bgv_params()?;
    let ctx = BgvContext::new(params.clone());
    let mut rng = rng(4);
    let keys = ctx.keygen()?.generate_keypair(&mut rng)?;
    let encoder = ctx.encoder();
    let ciphertext = ctx
        .encryptor(keys.public)?
        .encrypt(&encoder.encode_u64(&[0, 1, 2, 3, 4])?, &mut rng)?;
    let output = BgvPolynomialEvaluator::new(params)?.evaluate(&ciphertext, &[5, 3, 2], None)?;
    let decrypted = ctx.decryptor(keys.secret)?.decrypt(&output)?;
    Ok(ExampleOutput::new(
        "bgv_polynomial",
        encoder.decode_u64(&decrypted)?[..5].iter(),
    ))
}

/// Runs a CKKS encrypt/decrypt round trip.
pub fn ckks_basic() -> Result<ExampleOutput, ExampleError> {
    let ctx = CkksContext::new(ckks_params()?);
    let mut rng = rng(5);
    let keys = ctx.keygen()?.generate_keypair(&mut rng)?;
    let encoder = ctx.encoder();
    let plaintext = encoder.encode_real(&[0.5, -1.25, 4.0])?;
    let ciphertext = ctx.encryptor(keys.public)?.encrypt(&plaintext, &mut rng)?;
    let decrypted = ctx.decryptor(keys.secret)?.decrypt(&ciphertext)?;
    Ok(ExampleOutput::new(
        "ckks_basic",
        encoder.decode_real(&decrypted)?[..3]
            .iter()
            .map(|value| format!("{value:.2}")),
    ))
}

/// Demonstrates CKKS multiplication and rescaling metadata.
pub fn ckks_rescale() -> Result<ExampleOutput, ExampleError> {
    let params = ckks_params()?;
    let ctx = CkksContext::new(params.clone());
    let mut rng = rng(6);
    let keygen = ctx.keygen()?;
    let keys = keygen.generate_keypair(&mut rng)?;
    let eval_keys = keygen.generate_evaluation_keys(&keys.secret, &[1]);
    let encoder = ctx.encoder();
    let encryptor = ctx.encryptor(keys.public)?;
    let lhs = encryptor.encrypt(&encoder.encode_real(&[1.5, 2.0])?, &mut rng)?;
    let rhs = encryptor.encrypt(&encoder.encode_real(&[3.0, -4.0])?, &mut rng)?;
    let product = ctx.evaluator().mul(&lhs, &rhs, Some(&eval_keys))?;
    let rescaled = ctx.evaluator().rescale_next(&product)?;
    Ok(ExampleOutput::new(
        "ckks_rescale",
        [
            format!("level={}", rescaled.level()),
            format!("scale={}", rescaled.scale().value()),
        ],
    ))
}

/// Runs the CKKS DFT scaffold and inverse transform.
pub fn ckks_dft() -> Result<ExampleOutput, ExampleError> {
    let input = phantom_schemes::ckks::Ciphertext::new(
        vec![
            Complex64::real(1.0),
            Complex64::new(0.0, 1.0),
            Complex64::real(-1.0),
            Complex64::new(0.0, -1.0),
        ],
        phantom_schemes::ckks::Scale::from_bits(10)?,
        2,
        phantom_schemes::ckks::Precision::new(10.0),
        1,
    );
    let dft = DftEvaluator::new(ckks_params()?);
    let transformed = dft.transform(&input, DftDirection::Forward)?;
    let roundtrip = dft.transform(&transformed, DftDirection::Inverse)?;
    Ok(ExampleOutput::new(
        "ckks_dft",
        roundtrip
            .slots()
            .iter()
            .map(|slot| format!("{:.1}+{:.1}i", slot.re, slot.im)),
    ))
}

/// Runs the CKKS reciprocal scaffold.
pub fn ckks_inverse() -> Result<ExampleOutput, ExampleError> {
    let input = ckks_ciphertext(&[Complex64::real(2.0), Complex64::real(-4.0)])?;
    let inverse = InverseEvaluator::new(ckks_params()?).reciprocal(&input, 0.1)?;
    Ok(ExampleOutput::new(
        "ckks_inverse",
        inverse.slots().iter().map(|slot| format!("{:.2}", slot.re)),
    ))
}

/// Runs the CKKS bootstrapping scaffold.
pub fn ckks_bootstrapping() -> Result<ExampleOutput, ExampleError> {
    let params = ckks_params()?;
    let boot_params = default_bootstrap_params(params.clone())?;
    let key = BootstrapKeyGenerator::new(boot_params.clone()).generate(&[1, 2]);
    let bootstrapper = Bootstrapper::new(boot_params.clone(), key);
    let input = ckks_ciphertext(&[Complex64::real(1.25), Complex64::real(-2.0)])?;
    let output = bootstrapper.bootstrap(&input)?;
    Ok(ExampleOutput::new(
        "ckks_bootstrapping",
        [
            format!("level={}", output.level()),
            format!("precision={}", output.precision().bits()),
        ],
    ))
}

/// Runs a multiparty BGV partial-decryption workflow.
pub fn mpbgv_basic() -> Result<ExampleOutput, ExampleError> {
    let params = bgv_params()?;
    let ctx = BgvContext::new(params.clone());
    let mut rng = rng(7);
    let keys = ctx.keygen()?.generate_keypair(&mut rng)?;
    let encoder = ctx.encoder();
    let ciphertext = ctx
        .encryptor(keys.public)?
        .encrypt(&encoder.encode_u64(&[7, 8, 9, 10])?, &mut rng)?;
    let partial =
        mpbgv::PartialDecryptor::new(params, session(ProtocolKind::PartialDecryption, 100)?);
    let mut aggregator = ShareAggregator::new(
        session(ProtocolKind::PartialDecryption, 100)?,
        ShareKind::PartialDecryption,
    );
    aggregator.add_share(partial.create_share(id(1)?, &ciphertext)?)?;
    aggregator.add_share(partial.create_share(id(2)?, &ciphertext)?)?;
    let reconstructed = partial.aggregate_plaintext(&aggregator)?;
    Ok(ExampleOutput::new(
        "mpbgv_basic",
        encoder.decode_u64(&reconstructed)?[..4].iter(),
    ))
}

/// Runs a multiparty CKKS partial-decryption workflow.
pub fn mpckks_basic() -> Result<ExampleOutput, ExampleError> {
    let params = ckks_params()?;
    let ctx = CkksContext::new(params.clone());
    let mut rng = rng(8);
    let keys = ctx.keygen()?.generate_keypair(&mut rng)?;
    let encoder = ctx.encoder();
    let ciphertext = ctx
        .encryptor(keys.public)?
        .encrypt(&encoder.encode_real(&[0.5, -1.25, 4.0])?, &mut rng)?;
    let partial =
        mpckks::PartialDecryptor::new(params, session(ProtocolKind::PartialDecryption, 200)?);
    let mut aggregator = ShareAggregator::new(
        session(ProtocolKind::PartialDecryption, 200)?,
        ShareKind::PartialDecryption,
    );
    aggregator.add_share(partial.create_share(id(1)?, &ciphertext)?)?;
    aggregator.add_share(partial.create_share(id(2)?, &ciphertext)?)?;
    let reconstructed = partial.aggregate_plaintext(&aggregator)?;
    Ok(ExampleOutput::new(
        "mpckks_basic",
        encoder.decode_real(&reconstructed)?[..3]
            .iter()
            .map(|value| format!("{value:.2}")),
    ))
}

/// Runs multiparty CKKS interactive bootstrapping.
pub fn mpckks_interactive_bootstrap() -> Result<ExampleOutput, ExampleError> {
    let params = ckks_params()?;
    let boot_params = BootstrapParams::builder(params.clone())
        .target_level(params.initial_level())
        .target_precision_bits(18.0)
        .build()?;
    let ctx = CkksContext::new(params.clone());
    let mut rng = rng(9);
    let keys = ctx.keygen()?.generate_keypair(&mut rng)?;
    let encoder = ctx.encoder();
    let ciphertext = ctx.encryptor(keys.public)?.encrypt(
        &encoder.encode_complex(&[Complex64::new(1.0, 0.5), Complex64::real(-2.0)])?,
        &mut rng,
    )?;
    let bootstrap = mpckks::InteractiveBootstrap::new(
        params,
        boot_params,
        session(ProtocolKind::InteractiveBootstrap, 300)?,
    );
    let mut aggregator = ShareAggregator::new(
        session(ProtocolKind::InteractiveBootstrap, 300)?,
        ShareKind::InteractiveBootstrap,
    );
    aggregator.add_share(bootstrap.create_share(id(1)?, &ciphertext)?)?;
    aggregator.add_share(bootstrap.create_share(id(2)?, &ciphertext)?)?;
    let refreshed = bootstrap.aggregate_refreshed(&aggregator)?;
    Ok(ExampleOutput::new(
        "mpckks_interactive_bootstrap",
        [
            format!("level={}", refreshed.level()),
            format!("precision={}", refreshed.precision().bits()),
        ],
    ))
}

fn bfv_params() -> Result<BfvParams, ExampleError> {
    Ok(BfvParams::new(toy_ring()?, 17)?)
}

fn bgv_params() -> Result<BgvParams, ExampleError> {
    Ok(BgvParams::new(toy_ring()?, 17)?)
}

fn ckks_params() -> Result<CkksParams, ExampleError> {
    Ok(CkksParams::builder()
        .degree(8)
        .moduli(vec![257, 769, 3329])
        .default_scale_bits(10)
        .build()?)
}

fn toy_ring() -> Result<Ring, ExampleError> {
    Ok(Ring::new(
        Degree::new(8)?,
        vec![Modulus::new(257)?, Modulus::new(769)?],
    )?)
}

fn ckks_ciphertext(slots: &[Complex64]) -> Result<phantom_schemes::ckks::Ciphertext, ExampleError> {
    Ok(phantom_schemes::ckks::Ciphertext::new(
        slots.to_vec(),
        phantom_schemes::ckks::Scale::from_bits(10)?,
        2,
        phantom_schemes::ckks::Precision::new(10.0),
        1,
    ))
}

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn id(value: u64) -> Result<ParticipantId, ExampleError> {
    Ok(ParticipantId::new(value)?)
}

fn session(protocol: ProtocolKind, offset: u64) -> Result<SessionState, ExampleError> {
    Ok(SessionState::new(
        SessionId::new(offset + protocol_tag(protocol) as u64)?,
        protocol,
        ParticipantSet::new(vec![id(1)?, id(2)?, id(3)?])?,
        2,
    )?)
}

fn protocol_tag(protocol: ProtocolKind) -> u32 {
    match protocol {
        ProtocolKind::CollectiveKeyGen => 1,
        ProtocolKind::RelinearizationKeyGen => 2,
        ProtocolKind::GaloisKeyGen => 3,
        ProtocolKind::PartialDecryption => 4,
        ProtocolKind::ReEncryption => 5,
        ProtocolKind::InteractiveBootstrap => 6,
        ProtocolKind::Custom(tag) => tag,
    }
}

impl From<phantom_bootstrapping::BootstrappingError> for ExampleError {
    fn from(error: phantom_bootstrapping::BootstrappingError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<phantom_circuits::CircuitsError> for ExampleError {
    fn from(error: phantom_circuits::CircuitsError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<phantom_multiparty::MultipartyError> for ExampleError {
    fn from(error: phantom_multiparty::MultipartyError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<phantom_ring::RingError> for ExampleError {
    fn from(error: phantom_ring::RingError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<phantom_schemes::SchemesError> for ExampleError {
    fn from(error: phantom_schemes::SchemesError) -> Self {
        Self::new(error.to_string())
    }
}
