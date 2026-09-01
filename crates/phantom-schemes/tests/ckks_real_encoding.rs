//! Tests for CKKS's real canonical-embedding encoder/decoder
//! (`Encoder::encode_complex_real`/`decode_complex_real` - Workstream 5
//! item 3, the first piece of the CKKS rebuild). Complements
//! `phase7_ckks.rs`'s coverage of the still-transparent
//! `encode_complex`/`decode_complex` path, which this doesn't touch.

use phantom_schemes::ckks::{CkksContext, CkksParams, Complex64};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Real CKKS encoding needs headroom for Delta-scaled coefficients the way
// real BGV/BFV need headroom for their own scaled values (see their own
// tests' comments) - a single large modulus, matching the scale used
// throughout phantom-schemes's other "real" test suites.
const REAL_DEGREE: usize = 8;
const REAL_MODULUS: u64 = 1_000_000_000_000_037;
const SCALE_BITS: u32 = 30;

fn real_encoding_params() -> CkksParams {
    CkksParams::builder()
        .degree(REAL_DEGREE)
        .moduli(vec![REAL_MODULUS])
        .default_scale_bits(SCALE_BITS)
        .build()
        .unwrap()
}

fn assert_close(actual: &[Complex64], expected: &[Complex64], tol: f64) {
    for (a, e) in actual.iter().zip(expected) {
        assert!(
            (a.re - e.re).abs() < tol && (a.im - e.im).abs() < tol,
            "actual={a:?} expected={e:?} tol={tol}"
        );
    }
}

#[test]
fn real_encode_decode_round_trips_for_a_hand_picked_case() {
    let ctx = CkksContext::new(real_encoding_params());
    let encoder = ctx.encoder();

    let values = vec![
        Complex64::new(0.5, -1.25),
        Complex64::new(-3.0, 2.0),
        Complex64::real(4.0),
        Complex64::new(0.0, -0.75),
    ];
    let plaintext = encoder.encode_complex_real(&values).unwrap();
    assert!(plaintext.poly().is_some());

    let decoded = encoder.decode_complex_real(&plaintext).unwrap();
    // Expected rounding error is ~0.5/Delta = 0.5/2^30 =~ 4.66e-10; allow a
    // small margin for the N=8-term summation amplifying it slightly.
    assert_close(&decoded, &values, 1e-7);
}

#[test]
fn real_encode_decode_round_trips_across_many_random_values() {
    let ctx = CkksContext::new(real_encoding_params());
    let encoder = ctx.encoder();
    let mut rng = ChaCha20Rng::from_seed([17u8; 32]);

    for trial in 0..200 {
        let values: Vec<Complex64> = (0..encoder.slot_count())
            .map(|_| {
                Complex64::new(
                    random_range(&mut rng, -10.0, 10.0),
                    random_range(&mut rng, -10.0, 10.0),
                )
            })
            .collect();

        let plaintext = encoder.encode_complex_real(&values).unwrap();
        let decoded = encoder.decode_complex_real(&plaintext).unwrap();
        assert_close(&decoded, &values, 1e-6);
        let _ = trial;
    }
}

#[test]
fn real_encode_decode_round_trips_with_fewer_values_than_slots() {
    let ctx = CkksContext::new(real_encoding_params());
    let encoder = ctx.encoder();

    let values = vec![Complex64::real(1.5)];
    let plaintext = encoder.encode_complex_real(&values).unwrap();
    let decoded = encoder.decode_complex_real(&plaintext).unwrap();

    assert_eq!(decoded.len(), encoder.slot_count());
    assert!((decoded[0].re - 1.5).abs() < 1e-7);
    for slot in &decoded[1..] {
        assert!(slot.re.abs() < 1e-7 && slot.im.abs() < 1e-7);
    }
}

#[test]
fn real_encoding_rejects_conjugate_invariant_params() {
    let params = CkksParams::builder()
        .degree(REAL_DEGREE)
        .moduli(vec![REAL_MODULUS])
        .default_scale_bits(SCALE_BITS)
        .conjugate_invariant(true)
        .build()
        .unwrap();
    let encoder = CkksContext::new(params).encoder();
    assert!(encoder
        .encode_complex_real(&[Complex64::real(1.0)])
        .is_err());
}

#[test]
fn decode_complex_real_rejects_a_transparent_plaintext() {
    let ctx = CkksContext::new(real_encoding_params());
    let encoder = ctx.encoder();
    let transparent = encoder.encode_complex(&[Complex64::real(1.0)]).unwrap();
    assert!(encoder.decode_complex_real(&transparent).is_err());
}

fn random_range(rng: &mut ChaCha20Rng, low: f64, high: f64) -> f64 {
    use rand_core::RngCore;
    let unit = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
    low + unit * (high - low)
}
