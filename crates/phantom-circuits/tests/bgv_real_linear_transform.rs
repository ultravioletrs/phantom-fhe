//! Real (encrypted) BGV linear transforms:
//! `LinearTransformEvaluator::apply_real` - the row-local diagonal-method
//! evaluator built on `phantom-schemes`'s real `rotate_real`/`mul_plain`/
//! `add` primitives. See that method's own module doc comment for why it's
//! restricted to row-local (block-diagonal) transforms.

use phantom_circuits::bgv::LinearTransformEvaluator;
use phantom_circuits::common::LinearTransform;
use phantom_lattice::rgsw::GadgetDecompositionParams;
use phantom_ring::{Degree, Modulus, Ring};
use phantom_schemes::bgv::{BgvContext, BgvParams, BgvRelinearizationKey};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

const DEGREE: usize = 8;
const MODULUS: u64 = 1_000_000_000_000_037;
const T: u64 = 17;

fn params() -> BgvParams {
    let ring = Ring::new(
        Degree::new(DEGREE).unwrap(),
        vec![Modulus::new(MODULUS).unwrap()],
    )
    .unwrap();
    BgvParams::new(ring, T).unwrap()
}

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

/// Rotation keys for every nonzero row-local diagonal offset a transform
/// needs (offset 0 needs none - `apply_real` never rotates for it).
fn rotation_keys_for(
    keygen: &phantom_schemes::bgv::BgvKeyGenerator,
    sk: &phantom_lattice::rlwe::SecretKey,
    params: &BgvParams,
    offsets: &[usize],
    rng: &mut ChaCha20Rng,
) -> Vec<(usize, BgvRelinearizationKey)> {
    let decomposition_params = GadgetDecompositionParams::new(8, 7).unwrap();
    offsets
        .iter()
        .filter(|&&k| k != 0)
        .map(|&k| {
            let element = params.rotation_element(k);
            let key = keygen
                .generate_rotation_key_real(sk, element, decomposition_params, rng)
                .unwrap();
            (element, key)
        })
        .collect()
}

fn dense_matrix_vector(rows: &[Vec<u64>], x: &[u64], t: u64) -> Vec<u64> {
    rows.iter()
        .map(|row| {
            row.iter()
                .zip(x)
                .fold(0u128, |acc, (&w, &v)| acc + (w as u128) * (v as u128))
                % t as u128
        })
        .map(|v| v as u64)
        .collect()
}

#[test]
#[allow(clippy::needless_range_loop)]
fn apply_real_computes_a_row_local_dense_matrix_vector_product() {
    let params = params();
    let half = DEGREE / 2;
    let ctx = BgvContext::new(params.clone());
    let mut rng = seeded_rng(71);
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair_real(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret.clone()).unwrap();
    let evaluator = LinearTransformEvaluator::new(params.clone());

    // A dense-within-each-row (block-diagonal) matrix: row r's output only
    // depends on inputs from r's own row, but is otherwise a full, not
    // diagonal-sparse, (half x half) block - exercises every row-local
    // rotation offset.
    let n = DEGREE;
    let mut rows = vec![vec![0u64; n]; n];
    for r in 0..n {
        let row_half = r / half;
        for c in row_half * half..row_half * half + half {
            rows[r][c] = ((r + 1) * 3 + c) as u64 % T;
        }
    }
    let transform = LinearTransform::dense(rows.clone()).unwrap();

    let x_values: Vec<u64> = (0..n as u64).map(|i| (i * 5 + 2) % T).collect();
    let x_pt = encoder.encode_batched(&x_values).unwrap();
    let x_ct = encryptor.encrypt(&x_pt, &mut rng).unwrap();

    let offsets: Vec<usize> = (0..half).collect();
    let rotation_keys = rotation_keys_for(&keygen, &keys.secret, &params, &offsets, &mut rng);

    let result = evaluator
        .apply_real(&x_ct, &transform, &rotation_keys)
        .unwrap();
    let decoded = encoder
        .decode_batched(&decryptor.decrypt(&result).unwrap())
        .unwrap();

    let expected = dense_matrix_vector(&rows, &x_values, T);
    assert_eq!(decoded, expected);
}

#[test]
#[allow(clippy::needless_range_loop)]
fn apply_real_matches_rotate_real_for_a_row_local_permutation() {
    let params = params();
    let half = DEGREE / 2;
    let ctx = BgvContext::new(params.clone());
    let mut rng = seeded_rng(73);
    let keygen = ctx.keygen().unwrap();
    let keys = keygen.generate_keypair_real(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret.clone());
    let decryptor = ctx.decryptor(keys.secret.clone()).unwrap();
    let evaluator = LinearTransformEvaluator::new(params.clone());

    let n = DEGREE;
    let shift = 2usize;
    // Row-local cyclic-by-shift permutation: within each row, slot j gets
    // the value that was at (j+shift) mod half in that same row.
    let mut rows = vec![vec![0u64; n]; n];
    for r in 0..n {
        let row_base = (r / half) * half;
        let local = r % half;
        rows[r][row_base + (local + shift) % half] = 1;
    }
    let transform = LinearTransform::dense(rows).unwrap();

    let x_values: Vec<u64> = (0..n as u64).map(|i| i + 1).collect();
    let x_pt = encoder.encode_batched(&x_values).unwrap();
    let x_ct = encryptor.encrypt(&x_pt, &mut rng).unwrap();

    let rotation_keys = rotation_keys_for(&keygen, &keys.secret, &params, &[shift], &mut rng);
    let result = evaluator
        .apply_real(&x_ct, &transform, &rotation_keys)
        .unwrap();
    let decoded = encoder
        .decode_batched(&decryptor.decrypt(&result).unwrap())
        .unwrap();

    let mut expected_row0 = x_values[..half].to_vec();
    expected_row0.rotate_left(shift);
    let mut expected_row1 = x_values[half..].to_vec();
    expected_row1.rotate_left(shift);
    let expected: Vec<u64> = expected_row0.into_iter().chain(expected_row1).collect();
    assert_eq!(decoded, expected);
}

#[test]
fn apply_real_rejects_a_transform_with_a_cross_row_entry() {
    let params = params();
    let half = DEGREE / 2;
    let n = DEGREE;
    let ctx = BgvContext::new(params.clone());
    let mut rng = seeded_rng(79);
    let keys = ctx
        .keygen()
        .unwrap()
        .generate_keypair_real(&mut rng)
        .unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret);
    let evaluator = LinearTransformEvaluator::new(params.clone());

    let mut rows = vec![vec![0u64; n]; n];
    // row 0 (in row0's half) reads from column `half` (row1's half) -
    // a cross-row entry, must be rejected.
    rows[0][half] = 1;
    let transform = LinearTransform::dense(rows).unwrap();

    let x_pt = encoder.encode_batched(&vec![1u64; n]).unwrap();
    let x_ct = encryptor.encrypt(&x_pt, &mut rng).unwrap();

    assert!(evaluator.apply_real(&x_ct, &transform, &[]).is_err());
}

#[test]
#[allow(clippy::needless_range_loop)]
fn apply_real_rejects_a_missing_rotation_key() {
    let params = params();
    let half = DEGREE / 2;
    let n = DEGREE;
    let ctx = BgvContext::new(params.clone());
    let mut rng = seeded_rng(83);
    let keys = ctx
        .keygen()
        .unwrap()
        .generate_keypair_real(&mut rng)
        .unwrap();
    let encoder = ctx.encoder();
    let encryptor = ctx.real_secret_key_encryptor(keys.secret);
    let evaluator = LinearTransformEvaluator::new(params.clone());

    let mut rows = vec![vec![0u64; n]; n];
    for r in 0..n {
        let row_base = (r / half) * half;
        let local = r % half;
        rows[r][row_base + (local + 1) % half] = 1;
    }
    let transform = LinearTransform::dense(rows).unwrap();

    let x_pt = encoder.encode_batched(&vec![1u64; n]).unwrap();
    let x_ct = encryptor.encrypt(&x_pt, &mut rng).unwrap();

    assert!(evaluator.apply_real(&x_ct, &transform, &[]).is_err());
}
