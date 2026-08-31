//! Confirms the facade re-exports reach real, usable workspace APIs.

use phantom_fhe::ring::{Degree, Modulus, Ring};
use phantom_fhe::schemes::bfv::{BfvContext, BfvParams};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[test]
fn bfv_round_trip_through_facade() {
    let ring = Ring::new(Degree::new(8).unwrap(), vec![Modulus::new(257).unwrap()]).unwrap();
    let params = BfvParams::new(ring, 17).unwrap();
    let ctx = BfvContext::new(params);
    let mut rng = ChaCha20Rng::from_seed([7; 32]);

    let keys = ctx.keygen().unwrap().generate_keypair(&mut rng).unwrap();
    let encoder = ctx.encoder();
    let plaintext = encoder.encode_i64(&[-2, 3, 5, -6]).unwrap();
    let ciphertext = ctx
        .encryptor(keys.public)
        .unwrap()
        .encrypt(&plaintext, &mut rng)
        .unwrap();
    let decrypted = ctx
        .decryptor(keys.secret)
        .unwrap()
        .decrypt(&ciphertext)
        .unwrap();

    assert_eq!(
        &encoder.decode_i64(&decrypted).unwrap()[..4],
        &[-2, 3, 5, -6]
    );
}
