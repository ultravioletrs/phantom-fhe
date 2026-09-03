//! Pedersen VSS / distributed-key-generation primitive tests (Workstream 7
//! item 4/5, Stage 1 - see `crates/phantom-multiparty/src/vss/mod.rs`'s own
//! module doc comment). This primitive is standalone and scheme-agnostic;
//! nothing here touches `mpbgv`/`mpbfv`/`mpckks`.

use curve25519_dalek::scalar::Scalar;
use phantom_multiparty::common::ParticipantId;
use phantom_multiparty::vss::{
    reconstruct_secret, verify_combined, PedersenGenerators, ShareAccumulator, VectorPolynomial,
    VssCommitmentSet, VssShare,
};
use phantom_multiparty::MultipartyError;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn id(value: u64) -> ParticipantId {
    ParticipantId::new(value).unwrap()
}

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

#[test]
fn single_dealer_shamir_round_trip_recovers_the_secret() {
    let vector_len = 4;
    let threshold = 3;
    let generators = PedersenGenerators::derive(vector_len);
    let dealer = id(1);
    let secret: Vec<i128> = vec![1, -1, 0, 1];

    let polynomial = VectorPolynomial::sample(&mut rng(1), dealer, &secret, threshold).unwrap();
    let commitments = polynomial.commit(&generators).unwrap();

    let participants = [id(1), id(2), id(3), id(4), id(5)];
    let mut shares = Vec::new();
    for &recipient in &participants {
        let share = polynomial.create_share(recipient);
        share.verify(&commitments, &generators).unwrap();
        shares.push((recipient, share.values().to_vec()));
    }

    // Reconstruct from exactly `threshold` shares.
    let reconstructed = reconstruct_secret(&shares[..threshold], threshold, 32).unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn multi_dealer_dkg_round_trip_reconstructs_the_sum_of_secrets() {
    let vector_len = 3;
    let threshold = 3;
    let n = 5;
    let generators = PedersenGenerators::derive(vector_len);
    let participants: Vec<ParticipantId> = (1..=n as u64).map(id).collect();

    let per_dealer_secrets: Vec<Vec<i128>> = vec![
        vec![1, -1, 0],
        vec![-1, 1, 1],
        vec![0, 0, -1],
        vec![1, 1, 1],
        vec![-1, -1, 0],
    ];

    // Each participant is also a dealer - the realistic DKG shape.
    let polynomials: Vec<VectorPolynomial> = participants
        .iter()
        .zip(&per_dealer_secrets)
        .enumerate()
        .map(|(i, (&dealer, secret))| {
            VectorPolynomial::sample(&mut rng(10 + i as u8), dealer, secret, threshold).unwrap()
        })
        .collect();
    let commitment_sets: Vec<VssCommitmentSet> = polynomials
        .iter()
        .map(|poly| poly.commit(&generators).unwrap())
        .collect();

    // Every participant accumulates a verified share from every dealer.
    let mut accumulators: Vec<ShareAccumulator> = participants
        .iter()
        .map(|&p| ShareAccumulator::new(p, vector_len))
        .collect();
    for (accumulator, &recipient) in accumulators.iter_mut().zip(&participants) {
        for (poly, commitments) in polynomials.iter().zip(&commitment_sets) {
            let share = poly.create_share(recipient);
            accumulator
                .add_verified_share(&share, commitments, &generators)
                .unwrap();
        }
        assert_eq!(accumulator.dealer_count(), n);
    }

    let final_shares: Vec<(ParticipantId, Vec<Scalar>)> = participants
        .iter()
        .zip(&accumulators)
        .map(|(&p, acc)| (p, acc.finalize().0))
        .collect();

    let expected_sum: Vec<i128> = (0..vector_len)
        .map(|slot| per_dealer_secrets.iter().map(|s| s[slot]).sum())
        .collect();

    let magnitude_bound = n as i128; // each secret coordinate is in {-1,0,1}
    let reconstructed =
        reconstruct_secret(&final_shares[..threshold], threshold, magnitude_bound).unwrap();
    assert_eq!(reconstructed, expected_sum);
}

#[test]
fn subset_independence_two_different_qualifying_subsets_agree() {
    let vector_len = 2;
    let threshold = 3;
    let n = 7; // >= 2*threshold - 1, so two disjoint-ish subsets exist
    let generators = PedersenGenerators::derive(vector_len);
    let participants: Vec<ParticipantId> = (1..=n as u64).map(id).collect();

    let per_dealer_secrets: Vec<Vec<i128>> = (0..n)
        .map(|i| vec![(i as i128 % 3) - 1, ((i + 1) as i128 % 3) - 1])
        .collect();

    let polynomials: Vec<VectorPolynomial> = participants
        .iter()
        .zip(&per_dealer_secrets)
        .enumerate()
        .map(|(i, (&dealer, secret))| {
            VectorPolynomial::sample(&mut rng(30 + i as u8), dealer, secret, threshold).unwrap()
        })
        .collect();
    let commitment_sets: Vec<VssCommitmentSet> = polynomials
        .iter()
        .map(|poly| poly.commit(&generators).unwrap())
        .collect();

    let mut final_shares = Vec::new();
    for &recipient in &participants {
        let mut accumulator = ShareAccumulator::new(recipient, vector_len);
        for (poly, commitments) in polynomials.iter().zip(&commitment_sets) {
            let share = poly.create_share(recipient);
            accumulator
                .add_verified_share(&share, commitments, &generators)
                .unwrap();
        }
        final_shares.push((recipient, accumulator.finalize().0));
    }

    let magnitude_bound = n as i128;
    let subset_a = &final_shares[0..threshold];
    let subset_b = &final_shares[n - threshold..n];
    // With n=7, threshold=3: subset_a = participants 1..3, subset_b = 5..7 - disjoint.
    assert!(subset_a
        .iter()
        .map(|(p, _)| *p)
        .collect::<std::collections::BTreeSet<_>>()
        .is_disjoint(
            &subset_b
                .iter()
                .map(|(p, _)| *p)
                .collect::<std::collections::BTreeSet<_>>()
        ));

    let reconstructed_a = reconstruct_secret(subset_a, threshold, magnitude_bound).unwrap();
    let reconstructed_b = reconstruct_secret(subset_b, threshold, magnitude_bound).unwrap();
    assert_eq!(reconstructed_a, reconstructed_b);
}

#[test]
fn vss_share_verification_rejects_a_tampered_commitment() {
    let vector_len = 2;
    let threshold = 2;
    let generators = PedersenGenerators::derive(vector_len);
    let dealer = id(1);
    let polynomial = VectorPolynomial::sample(&mut rng(2), dealer, &[1, -1], threshold).unwrap();
    let commitments = polynomial.commit(&generators).unwrap();
    let share = polynomial.create_share(id(2));
    share.verify(&commitments, &generators).unwrap();

    let mut tampered_bytes = commitments.encode();
    // Flip a bit inside the first commitment's own 32 bytes (after the
    // 6-byte tag + 8-byte dealer id + 8-byte length prefix header).
    let header_len = 6 + 8 + 8;
    tampered_bytes[header_len] ^= 0x01;
    let tampered = VssCommitmentSet::decode(&tampered_bytes).unwrap();

    // A flipped bit either produces a validly-decodable-but-wrong curve
    // point (caught by the Pedersen equation itself, `InvalidVssShare`) or
    // an invalid point encoding entirely (caught earlier, at decompression,
    // `MalformedMessage`) - both are "verification correctly failed", the
    // property under test; which specific error fires depends on the exact
    // bit flipped, not on anything this test should assume.
    let err = share.verify(&tampered, &generators).unwrap_err();
    assert!(
        matches!(
            err,
            MultipartyError::InvalidVssShare | MultipartyError::MalformedMessage
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn vss_share_verification_rejects_a_tampered_share_value() {
    let vector_len = 2;
    let threshold = 2;
    let generators = PedersenGenerators::derive(vector_len);
    let dealer = id(1);
    let polynomial = VectorPolynomial::sample(&mut rng(3), dealer, &[1, -1], threshold).unwrap();
    let commitments = polynomial.commit(&generators).unwrap();
    let share = polynomial.create_share(id(2));

    let mut tampered_bytes = share.encode();
    // Flip a bit inside the first value's own 32 bytes (after the 6-byte
    // tag + 8-byte dealer id + 8-byte recipient id + 8-byte length prefix).
    let header_len = 6 + 8 + 8 + 8;
    tampered_bytes[header_len] ^= 0x01;

    // A flipped bit either still decodes (a validly-canonical-but-wrong
    // scalar, caught by the Pedersen equation, `InvalidVssShare`) or fails
    // to decode at all (a non-canonical scalar encoding, `MalformedMessage`)
    // - both are "tampering correctly detected", the property under test.
    match VssShare::decode(&tampered_bytes) {
        Ok(tampered) => {
            assert_eq!(
                tampered.verify(&commitments, &generators).unwrap_err(),
                MultipartyError::InvalidVssShare
            );
        }
        Err(err) => assert_eq!(err, MultipartyError::MalformedMessage),
    }
}

#[test]
fn a_share_verified_against_the_wrong_dealer_is_rejected() {
    let vector_len = 2;
    let threshold = 2;
    let generators = PedersenGenerators::derive(vector_len);
    let dealer_a = VectorPolynomial::sample(&mut rng(4), id(1), &[1, 0], threshold).unwrap();
    let dealer_b = VectorPolynomial::sample(&mut rng(5), id(2), &[0, 1], threshold).unwrap();
    let commitments_b = dealer_b.commit(&generators).unwrap();

    let share_from_a = dealer_a.create_share(id(3));
    assert_eq!(
        share_from_a
            .verify(&commitments_b, &generators)
            .unwrap_err(),
        MultipartyError::InvalidVssShare
    );
}

#[test]
fn malformed_inputs_are_rejected() {
    let vector_len = 2;
    let threshold = 2;
    let generators = PedersenGenerators::derive(vector_len);
    let dealer = id(1);
    let polynomial = VectorPolynomial::sample(&mut rng(6), dealer, &[1, -1], threshold).unwrap();
    let commitments = polynomial.commit(&generators).unwrap();

    // Vector-length mismatch: verifying against generators of a different length.
    let wrong_generators = PedersenGenerators::derive(vector_len + 1);
    let share = polynomial.create_share(id(2));
    assert!(share.verify(&commitments, &wrong_generators).is_err());

    // Duplicate evaluation points in reconstruct_secret.
    let dup_shares = vec![
        (id(2), vec![Scalar::ONE, Scalar::ONE]),
        (id(2), vec![Scalar::ONE, Scalar::ONE]),
    ];
    assert_eq!(
        reconstruct_secret(&dup_shares, 2, 32).unwrap_err(),
        MultipartyError::DuplicateParticipant
    );

    // Fewer than threshold shares.
    let one_share = vec![(id(2), vec![Scalar::ONE, Scalar::ONE])];
    assert_eq!(
        reconstruct_secret(&one_share, 2, 32).unwrap_err(),
        MultipartyError::ThresholdNotMet
    );

    // recover_centered given a target outside its own bound, surfaced
    // through reconstruct_secret with a too-tight magnitude_bound.
    let participants = [id(2), id(3)];
    let mut shares = Vec::new();
    for &recipient in &participants {
        let share = polynomial.create_share(recipient);
        shares.push((recipient, share.values().to_vec()));
    }
    // The true secret coordinate 1 has value -1; a magnitude_bound of 0
    // cannot represent it.
    assert!(reconstruct_secret(&shares, 2, 0).is_err());
}

#[test]
fn combine_time_verification_accepts_genuine_and_rejects_tampered_combined_shares() {
    let vector_len = 2;
    let threshold = 2;
    let n = 3;
    let generators = PedersenGenerators::derive(vector_len);
    let participants: Vec<ParticipantId> = (1..=n as u64).map(id).collect();
    let secrets = [vec![1i128, 0], vec![-1, 1], vec![0, -1]];

    let polynomials: Vec<VectorPolynomial> = participants
        .iter()
        .zip(&secrets)
        .enumerate()
        .map(|(i, (&dealer, secret))| {
            VectorPolynomial::sample(&mut rng(40 + i as u8), dealer, secret, threshold).unwrap()
        })
        .collect();
    let commitment_sets: Vec<VssCommitmentSet> = polynomials
        .iter()
        .map(|poly| poly.commit(&generators).unwrap())
        .collect();
    let combined_commitments = VssCommitmentSet::combine(&commitment_sets).unwrap();

    let recipient = participants[0];
    let mut accumulator = ShareAccumulator::new(recipient, vector_len);
    for (poly, commitments) in polynomials.iter().zip(&commitment_sets) {
        let share = poly.create_share(recipient);
        accumulator
            .add_verified_share(&share, commitments, &generators)
            .unwrap();
    }
    let (values, blinding) = accumulator.finalize();

    verify_combined(
        recipient,
        &values,
        blinding,
        &combined_commitments,
        &generators,
    )
    .unwrap();

    let mut tampered_values = values.clone();
    tampered_values[0] += Scalar::ONE;
    assert_eq!(
        verify_combined(
            recipient,
            &tampered_values,
            blinding,
            &combined_commitments,
            &generators
        )
        .unwrap_err(),
        MultipartyError::InvalidVssShare
    );
}

#[test]
fn randomized_full_pipeline_round_trip() {
    let mut master_rng = rng(99);
    let mut counter: u8 = 0;
    for trial in 0..40 {
        let vector_len = 2 + (trial % 3);
        let threshold = 2 + (trial % 3);
        let n = threshold + 1 + (trial % 4);
        let per_dealer_bound: i128 = 1;
        let generators = PedersenGenerators::derive(vector_len);
        let participants: Vec<ParticipantId> = (1..=n as u64).map(id).collect();

        let secrets: Vec<Vec<i128>> = (0..n)
            .map(|i| (0..vector_len).map(|j| ((i + j) as i128 % 3) - 1).collect())
            .collect();

        let polynomials: Vec<VectorPolynomial> = participants
            .iter()
            .zip(&secrets)
            .map(|(&dealer, secret)| {
                counter = counter.wrapping_add(1);
                VectorPolynomial::sample(&mut master_rng, dealer, secret, threshold).unwrap()
            })
            .collect();
        let commitment_sets: Vec<VssCommitmentSet> = polynomials
            .iter()
            .map(|poly| poly.commit(&generators).unwrap())
            .collect();

        let mut final_shares = Vec::new();
        for &recipient in &participants {
            let mut accumulator = ShareAccumulator::new(recipient, vector_len);
            for (poly, commitments) in polynomials.iter().zip(&commitment_sets) {
                let share = poly.create_share(recipient);
                accumulator
                    .add_verified_share(&share, commitments, &generators)
                    .unwrap();
            }
            final_shares.push((recipient, accumulator.finalize().0));
        }

        let expected_sum: Vec<i128> = (0..vector_len)
            .map(|slot| secrets.iter().map(|s| s[slot]).sum())
            .collect();
        let magnitude_bound = n as i128 * per_dealer_bound;

        let reconstructed =
            reconstruct_secret(&final_shares[..threshold], threshold, magnitude_bound).unwrap();
        assert_eq!(reconstructed, expected_sum, "trial {trial} failed");
    }
}
