use phantom_examples::{
    bfv_basic, bfv_batching, bfv_real_basic, bfv_rotation, bgv_basic, bgv_polynomial,
    bgv_real_basic, ckks_basic, ckks_bootstrapping, ckks_dft, ckks_inverse, ckks_real_basic,
    ckks_rescale, mpbgv_basic, mpckks_basic, mpckks_interactive_bootstrap,
};

#[test]
fn documented_examples_run_on_toy_presets() {
    let outputs = [
        bfv_basic().unwrap(),
        bfv_batching().unwrap(),
        bfv_rotation().unwrap(),
        bgv_basic().unwrap(),
        bgv_polynomial().unwrap(),
        ckks_basic().unwrap(),
        ckks_rescale().unwrap(),
        ckks_dft().unwrap(),
        ckks_inverse().unwrap(),
        ckks_bootstrapping().unwrap(),
    ];

    for output in outputs {
        assert!(
            !output.values.is_empty(),
            "{} produced no values",
            output.name
        );
    }
}

#[test]
fn real_examples_run_on_realistically_sized_parameters() {
    // `mpbgv_basic`/`mpckks_basic` moved here alongside the others:
    // `mpbgv::CollectiveKeyGen`/`PartialDecryptor` and
    // `mpckks::CollectiveKeyGen`/`PartialDecryptor` are real now
    // (Workstream 7), and both need noise-safe, realistically-sized
    // parameters - the toy presets the other group above uses were never
    // safe for either real path (see `bgv_real_basic`'s own doc comment for
    // the same requirement; `mpckks_basic`'s own dedicated
    // `mpckks_real_params()` additionally needs a much larger scale than
    // `ckks_real_basic`'s own fixture, since CKKS's own smudging noise
    // costs decode precision directly - see `mpckks::reencryption`'s own
    // doc comment). `mpckks_interactive_bootstrap` joined them once
    // `mpckks::InteractiveBootstrap` went real too (Workstream 7 item 5),
    // for the identical reason.
    let outputs = [
        bgv_real_basic().unwrap(),
        bfv_real_basic().unwrap(),
        ckks_real_basic().unwrap(),
        mpbgv_basic().unwrap(),
        mpckks_basic().unwrap(),
        mpckks_interactive_bootstrap().unwrap(),
    ];

    for output in outputs {
        assert!(
            !output.values.is_empty(),
            "{} produced no values",
            output.name
        );
    }
}
