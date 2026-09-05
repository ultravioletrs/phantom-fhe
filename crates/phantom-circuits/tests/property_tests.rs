//! Property-based tests (Workstream 8 item 4), using `proptest` - the same
//! pre-approved dev-dependency `phantom-ring`/`phantom-lattice` already use
//! for exactly this purpose (see `docs/internal/dependency-policy.md`).
//!
//! `phantom-schemes`/`phantom-circuits`'s own encrypted-path tests already
//! carry extensive hand-seeded randomized coverage throughout (many
//! "verified across N random trials" tests), and `phantom-lattice`'s own
//! `tests/randomized.rs` already covers the RLWE/RGSW layer at that same
//! density - this file doesn't duplicate any of that. What it targets
//! instead is `phantom-circuits::common::lintrans`'s own scheme-independent
//! planning logic (the diagonal-matrix conversion and BSGS scheduling BSGS
//! evaluation is built on), which had no randomized coverage at all before
//! this file - only fixed, hand-picked matrices/offsets in
//! `phase8_common.rs`. This is exactly where proptest's own wider,
//! generator-driven input space (arbitrary matrix sizes and values, not a
//! handful of hand-picked ones) adds real value cheaply - no ciphertexts or
//! encryption involved, these are pure data-structure conversions.

use phantom_circuits::common::LinearTransform;
use proptest::prelude::*;

fn square_matrix(max_side: usize) -> impl Strategy<Value = Vec<Vec<i64>>> {
    (1..=max_side).prop_flat_map(|side| {
        prop::collection::vec(prop::collection::vec(-100i64..100, side), side)
    })
}

proptest! {
    /// A dense transform converted to cyclic diagonals and back must
    /// reproduce the exact original matrix - `to_dense`/`from_linear_transform`
    /// are meant to be exact inverses of each other (see their own doc
    /// comments), for any square matrix, not just the fixed cases
    /// `phase8_common.rs` already checks.
    #[test]
    fn dense_to_diagonal_and_back_round_trips_for_random_matrices(rows in square_matrix(6)) {
        let transform = LinearTransform::dense(rows.clone()).unwrap();
        let diagonal = transform.to_diagonal_matrix();
        prop_assert_eq!(diagonal.to_dense(), rows);
    }

    /// Every diagonal offset a `DiagonalMatrix` actually reports must be
    /// decomposable by its own `BabyStepGiantStepPlan` into a
    /// `(giant_step, baby_step)` pair that (a) reconstructs the original
    /// offset modulo the slot count and (b) only uses steps the plan itself
    /// advertises via `giant_steps`/`baby_steps` - the schedule a real BSGS
    /// evaluator would walk to actually cover every rotation it needs.
    #[test]
    fn bsgs_plan_decomposes_every_offset_it_covers(
        rows in square_matrix(6),
        baby_step_count in 1usize..6,
    ) {
        let transform = LinearTransform::dense(rows).unwrap();
        let diagonal = transform.to_diagonal_matrix();
        let plan = diagonal.bsgs_plan(baby_step_count).unwrap();

        for &offset in plan.diagonal_offsets() {
            let (giant, baby) = plan.decompose_offset(offset).unwrap();
            prop_assert_eq!((giant + baby) % plan.slot_count(), offset);
            prop_assert!(plan.giant_steps().contains(&giant));
            prop_assert!(plan.baby_steps().contains(&baby));
        }
    }
}
