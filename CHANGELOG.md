# Changelog

All notable releases of Phantom-FHE are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project has not yet published a versioned release to crates.io, so entries
track the Alpha Hardening roadmap in
[`docs/internal/implementation-plan.md`](docs/internal/implementation-plan.md)
rather than semver bumps.

## Unreleased

### Added

- A production-shaped parameter preset (`N=8192`, table-validated against the homomorphicencryption.org 128-bit standard) proven correct end to end for BGV, BFV, and CKKS, in `crates/phantom-schemes/tests/production_preset.rs` (`#[ignore]`d by default - minutes-long at this scale, run explicitly with `--ignored`). See [`docs/user-guide.md#a-production-shaped-example`](docs/user-guide.md#a-production-shaped-example) for the exact numbers and scope (one example, not a general methodology or a security review).

### Fixed

Building and verifying that preset surfaced three real, previously-undiscovered bugs, all fixed:

- **`phantom-ring`**: `NttTable`'s root-finding could hang (not just run slowly) for a ciphertext modulus far larger than the ring degree - every existing preset happened to avoid this by keeping the modulus close in size to `2 * degree`. Fixed by computing a candidate root directly instead of searching for one.
- **`phantom-multiparty`**: `vss::scalar_embed::recover_centered` had an `O(magnitude_bound)` denial-of-service hazard for any caller passing a large bound (found via an external report, independently verified before fixing). Fixed to `O(1)` via direct canonical-byte inspection.
- **`phantom-schemes`**: real BFV decoding (`decode_u64_real`/`decode_batched_real`) silently produced wrong results for any ciphertext modulus with more than one RNS component - it only ever read the first modulus, correct by accident for every prior single-modulus test. Fixed with a new shared `phantom_ring::rns::decode_scaled_value` primitive.

### Documentation

- `docs/user-guide.md#choosing-parameters` restructured around a single per-preset table, each preset (BFV/BGV toy, CKKS toy, CKKS bootstrapping, the real-noise-headroom preset used by `*_real_basic`/multiparty examples, and the production-shaped example) carrying its own explicit security note - closes the `docs/internal/release-checklist.md` Beta checklist item asking for this, and the Beta checklist itself is now complete.

## 0.1.0 - Alpha (2026-09-05)

First tagged milestone: all 18 roadmap phases are implemented, and Alpha
Hardening Workstreams 1-9 and 11 are done (Workstream 10, this checklist,
closes the Alpha cycle; Workstream 2 has one item intentionally deferred,
noted below). Every crate compiles, is tested, and its examples run
end-to-end under `make ci`.

### Implemented crate map

| Crate | What it provides |
| --- | --- |
| `phantom-fhe` | Top-level facade re-exporting every crate below |
| `phantom-utils` | Cross-cutting support: serialization headers, buffers, secure sampling helpers |
| `phantom-ring` | RNS polynomial ring arithmetic: NTT, Barrett/Montgomery reduction, RNS basis extension/rescale, sampling |
| `phantom-lattice` | Scheme-agnostic RLWE and RGSW primitives: keygen, encryption, RNS hybrid key-switching, noise bounds |
| `phantom-schemes` | Concrete BGV, BFV, and CKKS scheme APIs, each with both a transparent scaffold path and a real (noise-bearing) encryption path |
| `phantom-circuits` | Shared circuit planning (linear transforms, BSGS) plus scheme-specific polynomial/comparison/inverse/mod1/DFT circuits |
| `phantom-bootstrapping` | CKKS bootstrapping pipeline (CoeffsToSlots, EvalMod, SlotsToCoeffs, modulus raise) end to end on real ciphertexts; BGV/BFV module locations reserved |
| `phantom-multiparty` | Threshold protocols for BGV, BFV, and CKKS: collective keygen, Galois/relinearization keygen, collaborative re-encryption, partial decryption, interactive bootstrap, and Pedersen VSS |
| `phantom-examples` | 16 runnable example binaries (workspace-only) |
| `phantom-benches` | Criterion benchmarks with toy/small parameter tiers and allocation-count diagnostics (workspace-only) |

### Supported examples

`cargo run -p phantom-examples --example <name>`, or `make examples` for
all of them: `bfv_basic`, `bfv_batching`, `bfv_real_basic`, `bfv_rotation`,
`bgv_basic`, `bgv_polynomial`, `bgv_real_basic`, `ckks_basic`,
`ckks_bootstrapping`, `ckks_dft`, `ckks_inverse`, `ckks_real_basic`,
`ckks_rescale`, `mpbgv_basic`, `mpckks_basic`, `mpckks_interactive_bootstrap`.
See [`docs/user-guide.md`](docs/user-guide.md#runnable-examples) for what
each one demonstrates.

### Security status

Phantom-FHE is a research-stage implementation (TRL 2-3), **not yet safe
for production secrets**. In brief (full detail in
[SECURITY.md](SECURITY.md) and
[`docs/technical-manual.md`](docs/technical-manual.md)):

- Real (non-transparent) encryption paths exist for RLWE/RGSW and for BGV,
  BFV, and CKKS, each with a real discrete-Gaussian error term and
  worst-case noise bounds - but several are opt-in alternatives to an
  existing transparent scaffold path, not yet the default every caller
  goes through.
- `sample_discrete_gaussian` is a real discrete Gaussian, but not
  constant-time.
- Real RNS hybrid key-switching, relinearization, and Galois-key machinery
  exist for RLWE, BGV, BFV, and CKKS (single-party and multiparty), but
  BFV/CKKS's own relinearization noise contribution has no formally-derived
  bound yet (BGV's does).
- CKKS bootstrapping's digit-extraction pipeline is real end to end on real
  ciphertexts; BGV/BFV bootstrapping remain reserved but unimplemented.
- All six multiparty threshold protocols (BGV, BFV, CKKS) are real,
  additive n-of-n constructions with format/shape validation and
  anti-replay protection, but have not had an adversarial security review
  for active (malicious-participant) attacks.
- Every parameter preset shipped in tests/examples/docs is a small
  development size, not a production security margin - there is currently
  no production parameter preset to graduate to (see
  [`docs/user-guide.md#choosing-parameters`](docs/user-guide.md#choosing-parameters)).

### Known scaffold limitations

- Every scheme's real encryption path is opt-in (`*_real` constructors);
  `phantom-circuits`, `phantom-bootstrapping`, and `phantom-multiparty`
  still default to the original transparent (non-encrypted) scaffold for
  most operations, since their toy parameters have no noise headroom for
  the real path yet.
- RGSW encrypts real gadget matrices with a real external product, but no
  bootstrapping construction in this codebase consumes it yet.
- CKKS lacks conjugate-invariant real packing and an NTT/FFT fast path for
  encode/decode.
- `phantom-benches`'s toy/small parameter tiers (Workstream 9) don't yet
  extend to the five scheme-level evaluator benches, for the same "no
  production preset yet" reason above.

### Planned production-hardening tracks

Tracked in detail in
[`docs/internal/implementation-plan.md`](docs/internal/implementation-plan.md):

- Migrate `phantom-circuits`/`phantom-bootstrapping`/`phantom-multiparty`'s
  remaining callers onto each scheme's real encryption path by default.
- Constant-time sampling (the discrete Gaussian CDT walk currently
  short-circuits at the matching bucket).
- Formally-derived noise bounds for BFV/CKKS relinearization and Galois
  key-switching (BGV's own is already derived).
- A bootstrapping construction that consumes RGSW's real external product;
  BGV/BFV bootstrapping.
- An adversarial (active-security) review of the multiparty protocols,
  closing the "well-formed but dishonestly-computed share" gap
  `SECURITY.md` documents today.
- Splitting toy/test parameter presets from a documented production
  preset (deferred in Workstream 2 pending the noise-management/RNS/
  security-review work above), and true Harvey-style lazy-reduction NTT
  butterflies (deferred in Workstream 3 as further optimization, not a
  correctness gap).
