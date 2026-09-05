# Developer Guide

Conventions and workflow for contributing to Phantom-FHE: coding patterns, testing conventions, the serialization pattern to follow for new wire types, and a walkthrough for adding a new scheme/circuit. For local commands, PR scope, and authorship rules, start with [CONTRIBUTING.md](../CONTRIBUTING.md) — this document goes deeper into *why* the code is shaped the way it is, so new code fits the existing patterns.

## Repository layout

```text
phantom-fhe/
  Cargo.toml              workspace manifest + shared [workspace.dependencies]
  Makefile                make check / make test / make ci / ...
  .github/workflows/ci.yml
  crates/                 all workspace crates (see architecture.md)
  docs/                   this documentation set
  docs/internal/          PRD, technical spec, implementation plan, dependency policy, release checklist
```

Every crate under `crates/` follows the same manifest shape: `[package]` pulls `edition`/`license`/`repository`/`rust-version` from `[workspace.package]`, and shared external dependency versions come from `[workspace.dependencies]` in the root `Cargo.toml` — never pin a version directly in a crate manifest if the workspace already declares it.

See [`architecture.md`](architecture.md#crate-dependency-graph) for the dependency hierarchy every crate must respect: a crate may only depend on crates at or below its layer, never sideways or up.

## Coding conventions

- **One error enum per crate.** `#[derive(thiserror::Error)]`, exported alongside a `pub type Result<T> = core::result::Result<T, XxxError>;` from the crate root. Wrap lower-layer errors with `#[from]` (or `#[error(transparent)]` for pure wrapping) rather than converting them to strings — see the full catalog in [`technical-manual.md#error-reference`](technical-manual.md#error-reference) for the shape every existing crate follows.
- **Builder + direct constructor for parameters.** Every `*Params` type has both a `new(...)` that validates its arguments directly and a `builder()` returning a `*ParamsBuilder` whose `build()` validates the assembled whole. Follow this shape for new parameter types — don't add a builder that skips validation, and don't add a `new()` that's laxer than the builder's `build()`.
- **Strong domain types at API boundaries.** Don't add a new public function taking a bare `usize`/`u64`/`f64` where a validated type (`Degree`, `Modulus`, `Scale`, `ParticipantId`, ...) already exists for that concept; if a new concept needs validation, wrap it in a small newtype rather than validating ad hoc at every call site.
- **`const fn` where possible.** Trivial getters/constructors that don't allocate or validate are marked `const fn` throughout the codebase (e.g. `Modulus::value`, `Ring::degree`, `SecretKey::value`). Keep doing this for new trivial accessors.
- **Redact secrets.** Any new secret-bearing type should get a manual `Debug` impl that redacts its contents (see `phantom_lattice::rlwe::SecretKey`) and a `Drop` impl that zeroes its backing storage, following that same type as the reference pattern — until the dependency policy's `zeroize` question (see [`internal/dependency-policy.md`](internal/dependency-policy.md)) is revisited.
- **Comment for *why*, not *what*.** The existing doc comments are almost entirely one-line `///` summaries naming what a function returns/does; multi-paragraph explanations belong in these docs, not inline. When a scaffold is intentionally non-production (transparent encryption, placeholder sampling, identity operations), say so directly in the doc comment — see `RgswCiphertext`, `BootstrapParams`... for the existing tone to match, and update [`technical-manual.md`](technical-manual.md) alongside any change to what's real vs. scaffolded.

## Testing conventions

- **Integration tests live in `crates/<crate>/tests/`, one file per implementation phase**, named `phaseNN_<topic>.rs` matching the phase numbering in [`internal/implementation-plan.md`](internal/implementation-plan.md) (e.g. `phase5_bgv.rs`, `phase17_serialization.rs`). When you add coverage for an existing phase's area, add to that file; a genuinely new area gets a new `phaseNN_*.rs` file matching its plan entry.
- **Deterministic RNGs everywhere.** Tests and examples never use OS randomness — they build a `ChaCha20Rng` from a fixed 32-byte seed (`ChaCha20Rng::from_seed([N; 32])`, or `phantom_utils::test::deterministic_rng`/`zero_seed_rng` where available). This keeps test failures reproducible. Follow the same pattern for new tests.
- **Local test-only params/rng helper functions** (`fn params() -> BgvParams { ... }`, `fn seeded_rng() -> ChaCha20Rng { ... }`) at the top of each test file, built on the development presets in [`user-guide.md#choosing-parameters`](user-guide.md#choosing-parameters). Don't reach for a shared test-fixture crate; the duplication across test files is intentional and keeps each file self-contained.
- **`phantom-utils`'s `test-utils` feature** gates its `deterministic_rng`/`zero_seed_rng` helpers for use as a dev-dependency from other crates; it's otherwise always available under `cfg(test)` within `phantom-utils` itself.
- **Serialization tests always cover five cases** (Workstream 8): a successful round trip, a golden-byte fixture (a previously-generated encoding pinned in the test, asserted in both directions - catches wire-shape drift a round trip alone can't), rejection of a wrong-domain payload, rejection of a wrong-version payload, rejection of a truncated payload, and a `proptest` property that decoding arbitrary bytes never panics. See [`internal/serialization-compatibility-policy.md`](internal/serialization-compatibility-policy.md) for the full policy and [Adding a new serialized type](#adding-a-new-serialized-type) below.
- **`phantom-examples`'s `tests/examples_run.rs`** exercises every example workflow function as a test (not just as a runnable binary), so a broken example fails `cargo test`, not just `cargo run`.
- Property-based testing (`proptest`) is pre-approved as a dev-dependency (see [`internal/dependency-policy.md`](internal/dependency-policy.md)) and adopted workspace-wide as of Workstream 8: `phantom-ring`/`phantom-lattice` use it for arithmetic/algebraic properties (`tests/property_tests.rs`, `tests/randomized.rs`), `phantom-circuits` for its scheme-independent planning logic, and every `SerializationHeader`-based crate plus `phantom-multiparty` for decode-never-panics coverage.

Run the full suite with `make test` (`cargo test --workspace --all-targets`), or `make check` to also run fmt/clippy/doc — the same commands CI runs. See [Makefile and CI](#makefile-and-ci) below.

## Adding a new serialized type

Follow the exact pattern in any existing `serialization.rs` (`phantom-lattice`, `phantom-schemes`, `phantom-circuits::common`, `phantom-bootstrapping`):

1. Pick an 8-byte ASCII domain tag not already in the catalog ([`technical-manual.md#domain-tag-catalog`](technical-manual.md#domain-tag-catalog) has every tag in use) — the existing convention is an abbreviation of the type name padded with a two-digit version suffix, e.g. `b"BGVCTXT1"`.
2. Add `const XXX_DOMAIN: DomainTag = DomainTag::from_array(*b"XXXXXXXX");` alongside the crate's existing `VERSION: Version` constant (reuse the crate's existing version unless you're intentionally starting a new format).
3. Write `encode_xxx`/`decode_xxx` using the crate-local `writer`/`reader` helpers (which wrap `SerializationHeader::write_to`/`read_expected`) and `BufferWriter`/`BufferReader`'s primitive methods — never write raw bytes without going through these.
4. Add the five-case test set described [above](#testing-conventions).
5. Add a row to the domain-tag table in [`technical-manual.md`](technical-manual.md#domain-tag-catalog) — that table is the canonical cross-crate catalog and must stay in sync with the source.

Never serialize a secret-bearing type (`SecretKey`, RGSW key material, a multiparty participant's own local secret share) without a deliberate security review — see [`internal/serialization-compatibility-policy.md`](internal/serialization-compatibility-policy.md) for the standing policy this enforces and its one documented exception (`vss::VssShare`).

## Adding a new scheme or circuit

There's no scheme/circuit trait to implement against yet — the convention is structural, established by BGV/BFV/CKKS and their circuit modules. To add a new scheme (or a new circuit family for an existing scheme):

1. **Params**: a `XxxParams` wrapping a `phantom_ring::Ring` (plus scheme-specific fields), with `new(...)` validating directly and a `XxxParamsBuilder`. Look at `bgv::BgvParams` for the minimal shape, `ckks::CkksParams` for one with more fields.
2. **Plaintext/Ciphertext**: thin wrappers — either directly over `phantom_ring::Poly` (as CKKS's transparent slots are) or over `phantom_lattice::rlwe::{Plaintext, Ciphertext}` (as BGV/BFV are). Prefer wrapping the RLWE types unless you have a specific reason not to (CKKS's departure from that pattern is because its "ciphertext" is currently transparent floating-point data with metadata, not an RLWE ciphertext at all — see [`technical-manual.md#ckks`](technical-manual.md#ckks)).
3. **Encoder**: `encode_*`/`decode_*` methods translating your plaintext domain (integers, reals, whatever your scheme represents) into/out of the `Plaintext` type.
4. **KeyGenerator**: wraps `phantom_lattice::rlwe::KeyGenerator`, producing a `XxxKeyPair` and `EvaluationKeys`.
5. **Encryptor/Decryptor**: wraps the corresponding `phantom_lattice::rlwe` type, or implements the scheme's own logic if it can't reuse RLWE encryption directly.
6. **Evaluator**: `add`/`sub`/`neg`/`add_plain`/`mul`/`mul_plain` at minimum, following the exact method names and signatures used by `bgv::Evaluator`/`ckks::Evaluator` so downstream code (circuits, examples) can stay structurally similar across schemes.
7. **Context**: the single entry point (`XxxContext::new(params)`) with `encoder()`/`keygen()`/`encryptor()`/`secret_key_encryptor()`/`decryptor()`/`evaluator()` methods constructing the pieces above from shared params — this is what user-facing code actually touches (see every example in [`user-guide.md`](user-guide.md)).
8. **`mod.rs`**: re-export every public type from the module root, matching `bgv::mod`'s flat `pub use` list.
9. **Tests**: a `phaseNN_<scheme>.rs` integration test file covering encode/decode, encrypt/decrypt round trip, and every evaluator operation — mirror `phase5_bgv.rs`.
10. **Serialization**: add `encode_xxx_params`/`_plaintext`/`_ciphertext` to the crate's `serialization.rs` following [Adding a new serialized type](#adding-a-new-serialized-type).
11. **Example**: add one `phantom-examples/examples/xxx_basic.rs` calling into a new `pub fn xxx_basic() -> Result<ExampleOutput, ExampleError>` in `phantom-examples/src/workflows.rs`, following the existing functions there (a `params()`-style local helper building a small development `Ring`/params, then keygen → encode → encrypt → evaluate → decrypt → decode → `ExampleOutput::new`).

For a circuit family instead of a whole scheme: follow `phantom_circuits::bgv`/`ckks`'s shape — a `LinearTransformEvaluator`/`PolynomialEvaluator` (or a new evaluator type) taking the scheme's `Params` in its constructor and operating on the scheme's `Ciphertext` type, built on `phantom_circuits::common`'s scheme-independent planning types (`LinearTransform`, `DiagonalMatrix`, `BabyStepGiantStepPlan`, `PolynomialEvalPlan`) rather than reimplementing diagonal-method or BSGS planning locally.

## Performance work

See [`technical-manual.md#performance`](technical-manual.md#performance) for the precise current state (a real O(N log N) NTT wired into `Ring::mul`, which every real call site above `phantom-ring` now uses in place of the always-O(N²) `Ring::schoolbook_mul`; Criterion-based benchmarking as of Workstream 9). In short: don't optimize prematurely — the current priority order (per [`internal/implementation-plan.md`](internal/implementation-plan.md) Workstream 3) is lazy/deferred reduction and allocation-reduction passes before micro-tuning, since those are the changes that actually move the needle at production ring sizes.

If you're adding a benchmark target: follow the shape in `crates/phantom-benches/benches/` (a `criterion_group!`/`criterion_main!` pair using the shared `support::criterion_config()` from `benches/support/mod.rs` — a ring/RLWE-level primitive gets a `toy`/`small` `BenchmarkGroup` like `ring_ntt.rs`; a scheme/evaluator-level bench stays single-tier with a `#[global_allocator]`-backed allocation diagnostic like `bfv_eval.rs`), add the corresponding `[[bench]] name = "..." harness = false` entry to `phantom-benches/Cargo.toml`, and run it with `cargo bench -p phantom-benches --bench <name>` or `make bench` for the full set.

## Makefile and CI

`make help` lists every target; the ones you'll use most:

- `make check` — `fmt-check` + `clippy` + `test` + `doc`, exactly what CI's four separate jobs run (see `.github/workflows/ci.yml`).
- `make ci` — `check` plus `bench`, the full local command matrix.
- `make examples` — runs every `phantom-examples` binary in sequence.

CI (`.github/workflows/ci.yml`) runs `fmt`, `test`, `clippy`, `doc`, and `bench-smoke` as separate parallel jobs on every push/PR to `main` — deliberately split rather than one combined job, so a failure names exactly which check broke. `RUSTDOCFLAGS=-D warnings` is set for the `doc` job, so a broken doc link or invalid intra-doc reference fails CI, not just `cargo doc`'s local output.

## Where the roadmap lives

Day-to-day "what's next" tracking is [`internal/implementation-plan.md`](internal/implementation-plan.md) — phase-by-phase for the original build-out (all complete), then workstream-by-workstream for the current Alpha Hardening pass. If you're picking up new work, check there first for owned areas and exit criteria before starting; PRs should stay scoped to one workstream/phase where possible (see [CONTRIBUTING.md](../CONTRIBUTING.md#scope-of-changes)).
