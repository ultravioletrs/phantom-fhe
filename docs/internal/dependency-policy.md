# Dependency Policy

## Goals

Keep the core cryptographic crates small, auditable, and fast to build.
Every new dependency in a core crate is a piece of the trusted computing
base for anyone who later relies on this library for real secrets, so
additions should be deliberate.

## Core crates

`phantom-utils`, `phantom-ring`, `phantom-lattice`, `phantom-schemes`,
`phantom-circuits`, `phantom-bootstrapping`, `phantom-multiparty`, and the
`phantom-fhe` facade.

Allowed today:

- `rand_core` - RNG trait surface, no-default-features where possible.
- `rand_chacha` - the only concrete RNG the workspace ships; deterministic
  and audit-friendly. `phantom-utils` gates it behind `std`/`test-utils`
  rather than requiring it unconditionally.
- `thiserror` - error-type ergonomics; does not affect the public API shape
  beyond `std::error::Error` implementations.
- `sha2` (`default-features = false`) - `phantom-multiparty` only, for
  `common::transcript::stable_hash_256`. Replaces a hand-rolled,
  no-cryptanalysis mixer that `SECURITY.md` and `docs/technical-manual.md`
  both flagged as unsuitable for anything relying on collision or preimage
  resistance (Workstream 7 item 3). RustCrypto's `sha2`: pure Rust, MIT/Apache-2.0,
  the same license terms already in use elsewhere in this workspace, `rust-version`
  matching the workspace's own `1.85`. `default-features = false` drops the
  `alloc`/`oid` features (this crate only ever calls `Sha256::digest` on a
  borrowed slice into a fixed `[u8; 32]`, no allocation or ASN.1 OID encoding
  needed) - pulls in `digest`, `block-buffer`, `crypto-common`,
  `hybrid-array`, `typenum`, and `cpufeatures` transitively, all from the
  same RustCrypto organization already vetted for this addition.

Not currently a dependency of any core crate, with a standing decision
below:

- `serde` - a `serde` feature flag already exists on `phantom-utils` (and is
  plumbed through the `phantom-fhe` facade) but adds no dependency yet.
  When it is wired up, it must stay optional and off by default, and
  secret-bearing types (`SecretKey`, RLWE/RGSW key material, multiparty
  shares) must **not** derive `Serialize`/`Deserialize` even when the
  feature is enabled - use the workspace's own versioned binary encodings
  in each crate's `serialization.rs` for anything secret-adjacent.
- `zeroize` - not used. Secret-bearing types currently implement `Drop`
  manually (see `phantom-lattice::rlwe::secret_key::SecretKey`). Adopting
  `zeroize` is worth revisiting during Workstream 4 (production RLWE/RGSW)
  if manual `Drop` impls become inconsistent or hard to audit, but it is
  not required to add the dependency preemptively.
- `rayon` - not used. Parallelism is out of scope until the CPU backend
  (Workstream 3/9) has a single-threaded performance baseline to compare
  against. Add it only alongside benchmark evidence that it helps a real
  hot path, and keep it feature-gated (`parallel`) rather than default-on,
  since it pulls in a thread pool that not every embedder wants.

## Dev/test-only dependencies

Allowed in `[dev-dependencies]` of any crate, and in the `phantom-examples`
and `phantom-benches` packages (which are `publish = false` and are not
part of the trusted core surface):

- `rand_chacha` - deterministic seeded RNGs for tests and examples.
- `proptest` - a dev-dependency of `phantom-ring` (`tests/property_tests.rs`,
  Workstream 3 item 1) for property-based tests. Still pre-approved for the
  same use in other crates (Workstream 8) as it's picked up there. Must
  never appear in a non-dev dependency list.

## Benchmarks

`phantom-benches` currently uses dependency-free `std::time::Instant` smoke
timing (see `docs/technical-manual.md#performance`) so it runs without extra setup.
Criterion is pre-approved for adoption once Workstream 9 is picked up, as a
dev-dependency of `phantom-benches` only:

```toml
[dev-dependencies]
criterion = { version = "...", default-features = false }
```

Criterion must not become a dependency of any core crate.

## Adding a new dependency

1. Prefer the standard library or an existing workspace dependency first.
2. If a new dependency is needed in a core crate, open a PR that:
   - names the exact crate, version, and feature set requested,
   - explains why the standard library or an existing dependency is not
     enough,
   - states whether it is default-on or feature-gated, and
   - updates this file's "Allowed today" list.
3. Dev-only and example/bench-only dependencies are lower risk but should
   still be added deliberately, not accumulated incidentally.
4. Pin dependencies via `[workspace.dependencies]` in the root `Cargo.toml`
   so every crate resolves the same version.
