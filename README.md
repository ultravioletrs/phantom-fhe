# Phantom-FHE

[![CI](https://github.com/ultravioletrs/phantom-fhe/actions/workflows/ci.yml/badge.svg)](https://github.com/ultravioletrs/phantom-fhe/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](Cargo.toml)

`phantom-fhe` is a Rust-native fully homomorphic encryption (FHE) library for modern RLWE-based cryptography: BFV, BGV, CKKS, homomorphic circuits, bootstrapping, and multiparty/threshold protocols, built as an original Rust implementation.

Phantom-FHE is a research-stage implementation under active development (TRL 2–3). The full architecture is implemented and tested end-to-end; cryptographic hardening toward production-grade security is in progress under a tracked roadmap — see [SECURITY.md](SECURITY.md) for current status.

## Contents

- [Scope](#scope)
- [Quickstart](#quickstart)
- [Workspace](#workspace)
- [Status](#status)
- [Documentation](#documentation)
- [Development](#development)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## Scope

- RNS polynomial ring arithmetic
- RLWE and RGSW core primitives
- BFV, BGV, and CKKS schemes
- Homomorphic circuits (linear transforms, polynomial evaluation, comparison/inverse/mod1, DFT)
- Scheme bootstrapping, with CKKS first
- Multiparty / threshold protocols
- Runnable examples and smoke benchmarks

## Quickstart

Phantom-FHE is not yet published to crates.io. Depend on it directly from git:

```toml
[dependencies]
phantom-fhe = { git = "https://github.com/ultravioletrs/phantom-fhe" }
```

```rust
use phantom_fhe::ring::{Degree, Modulus, Ring};
use phantom_fhe::schemes::bfv::{BfvContext, BfvParams};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Development parameters, chosen for fast iteration - see docs/user-guide.md#choosing-parameters.
    let ring = Ring::new(Degree::new(8)?, vec![Modulus::new(257)?])?;
    let ctx = BfvContext::new(BfvParams::new(ring, 17)?);
    let mut rng = ChaCha20Rng::from_seed([7; 32]);

    let keys = ctx.keygen()?.generate_keypair(&mut rng)?;
    let encoder = ctx.encoder();
    let plaintext = encoder.encode_i64(&[-2, 3, 5, -6])?;
    let ciphertext = ctx.encryptor(keys.public)?.encrypt(&plaintext, &mut rng)?;
    let decrypted = ctx.decryptor(keys.secret)?.decrypt(&ciphertext)?;

    assert_eq!(&encoder.decode_i64(&decrypted)?[..4], &[-2, 3, 5, -6]);
    Ok(())
}
```

More workflows (BGV, CKKS, bootstrapping, multiparty) are runnable from [`crates/phantom-examples/examples`](crates/phantom-examples/examples) — see [Development](#development). For a walked-through first program and every scheme's usage, start with [`docs/getting-started.md`](docs/getting-started.md).

## Workspace

| Crate | Description |
| --- | --- |
| [`phantom-fhe`](crates/phantom-fhe) | Top-level facade; re-exports the crates below as `ring`, `lattice`, `schemes`, `circuits`, `bootstrapping`, `multiparty`, and `utils` |
| [`phantom-utils`](crates/phantom-utils) | Minimal cross-cutting support utilities |
| [`phantom-ring`](crates/phantom-ring) | RNS polynomial ring arithmetic |
| [`phantom-lattice`](crates/phantom-lattice) | Scheme-agnostic RLWE and RGSW primitives |
| [`phantom-schemes`](crates/phantom-schemes) | Concrete BGV, BFV, and CKKS scheme APIs |
| [`phantom-circuits`](crates/phantom-circuits) | Shared circuit planning plus scheme-specific circuit implementations |
| [`phantom-bootstrapping`](crates/phantom-bootstrapping) | CKKS bootstrapping pipeline plus reserved BGV/BFV module locations |
| [`phantom-multiparty`](crates/phantom-multiparty) | Threshold protocol implementations (mpBGV, mpBFV, mpCKKS) |
| [`phantom-examples`](crates/phantom-examples) | Runnable example workflows and binaries (workspace-only) |
| [`phantom-benches`](crates/phantom-benches) | Criterion benchmarks for current hot paths (workspace-only) |

`phantom-examples` and `phantom-benches` are workspace-only (`publish = false`): they exercise the individual `phantom-*` crates directly, and the facade crate has its own smoke test ([`crates/phantom-fhe/tests/facade.rs`](crates/phantom-fhe/tests/facade.rs)) confirming its re-exports resolve to working APIs.

## Status

All 18 roadmap phases are implemented — every crate above compiles, is tested, and its examples run end-to-end. The project is now executing an **Alpha Hardening** plan to progress cryptographic hardness toward production strength: release infrastructure and API/documentation clarity are complete, and remaining work is tracked as a sequence of workstreams — ring hardening, production RLWE/RGSW, production BFV/BGV/CKKS, bootstrapping/circuits hardening, and multiparty protocol security. See [SECURITY.md](SECURITY.md) for current cryptographic status.

The full phase-by-phase and workstream-by-workstream detail lives in [`docs/internal/implementation-plan.md`](docs/internal/implementation-plan.md).

## Documentation

The full documentation set lives under [`docs/`](docs) — see [`docs/README.md`](docs/README.md) for the index. Highlights:

- [`docs/getting-started.md`](docs/getting-started.md) — clone, build, run the examples, your first program
- [`docs/user-guide.md`](docs/user-guide.md) — using every scheme, circuits, bootstrapping, and multiparty protocols, with runnable code
- [`docs/concepts.md`](docs/concepts.md) — the cryptography and math behind the library
- [`docs/architecture.md`](docs/architecture.md) — crate layout, dependency hierarchy, design conventions
- [`docs/developer-guide.md`](docs/developer-guide.md) — coding/testing conventions, adding a new scheme
- [`docs/technical-manual.md`](docs/technical-manual.md) — the precise, code-level reference: exactly what's real vs. scaffolded, wire formats, error taxonomy, performance
- [`docs/internal/`](docs/internal) — maintainer-facing: PRD, technical spec, implementation plan, dependency policy, release checklist

Rustdoc for every crate is generated with `make doc` (see below).

## Development

```bash
make help    # list all targets
make check   # fmt-check + clippy + test + doc, same as CI
make test    # cargo test --workspace --all-targets
make examples  # run every phantom-examples binary
make bench   # run the phantom-benches smoke benchmarks
make ci      # check + bench, the full local command matrix
```

See [`Makefile`](Makefile) for the underlying `cargo` invocations, and [CONTRIBUTING.md](CONTRIBUTING.md) for testing conventions and PR scope.

## Security

Phantom-FHE is under active cryptographic hardening. See [SECURITY.md](SECURITY.md) for current per-crate status, the hardening roadmap, and vulnerability reporting guidance.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [`docs/developer-guide.md`](docs/developer-guide.md) for local checks, coding/testing conventions, and authorship rules, and [`docs/internal/dependency-policy.md`](docs/internal/dependency-policy.md) before adding a dependency.

This repository should contain original Rust source authored for Phantom-FHE. Public papers and mature open-source FHE libraries may be used for understanding algorithms, terminology, parameters, and validation behavior, but source code, tests, examples, documentation, and serialization formats here must be authored for this repository — do not copy or mechanically translate third-party implementation code.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
