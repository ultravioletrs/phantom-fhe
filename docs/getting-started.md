# Getting Started

This walks through cloning the repository, building it, running the tests and examples, and writing your first program against Phantom-FHE. If you just want the quickest possible taste, the [README quickstart](../README.md#quickstart) has a shorter version of the same thing.

Everything below uses small development parameters, chosen for fast iteration rather than production security margins — see [SECURITY.md](../SECURITY.md) for current cryptographic status.

## Prerequisites

- Rust 1.85 or newer (`rustup update` if you're not sure), matching the `rust-version` pinned in the workspace `Cargo.toml`.
- `make` (optional but recommended — every command below has a `make` shortcut; see [`developer-guide.md#makefile-and-ci`](developer-guide.md#makefile-and-ci)).

No other system dependencies: the workspace's only external crates are `rand_core`, `rand_chacha`, and `thiserror` (see [`internal/dependency-policy.md`](internal/dependency-policy.md)), and `phantom-benches` deliberately avoids even a benchmarking dependency.

## Clone and build

```bash
git clone https://github.com/ultravioletrs/phantom-fhe
cd phantom-fhe
cargo build --workspace --all-targets
```

## Run the tests

```bash
make test          # or: cargo test --workspace --all-targets
```

This runs every crate's integration test suite (see [`developer-guide.md#testing-conventions`](developer-guide.md#testing-conventions) for how they're organized) plus doc-tests. For the complete local check CI also runs — formatting, lint, docs, tests — use:

```bash
make check
```

## Run an example

`phantom-examples` ships one runnable binary per demonstrated workflow:

```bash
cargo run -p phantom-examples --example bfv_basic
```

```text
bfv_basic: -2, 3, 5, -6
```

Run all of them at once with `make examples`, or see the full catalog in [`user-guide.md#runnable-examples`](user-guide.md#runnable-examples).

## Your first program

Create a new binary crate and add Phantom-FHE as a git dependency:

```bash
cargo new bfv-demo && cd bfv-demo
cargo add --git https://github.com/ultravioletrs/phantom-fhe phantom-fhe
cargo add rand_chacha rand_core
```

Replace `src/main.rs` with a BFV encrypt → add → decrypt round trip:

```rust
use phantom_fhe::ring::{Degree, Modulus, Ring};
use phantom_fhe::schemes::bfv::{BfvContext, BfvParams};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A small development ring: degree 8, two tiny moduli.
    // See docs/user-guide.md#choosing-parameters for why these numbers.
    let ring = Ring::new(Degree::new(8)?, vec![Modulus::new(257)?, Modulus::new(769)?])?;
    let ctx = BfvContext::new(BfvParams::new(ring, 17)?); // plaintext modulus t = 17

    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let keys = ctx.keygen()?.generate_keypair(&mut rng)?;
    let encoder = ctx.encoder();
    let evaluator = ctx.evaluator()?;

    let pt_a = encoder.encode_i64(&[1, 2, 3, 4])?;
    let pt_b = encoder.encode_i64(&[10, 20, 30, 40])?;

    let encryptor = ctx.encryptor(keys.public)?;
    let ct_a = encryptor.encrypt(&pt_a, &mut rng)?;
    let ct_b = encryptor.encrypt(&pt_b, &mut rng)?;

    let ct_sum = evaluator.add(&ct_a, &ct_b)?;

    let decryptor = ctx.decryptor(keys.secret)?;
    let decrypted = decryptor.decrypt(&ct_sum)?;
    let result = encoder.decode_i64(&decrypted)?;

    println!("{:?}", &result[..4]); // [11, 22, 33, 40] mod 17 -> [11, 5, 16, 6]
    Ok(())
}
```

```bash
cargo run
```

What happened, in order:

1. `Ring` — a polynomial ring of degree 8 over two small RNS moduli (see [`concepts.md#ring-arithmetic`](concepts.md#ring-arithmetic)).
2. `BfvContext` — the entry point for everything BFV: key generation, encoding, encryption, evaluation, decryption (see [`architecture.md#phantom-schemes`](architecture.md#phantom-schemes)).
3. `keygen()?.generate_keypair(...)` — a secret/public key pair.
4. `encoder.encode_i64(...)` — packs four signed integers into plaintext slots.
5. `encryptor.encrypt(...)` — encrypts under the public key.
6. `evaluator.add(...)` — homomorphic addition, on ciphertexts, without ever decrypting.
7. `decryptor.decrypt(...)` / `encoder.decode_i64(...)` — recovers the (mod-17) sum.

## Where to go next

- **Using more of the library** — every scheme, circuits, bootstrapping, multiparty protocols, serialization: [`user-guide.md`](user-guide.md)
- **Understanding the math** — what RLWE/RGSW/BGV/BFV/CKKS/bootstrapping/multiparty actually are: [`concepts.md`](concepts.md)
- **How the crates fit together** — [`architecture.md`](architecture.md)
- **Contributing** — coding conventions, testing, adding a new scheme: [`developer-guide.md`](developer-guide.md) and [CONTRIBUTING.md](../CONTRIBUTING.md)
- **What's real vs. scaffolded, precisely** — [`technical-manual.md`](technical-manual.md) and [SECURITY.md](../SECURITY.md)
