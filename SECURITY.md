# Security Policy

## Current Status

Phantom-FHE is a research-stage implementation, roughly **TRL 2–3** (technology concept formulated; experimental proof of concept). The full architecture — ring arithmetic, RLWE/RGSW primitives, BGV/BFV/CKKS schemes, homomorphic circuits, CKKS bootstrapping, and multiparty threshold protocols — is implemented, tested end-to-end, and documented (see `docs/technical-manual.md` for the precise per-operation reference). Cryptographic hardening toward production strength is in progress under a tracked roadmap (`docs/internal/implementation-plan.md`).

The following components are not yet at production cryptographic strength:

- `phantom-ring::sampling::sample_discrete_gaussian` is a real discrete
  Gaussian (CDT-based) but is not constant-time.
- `phantom-lattice::rlwe` now samples real Gaussian encryption error
  (`phantom_lattice::security::STANDARD_ERROR_STD_DEV`, the
  homomorphicencryption.org community-standard σ≈3.2) into both key
  generation and encryption, with worst-case noise-growth bounds in
  `phantom_lattice::noise`. `phantom_lattice::rlwe::{generate_key_switch_key,
  key_switch}` are now a real RNS hybrid key-switch (the modern
  RNS-CKKS-era technique, not a textbook simplification), and both
  `Evaluator::relinearize` (given `KeyGenerator::generate_hybrid_relinearization_key`)
  and `Evaluator::apply_galois_automorphism` (given
  `KeyGenerator::generate_hybrid_galois_key`) do real work when given a real
  key - but every scheme crate above `phantom-lattice` (BGV, BFV, CKKS,
  multiparty) still only constructs the identity-preserving placeholder keys
  (`RelinearizationKey::placeholder()`, `GaloisKey::new`), since none of
  them yet have a concept of the auxiliary `P` moduli a real key needs, so
  both operations still behave as a no-op in practice for every scheme
  (`Evaluator::rotate_coefficients`, the raw-coefficient placeholder BGV's
  evaluator still calls directly, is unaffected). Noise tracking itself is a
  sound-but-loose worst-case bound, not a tight probabilistic one, and
  key-switching's own noise contribution doesn't yet have a
  formally-derived bound (only an empirically-set test threshold).
- `phantom-lattice::rgsw` now encrypts real gadget matrices (the standard
  GSW/RGSW construction) instead of the earlier plaintext-backed scaffold,
  with a real external product and its own noise bound in
  `phantom_lattice::noise::external_product_noise_bound` - but RGSW
  ciphertexts aren't yet consumed anywhere (no bootstrapping construction
  built on top), and, like the rest of `phantom-lattice::rlwe`, its noise
  tracking is a sound-but-loose worst-case bound.
- `phantom-schemes::bgv` and `phantom-schemes::bfv` each now have a real,
  noise-bearing encryption path
  (`Encryptor::with_secret_key_real`/`with_public_key_real`) alongside
  their original transparent one - every existing caller
  (`phantom-circuits`, `phantom-bootstrapping`, `phantom-multiparty`) still
  only constructs the transparent (non-encrypted) path, since their toy
  ring parameters have no headroom for real noise and haven't been
  migrated yet; `phantom-examples` additionally has two dedicated
  real-path workflows (`bgv_real_basic`/`bfv_real_basic`) at
  realistically-sized parameters, kept separate from its toy-preset
  examples rather than a migration of them. BGV's real path needs
  noise scaled by the plaintext modulus `t` and a matching real public key
  (`BgvKeyGenerator::generate_keypair_real`); BFV's real path scales the
  *message* by `Delta = floor(Q/t)` instead and reuses a standard public
  key unchanged - genuinely different math, not a relabeling (the
  pre-existing "BFV" scheme, before this, was actually just BGV's own
  exact scheme reused directly, with no Δ-scaling anywhere). Real BGV
  relinearization isn't wired up either (would need the key-switching
  key's own noise scaled by the plaintext modulus too, not just fresh
  encryption's). BFV now also has real multiplication
  (`Evaluator::mul_real`, alongside encrypt/decrypt and ciphertext-ciphertext
  add/sub/neg) - a full tensor-and-rescale procedure computed in an
  auxiliary basis large enough to avoid wraparound, using new general
  bignum/bignum division (`phantom_ring::bignum::BigUint::divmod`) for the
  rescale step's rounding. BFV's plaintext operations are also both real
  now: new `Evaluator::add_plain_real` scales its plaintext operand by
  `Delta` first (needed, since `add_plain`'s raw-add behavior is wrong for a
  real ciphertext), while `mul_plain` needed no separate real path at all -
  multiplying by a small unscaled plaintext doesn't have addition's
  problem, verified numerically. BFV can now also relinearize
  `mul_real`'s degree-2 output back to degree 1
  (`Evaluator::relinearize_real`, `BfvKeyGenerator::generate_hybrid_relinearization_key`)
  - a direct reuse of `phantom_lattice::rlwe`'s existing real key-switching
  machinery, safe for BFV since it has no `t`-scaled-noise requirement.
  **BGV's own relinearization is real now too**
  (`Evaluator::relinearize_real`, `BgvKeyGenerator::generate_relinearization_key_real`),
  but needed a genuinely different construction from BFV's: BFV's
  key-switching key would be unsafe for BGV's own real ciphertexts (its
  noise isn't a multiple of `t`, so using it - or even a version with its
  noise naively scaled by `t` - silently corrupts BGV's mod-`t` invariant,
  verified numerically before ruling it out). BGV's relinearization key
  (`phantom-schemes::bgv::relinearization::BgvRelinearizationKey`) instead
  uses classical (power-of-base) gadget decomposition, which has no
  division/rounding step to corrupt `t`-scaled noise the way the RNS hybrid
  technique's `mod_down` does - verified to recover the exact product (not
  just within a noise bound) across 30 randomized trials. BGV also has a
  real RNS modulus-switching path now (`ModulusSwitcher::switch_next_real`,
  alongside the original clone-only `switch_next`), with the same
  not-yet-migrated caller situation as everything else here.
- `phantom-schemes::ckks` still has its original approximate encoding
  (`Encoder::encode_complex`/`decode_complex`) and transparent
  `Ciphertext`/`Encryptor`/`Decryptor` as its default path - the actual
  slot values are still carried in the clear - but its `Precision`
  bookkeeping is now derived from real noise analysis (new `ckks::noise`,
  the same triangle-inequality style `phantom_lattice::noise` already uses
  for BGV/BFV/RGSW, adapted to CKKS's canonical-embedding/scale setting)
  rather than the flat illustrative constants (`degrade(0.25)`,
  `degrade(1.0)`) every `Evaluator` operation used before - see
  `ckks::noise`'s own module doc comment for the per-operation formulas
  and what's deliberately still left unmodeled (relinearization's and
  Galois key-switching's own noise contribution, since
  `phantom_lattice::rlwe`'s hybrid key-switching doesn't have a
  formally-derived noise bound of its own yet either - the same gap noted
  above for BGV/BFV). `phantom-schemes::ckks` also now has a full real
  ciphertext/encryption/arithmetic path alongside the transparent one:
  `Encoder::encode_complex_real`/`decode_complex_real`
  round-trip slots through a `phantom_ring::Poly` rather than carrying them
  in the clear (`Plaintext`'s `Option`-typed `poly` field), and
  `Ciphertext` gained the same kind of `Option`-typed real RLWE
  representation. `Encryptor::encrypt_real`/`Decryptor::decrypt_real` do
  genuine RLWE encryption/decryption (structurally BFV's own real path,
  since CKKS's message is already `Delta`-scaled by the encoder rather than
  needing per-operation scaling), and `Evaluator::{add,sub,neg,add_plain,mul,relinearize,rescale_next}_real`
  do genuine ring arithmetic - `add`/`sub`/`neg`/`add_plain`/`mul` (raw
  tensor, no relinearization) are direct pass-throughs to
  `phantom_lattice::rlwe::Evaluator`, `relinearize_real` reuses the same
  real hybrid key-switching machinery BFV's relinearization does, and
  `rescale_next_real` drops the ciphertext's last RNS component via the
  existing `phantom_ring::rns::rescale::mod_down` primitive and divides the
  tracked `Scale` to match - CKKS has no plaintext-modulus invariant to
  protect the way BGV's own rescale does, so a plain floor division
  suffices. Real CKKS multiplication needs no BFV-style extended-basis
  tensor-and-rescale procedure: its mod-`Q` tensor product is already
  exactly what the *next*, separate rescale step needs. This real path
  isn't wired into `phantom-circuits`/`phantom-bootstrapping`/`phantom-multiparty`
  yet, the same not-yet-migrated situation as BGV/BFV's own real paths
  above; `phantom-examples` additionally has a dedicated real-path
  workflow (`ckks_real_basic`), the same as BGV/BFV's own two. Conjugate-
  invariant real packing and an NTT/FFT fast path for encode/decode remain
  unimplemented.
- `phantom-bootstrapping::ckks` is a message-preserving pipeline, not yet a
  production refresh pipeline. BGV/BFV bootstrapping modules are reserved
  but unimplemented.
- `phantom-multiparty` protocols have not had an adversarial security
  review. Collective key generation, relinearization-key generation, and
  Galois-key generation currently aggregate shares into placeholder key
  material (e.g. an all-zero public key) rather than real cryptographic key
  material, and the transcript hash used for protocol transcripts
  (`phantom_multiparty::common::transcript::stable_hash_256`) is a small
  hand-rolled mixer, not a vetted cryptographic hash function.
- All example and test parameter presets (see
  `docs/user-guide.md#choosing-parameters`) are small development sizes
  chosen for fast iteration, not production security margins.

For the precise, per-operation account of what each of the above means in
code, see `docs/technical-manual.md`. This status is expected to change
substantially as the hardening roadmap executes; **this implementation
should not be relied on for production security until these items are
resolved.**

## Reporting a Vulnerability

Because the project has not yet reached a security-reviewed state, most
cryptographic weaknesses are already known and tracked in
`docs/internal/implementation-plan.md` rather than being reportable surprises. Still, if
you find:

- a memory-safety or panic-safety issue reachable from public APIs,
- a logic bug that breaks correctness guarantees the current implementation
  does claim (for example, a documented round-trip or test that can be
  broken with valid inputs), or
- a supply-chain or build-process concern,

please open a GitHub issue with a minimal reproduction. If the issue is
sensitive (for example, it affects a downstream consumer who has already
deployed a preset from this repository), contact the maintainer directly
instead of filing a public issue.

## Scope Boundary

Reports about the *absence* of production hardening that is already listed
in `docs/internal/implementation-plan.md` (real noise management, optimized NTT/RNS,
secure parameter sets, protocol security review, etc.) are welcome as
general feedback but are not treated as new vulnerabilities - they are
tracked, expected gaps at this stage of the project.
