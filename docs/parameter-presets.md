# Parameter Presets

The current repository uses toy presets for examples, tests, and benchmark scaffolds. They are intentionally tiny so every workflow runs quickly in CI and during local development.

## Toy Exact Schemes

BFV and BGV examples use:

- polynomial degree: `8`
- ciphertext moduli: `257`, `769`
- plaintext modulus: `17`

These settings are for API and correctness demonstrations only. They are not cryptographically secure.

## Toy CKKS

CKKS examples use:

- polynomial degree: `8`
- ciphertext moduli: `257`, `769`, `3329`
- default scale: `2^10`
- conjugate-invariant mode: off unless an example explicitly enables it

CKKS bootstrapping examples use the same CKKS parameters with the current scaffold bootstrapping defaults.

## Release Path

Before alpha release, promote these presets into named APIs only if the names make their security status clear. Production presets should not be added until noise analysis, parameter validation, and security documentation are ready.
