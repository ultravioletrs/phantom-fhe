# Internal Docs

These documents drive day-to-day development and release decisions rather than describing the public API. They are part of this public repository (nothing here is secret), but they are written for maintainers/contributors, not library consumers.

- [`phantom-fhe-prd.md`](phantom-fhe-prd.md) — product requirements
- [`technical-spec.md`](technical-spec.md) — compact architecture and design roadmap
- [`implementation-plan.md`](implementation-plan.md) — authoritative, phase-by-phase and workstream-by-workstream coding plan; source of truth for "what's next"
- [`dependency-policy.md`](dependency-policy.md) — what dependencies are allowed where, and why
- [`serialization-compatibility-policy.md`](serialization-compatibility-policy.md) — domain tags vs. versions, what every serialized type must be tested for, and why secret-bearing types stay unserializable by default
- [`release-checklist.md`](release-checklist.md) — the Alpha/Beta/Stable release gates

User-facing documentation (getting started, architecture, concepts, user guide, developer guide, technical manual) lives one level up in [`docs/`](..) — see [`docs/README.md`](../README.md) for the index.
