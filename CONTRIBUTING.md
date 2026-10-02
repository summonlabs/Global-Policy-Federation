# Contributing to Global Policy Federation

Global Policy Federation is Apache-2.0 licensed open source software published by Summon
Software Labs. Contributions are accepted under the terms of the Apache License, Version 2.0
(see [LICENSE](LICENSE)). There is no Contributor License Agreement to sign and no copyright
assignment: by submitting a contribution you confirm you have the right to submit it and you
license it to the project and its users under Apache-2.0.

## Ground rules for this boundary

This repository owns policy federation semantics: propagation, compatibility negotiation,
delegation, conflict containment and local override of facility policy across federated data
centers. It deliberately does not own federation membership, rule authoring for every domain,
or the execution of placement, capacity or recovery effects.

Changes must preserve these properties:

- One thing owned exactly. Neighboring runtimes are consumed through explicit contracts,
  evidence, or authority tokens, never by reaching into their internals.
- No implicit authority. Federation membership alone grants no right to change policy.
- No fabricated authority, capacity, health, compatibility, or success. Unsupported, unknown,
  stale, revoked, conflicting and indeterminate states stay distinct.
- Deterministic behavior: no resolution of authoritative conflict by arrival order, no
  locale-dependent formatting, no unseeded randomness in authoritative paths.
- Bounded everything: workers, queues, retries, payloads, persisted growth, allocations driven
  by untrusted input.
- Checked arithmetic for capacities, counts, generations and sequence numbers.

## Building

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```

Requirements: CMake 3.20 or newer and a C++20 compiler (MSVC 19.3x, GCC 12+, or Clang 15+).
There are no third-party runtime dependencies.

## Tests and quality gates

- Every behavior change needs a test that fails before it and passes after it.
- Tests are never given timeouts, watchdogs, or process-kill-as-pass logic. A hanging test is a
  defect to diagnose, not a condition to mask.
- Randomized tests must be seeded and must print their reproduction data on failure.
- First-party code builds with strict warnings and warnings-as-errors. Do not suppress warnings
  globally; fix the cause. A narrow, commented, compiler-specific suppression is acceptable
  when the alternative is incorrect code.
- Persistence changes must keep the on-disk format versioned, integrity-checked and recoverable,
  and must distinguish a torn tail from interior corruption.

## Commit hygiene

- Commit messages describe the change in neutral engineering language, in the imperative mood.
- Do not include tool directives, prompts, or internal workflow text in commits, code, or docs.
- Do not add `Co-authored-by` trailers, AI attribution, or generated-by notices.
- Do not add telemetry of any kind. This project transmits nothing.

## Reporting problems

Open an issue with the exact command, the observed output, the expected behavior, and the
platform and compiler used. For persistence or recovery defects, include the store layout and
the failing artifact if it can be shared.
