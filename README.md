# Global Policy Federation

Global Policy Federation is the Data Center Control Plane boundary that governs how facility policy
is **distributed across autonomous sites**: how global intent is propagated, negotiated for
compatibility, delegated, contained when it conflicts, and overridden locally without either
silently inventing authority or silently discarding it.

It is a C++20 library plus three real executables, built with CMake, with no third-party runtime
dependencies, no telemetry, and Apache-2.0 licensing.

## What this boundary owns, and what it does not

It owns **policy federation semantics**: policy bundle identity and integrity, global and local
policy generations, federation and member scope, rule identity and semantic versioning, capability
prerequisites, mandatory/default/advisory classification, local-override permission and delegated
override authority, conflict domains and conflict containment, effective-policy compilation with
explanation, the receipt trail, partition behavior, reconnection reconciliation, and durable
storage of all of it.

It does **not**:

- replace a site's Facility Policy Engine, which remains the runtime that acts on policy;
- define every rule, or own rule authoring for a domain;
- own federation membership (membership is consumed as explicit neighboring truth);
- execute placement, capacity, power, cooling or recovery effects;
- accept a reference to ASI or DFI as permission to reach into another runtime's internals.

The architectural invariant is: **own one thing exactly, consume neighboring truth explicitly,
never infer another runtime's authority, never absorb another boundary merely because integration
exists.** Concretely, in this codebase:

- Federation membership grants nothing. Every right is a granted, scoped, revocable delegation.
- A site never invents a global generation. While disconnected, the newest global generation stays
  exactly what was last accepted.
- Capability *unknown* and capability *unsupported* are different answers, and so are *stale* and
  *revoked*, *absent* and *conflicted*, *incompatible* and *unavailable*.

## The core question, answered

> How can policy be distributed across autonomous sites so global intent is enforceable where
> delegated, local sovereignty remains explicit, incompatible rules are contained, and
> partitions or stale generations cannot silently change authority?

- **Enforceable where delegated:** only a holder of a publish-mandatory grant can publish binding
  policy, and only inside the grant's scope and conflict domains. The coordinator assigns the
  generation; a publisher cannot skip ahead of its own history.
- **Local sovereignty explicit:** local policy is authored as an ordinary bundle in site scope;
  overrides are explicit records with an author, a reason, a local generation, and a binding to the
  exact rule and generation they replace.
- **Incompatibility contained:** a contradictory subject becomes conflicted while every other
  subject in the domain still compiles.
- **Partitions cannot silently change authority:** accepted policy stays effective exactly as far
  as its *declared* staleness policy permits; require-fresh policy is withheld and reported,
  allow-last-known-valid policy is used and reported as last-known-valid, never as current.

## Repository layout

```
include/gpf/      public headers: the stable typed API
src/              implementation
apps/             gpfctl, gpf-federation, gpf-site
tests/            unit, property, adversarial, recovery, concurrency, multiprocess suites
benchmarks/       measured benchmarks (GPF_BUILD_BENCHMARKS=ON)
examples/         standalone downstream consumer project
cmake/            package config template and package validation script
```

Layer dependency is one-directional: base -> codec -> policy -> authority -> effective ->
store/protocol -> runtime -> applications. The deterministic core (policy, authority, effective,
conflict) performs no I/O, holds no locks and consults no clock.

## Data model

**Identities.** Every authoritative object has a stable 128-bit identity that survives restarts,
reconnects and reordering: PolicyBundleId, RuleId, FederationId, MemberId, SiteId, GrantId,
RevocationId, OverrideId, ReceiptId, ConflictId, StoreId. Identities are canonically rendered as a
lowercase hex string with a kind prefix.

**Rule.** A rule addresses one subject in one conflict domain, carries one typed value
(boolean/integer/text -- never coerced between types), and declares:

- *class*: mandatory, default or advisory;
- *scope*: federation-wide, member targets, or site targets (a scope with no target is invalid,
  because "no target" would silently mean "everyone");
- *precedence*, honored **only** between mandatory rules of the same domain, class and scope level;
- *capability prerequisites* with minimum versions, each optional or blocking;
- *override permission*: prohibited, allowed-with-authority, or allowed;
- *staleness policy*: require-fresh or allow-last-known-valid with a bounded window;
- effective/expiry times and a rationale.

A rule digest covers all authoritative fields. Types are never coerced: an integer rule and a text
rule with the same subject are contradictory, not convertible.

**Bundle.** A bundle is authored content published by one member under one delegated authority: a
bundle identity, the federation, the publisher, the publication scope, issued/effective/expiry
times, the runtime version it requires, the capability catalog generation it was authored against,
a staleness policy, the rules, and a **provenance chain** in which each entry records actor, member,
grant, authority epoch, generation, time, note, and the digest of the previous entry.

Two digests are computed, never authored: an *integrity digest* over all authoritative fields and
per-rule digests, and a *compatibility digest* over the compatibility surface (required runtime,
catalog generation, capability requirements, and the subject/major-version surface). A third digest,
the *content digest*, excludes the coordinator-assigned generation so that re-publishing identical
content is recognised as the same publication.

**Scope, inheritance and containment.** A bundle may never carry a rule wider than its own
publication scope. Scope containment is evaluated with the membership binding; a member-scoped
outer scope does not cover a site-scoped inner scope unless the membership binding says the site
belongs to that member. Absent that truth the answer is "cannot be established", which is reported
as a containment failure rather than assumed.
## Authority and generation model

Authority is **derived, never stored as a mutable flag**. A grant is usable only while its whole
chain up to the federation root grant is present, unrevoked, unexpired, epoch-current and
scope-narrowing. Verifying a decision walks the chain and reports the *first* broken link as a
distinct outcome: no-grant, out-of-scope, domain-not-covered, not-yet-valid, expired, revoked,
broken-chain, epoch-fenced.

```
grant: id, federation, grantor, grantee, parent, action, scope, conflict domains,
       not-before, not-after, authority epoch, justification, digest
actions: delegate | publish-policy | publish-mandatory | revoke | override-policy
```

Rules of delegation, enforced on every `add_grant`:

- exactly one root grant per federation, issued by the configured root member, carrying `delegate`;
- only a `delegate` grant can have children;
- a child's scope must be contained in its parent's, and its conflict-domain list must narrow the
  parent's (dropping the restriction is widening, and is refused);
- the grantor must hold the parent grant;
- re-applying an identical grant is idempotent, which is what makes plan re-application safe; the
  same identity with different content is refused as a conflict.

Revocation is ordered: sequences are strictly increasing, replayed or reordered revocations are
refused, and revoking an ancestor invalidates every descendant by derivation. Revoking a grant,
a bundle or a rule is a distinct target kind with distinct downstream meaning. The authority epoch
is the recovery lever: advancing it fences every grant issued under the old epoch, and the root
authority can then be re-established deliberately (the old root stays in the ledger as fenced
history rather than being erased).

Generations are per publisher and per scope. `publish_bundle` computes the next generation from the
publisher's own history, seals the bundle, and commits it durably **before** it can be propagated.
A publisher cannot skip ahead of its own history, and a bundle whose identity was already published
with the same content is a no-op.

## Conflict handling

Contradiction is detected between rules that address the same subject with the same class and
overlapping scope. Precedence is applied **only where the contract defines it**, in this order:

1. **Class**: mandatory over default over advisory.
2. **Explicit precedence** among mandatory rules of the same domain and scope level.
3. **Local sovereignty** for non-binding policy: a default authored by the site supersedes
   federated defaults for the same subject.

Everything else is a conflict. Two mandatory rules in the same precedence tier that disagree produce
a conflict record with the participating rules and bundles, contained to that subject: every other
subject in the domain still compiles. Conflicts are never resolved by arrival order, by connection
order, or by which publisher spoke last. Where several mandatory rules *agree* on a value but
disagree about override rights, the **most restrictive permission governs**: agreement on a value
never erases a prohibition.

Two rules in one bundle that contradict each other are an authoring defect and the bundle is
refused outright; contradiction across independently valid publications is what the compiler
contains at runtime.

Supersession is separate from conflict: a newer generation from the *same* publisher for the same
scope replaces the older one, with a superseded receipt per replaced rule. Different publishers are
never superseded by each other, because generation is not a vote.

## Effective policy

Compilation is a pure function of its inputs (accepted bundles, local bundles, overrides, capability
view, authority ledger, membership binding, clock, partition state) and produces the same digest on
any site. Each addressed subject yields exactly one entry in one of these states:

| state | meaning | binding |
|---|---|---|
| absent | nothing addresses this subject | no |
| active | binding and current | yes |
| overridden | binding, decided by an accepted local override | yes |
| last-known-valid | usable only because the declared staleness policy permits it | yes |
| advisory | informational only; advisory policy never binds | no |
| conflicted | authoritative sources disagree and precedence cannot decide | no |
| withheld | policy exists but may not be used (stale, expired, not yet effective) | no |
| revoked | the governing policy was revoked | no |
| incompatible | capability prerequisites are not met | no |
| indeterminate | deferral: capability unknown, catalog stale, or partition blocks resolution | no |

Every entry carries its source rule, bundle, generation and digests, the applied override if any,
the capability outcome, a stable reason code, and an ordered human-readable explanation. A subject
that nothing addresses is answered as *absent* explicitly -- a different answer from *conflicted*.

## Lifecycle: propagation, acceptance, activation, receipts

These are separate, durably recorded steps, in this order:

```
propagate  -> the coordinator offers policy in reply to an explicit sync request
accept     -> the site verifies integrity, scope, federation and publisher authority,
              commits a bundle-accepted record, and emits an accepted receipt
activate   -> the site compiles effective policy, commits the resulting generations,
              the verified contact time, and every receipt the compilation produced
report     -> receipts are sent to the coordinator, which deduplicates by receipt identity
```

Receipt identities are derived from the decision itself, so a duplicated delivery cannot create a
second, contradictory receipt, and re-reporting after a partition is safe. Receipts distinguish
accepted, applied, rejected, overridden, revoked, deferred, superseded, conflict-recorded and
withheld.

A local override is accepted only when it is bound to a bundle generation the site actually holds,
carries an author and a reason, and is durable before it can affect policy. At compile time it is
applied only if the governing mandatory rule permits override, if the delegated override authority
it cites is valid and in scope, and if the rule it names is still part of the agreeing authoritative
tier. If mandatory delegated policy forbids override, the refusal is deterministic and recorded,
and the binding value stands.

## Partition and reconnection

While disconnected the site is fully operational on what it already accepted:

- no new global authority is fabricated, and the newest global generation stays what it was;
- each rule is evaluated against its declared staleness policy: require-fresh policy is withheld
  and reported, allow-last-known-valid policy is used within its window and reported as
  last-known-valid;
- local policy and overrides continue to work, because they never needed the federation to be
  reachable;
- the verified contact time is durable, so a restart during a partition does not reset the clock
  that staleness is measured from.

On reconnection the site sends its applied generation and receives the delta. Generations are
reconciled, superseded publications are recorded as superseded, revocations are applied, and
receipts are re-reported and deduplicated. A coordinator that answers with an explicitly partial
sync is refused rather than half-applied.

## Persistence, recovery and fencing

A store directory contains a manifest, at most one sealed snapshot, and one write-ahead log:

```
MANIFEST                 identity, epoch, active snapshot, active log, reopen count
snapshot-<sequence>.gpf  sealed snapshot: format version, store id, sequence, digest, payload
wal-<sequence>.log       framed records: magic, kind, flags, length, payload CRC32C,
                         epoch, sequence, timestamp, payload
```

The commit protocol for every state change is: validate, append the record, flush it to stable
storage, and only then update the in-memory sequence. A record is authoritative only after the
flush returns. Compaction writes a new snapshot covering exactly the committed sequence, creates
the new log durably, republishes the manifest atomically, and only then removes the superseded
files -- so compaction cannot delete or supersede state that was not part of the snapshot it
published.

Recovery separates three outcomes that are never conflated:

- **clean**: the log replays completely;
- **torn tail**: the final record was not fully written. The trailing bytes are discarded, the log
  is truncated to the last good record, and the discarded byte count is reported.
- **interior corruption**: a damaged record with valid records after it, or a non-contiguous
  sequence. The store opens **read-only** and refuses writes and compaction. It never truncates
  through interior damage and never reports recovery success for it.

Fencing: every open advances the persisted store epoch, and every append verifies that the
persisted epoch still matches the writer's before touching the log. A process that was superseded
by another incarnation is refused with a fenced error instead of publishing into state it no longer
owns. Replayed history is idempotent by identity, and gaps are refused rather than reordered into
place.

## Wire protocol and transport

Framing is a little-endian 32-bit length followed by one JSON envelope carrying protocol version,
message type, request id, reply id and body. Both directions are bounded before allocation, every
message is validated before use, and a peer speaking another protocol version is refused explicitly
rather than parsed optimistically. Message bodies are validated as untrusted input: every field is
type-checked, every array is bounded, and every nested object is schema-checked.

A frame whose declared length exceeds the reader's bound closes the connection rather than leaving
a desynchronized stream to be reinterpreted. The handshake answers the handshake; policy always
travels in reply to an explicit sync request, so a site never has to guess how many frames to
expect. The transport is a blocking, bounded TCP adapter with no receive timeouts anywhere:
shutdown works by closing the socket, never by racing a clock.

## Concurrency and ownership rules

Stated once, and enforced by review of every call path:

- one mutex protects site state, and it is **not** held across a socket operation, an event
  callback, or a worker join;
- store appends are the commit point of a decision and are performed while holding the state lock,
  so two decisions cannot interleave validation and commit; the ordering is always state lock
  before store lock, never the reverse;
- event callbacks run after the state lock is released, so a callback may call back into the
  runtime; a throwing callback is contained and reported, never unwound through a lock;
- compilation runs on a bounded worker pool. Every task carries the store epoch and the generations
  it was built from; a result whose epoch or generation is no longer current is discarded as stale
  and reported as a stale-generation failure rather than published. Cancelled or superseded work
  never reports success;
- shutdown sets a stopping flag, notifies waiters, closes the socket, then joins workers. Workers
  never need the state lock to finish, so shutdown cannot wait on work while preventing it.
## Build, test, install

Requirements: CMake 3.20 or newer and a C++20 compiler (MSVC 19.3x, GCC 12+, or Clang 15+). There
are no third-party runtime dependencies; Threads is the only link dependency, and on Windows the
socket adapter links the platform ws2_32 library.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```

Options: GPF_BUILD_TESTS, GPF_BUILD_APPS, GPF_BUILD_BENCHMARKS, GPF_BUILD_EXAMPLES,
GPF_WARNINGS_AS_ERRORS (all ON except GPF_BUILD_BENCHMARKS). First-party code builds with strict
warnings and warnings-as-errors; no warning is suppressed globally.

Install and consume:

```
cmake --install build --prefix /some/prefix
cmake -S examples/downstream-consumer -B consumer -DCMAKE_PREFIX_PATH=/some/prefix
cmake --build consumer
./consumer/gpf-downstream-consumer
```

The exported target is the namespaced `SummonLabs::gpf`. The package configuration propagates its
transitive dependency, so a consumer declares nothing but the link. `ctest -R package_validation`
performs exactly those steps into a throwaway prefix, using the same toolchain as the validated
build, and fails if the installed package is incomplete or the consumer does not run.

## Command line

Three executables exercise the boundary for real, with no simulated transport and no fixtures
compiled into them.

```
gpfctl scenario --seed 4242 --sites 2 --bundles 1 --out plan.json
gpfctl validate-plan plan.json
gpfctl compile --plan plan.json --site-index 0 --out effective.json
gpfctl explain --effective effective.json --domain power --subject max_kw
gpfctl verify-store ./site-store --out store.json

gpf-federation serve --plan plan.json --store ./coordinator-store --port 46000 --sessions 2 \
                    --out coordinator-summary.json

gpf-site run --plan plan.json --site-index 0 --store ./site-store \
             --connect 127.0.0.1:46000 --sync-count 1 \
             --capabilities "power.metering=2.1.0,cooling.liquid=1.4.0" \
             --out site-summary.json
```

Exit codes are meaningful: `gpf-site` exits 0 when it synchronized, 2 when the federation was
unreachable (it kept working on accepted policy), 1 on failure; `gpfctl verify-store` exits 3 when
a store opened read-only because of interior corruption.

A local override is registered with the same executable:

```
gpf-site run --plan plan.json --site-index 0 --store ./site-store \
             --connect 127.0.0.1:46000 --sync-count 1 \
             --override power/max_kw=95 --override-reason "site thermal envelope" \
             --out site-override.json
```

The summary reports the compiler's verdict (`applied` or `refused:<reason>`), not merely that a
record was written, and the effective-policy section carries the explanation lines. The site
summary is a complete operational answer: accepted bundles, generations, receipt counts, pending
receipts, conflict and override counts, entries by state, the decision trail, and the effective
policy digest.

## Library use

```cpp
#include "gpf/effective.hpp"

gpf::EffectivePolicyInput input;
input.federation = federation;
input.member = member;
input.site = site;
input.now = now;
input.runtime_version = gpf::SemanticVersion{1, 0, 0};
input.capability_catalog.generation = gpf::Generation{1};
input.accepted_bundles.push_back(bundle);      // verified and sealed
input.authority = &ledger;                     // delegated authority
input.membership = &membership;                // membership truth, consumed not inferred

auto compiled = gpf::compile_effective_policy(input);
const gpf::EffectiveEntry* entry = compiled->find("power", "max_kw");
if (entry != nullptr && gpf::entry_state_is_binding(entry->state)) {
  // entry->value is authoritative, entry->state says exactly how, entry->explanation says why
}
```

The public headers are the contract: `gpf/base.hpp`, `gpf/codec.hpp`, `gpf/policy.hpp`,
`gpf/authority.hpp`, `gpf/effective.hpp`, `gpf/store.hpp`, `gpf/protocol.hpp`,
`gpf/net.hpp`, `gpf/platform.hpp`, `gpf/runtime.hpp`, `gpf/plan.hpp`.

## Validation performed

All of the following was executed on this repository on Windows 11 (16 logical cores), with
GCC 14.2.0 (MinGW-w64, UCRT, POSIX threads) and MSVC 19.4x (Visual Studio 2022, x64). Counts are
the checks reported by the run, not estimates.

| suite | tests | checks | what it covers |
|---|---|---|---|
| test_foundation | 15 | 239 | SHA-256 vectors, CRC32C, canonical encoding, bounded JSON, UTF-8, identity, time |
| test_policy | 9 | 106 | rule/bundle/override validation, digest canonicalization, capability negotiation |
| test_authority | 8 | 103 | delegation narrowing, chain outcomes, revocation ordering, epoch fencing, restore |
| test_effective | 14 | 1274 | precedence, conflict containment, overrides, capability outcomes, partition, seeded property test |
| test_protocol | 5 | 44 | framing, malformed and oversized frames, body validation, socket disconnect |
| test_runtime | 9 | 155 | publication authority, sync/activate/report, receipt dedup, callbacks, shutdown, fencing |
| test_store | 14 | 171 | round trip, torn tail, interior corruption, compaction, tampering, real process crash |
| test_multiprocess | 2 | 138 | three real executables over real TCP: sync, partition, restart, reconnect |
| package_validation | CTest | - | install into a throwaway prefix, build and run an independent consumer |

- **GCC 14.2 / Ninja, Debug:** 8 suites, 76 tests, 2230 checks, 0 failures; `ctest` 9/9 passed
  including package validation.
- **MSVC 19.4x / Visual Studio 2022, Release, x64:** `ctest` 9/9 passed, including the
  multiprocess end-to-end test and package validation.
- **Real process crash:** `test_store` spawns an independent process which writes three records,
  appends a partial record and exits without unwinding; the parent reopens the store, classifies the
  torn tail, truncates it, and continues. The helper's exit code is asserted.
- **Partition and reconnect:** `test_multiprocess` starts a coordinator process, syncs a site over
  TCP, stops the coordinator, runs the site again (exit code 2, partitioned, capability-aware
  last-known-valid and withheld states), then restarts the coordinator with more policy and
  reconnects. It asserts the applied generation advanced, supersession was recorded, receipts were
  deduplicated, and a mandatory prohibition refused an override deterministically while the binding
  value stood.
- **Adversarial input:** truncated and corrupted logs, absurd frame and record lengths, duplicate
  JSON keys, invalid UTF-8, malformed timestamps, unsigned overflow, nil and duplicated identities,
  unsafe file names, path traversal in a manifest, replayed and reordered revocations, and
  replayed receipts.

Not executed here, and therefore not claimed: Linux builds and tests, and the AddressSanitizer /
UndefinedBehaviorSanitizer configurations. Both are configured in `ci.yml` for standard hosted
runners; nothing in this document asserts a result for them.

## Benchmarks

`gpf_benchmarks --scale=1` measures a synthetic multi-site policy set of 4 publishers x 8 bundles
x 64 rules (2048 rules total, 32 bundles) on the machine described above, while a concurrent build
was running. Numbers are microseconds per operation as measured; `store.append` is labelled
DURABLE because every iteration is flushed to stable storage before it returns.

| benchmark | evidence | iterations | mean us | median us | p95 us | ops/s |
|---|---|---|---|---|---|---|
| bundle.seal | REAL | 200 | 95.9 | 97.3 | 124.4 | 10430 |
| bundle.verify | REAL | 200 | 278.2 | 291.8 | 366.9 | 3594 |
| effective.compile | REAL | 50 | 46397 | 42763 | 68157 | 21.6 |
| effective.compile_preverified | REAL | 50 | 44536 | 45264 | 53626 | 22.5 |
| effective.compile_partitioned | REAL | 25 | 47519 | 47187 | 51767 | 21.0 |
| bundle.json.encode | REAL | 500 | 406.8 | 421.1 | 551.0 | 2458 |
| bundle.json.decode | REAL | 500 | 554.1 | 614.8 | 694.5 | 1805 |
| protocol.encode | REAL | 200 | 15608 | 15122 | 21819 | 64.1 |
| protocol.decode | REAL | 200 | 8036 | 8185 | 10362 | 124.4 |
| protocol.roundtrip | REAL | 200 | 21636 | 21957 | 25197 | 46.2 |
| store.append (durable) | DURABLE | 200 | 1255 | 1169 | 1873 | 797 |
| store.replay | REAL | 20 | 7.7 | 7.6 | 8.6 | 130634 |
| store.open_recovery | REAL | 20 | 7297 | 7179 | 9114 | 137 |

Reading these honestly:

- Activating a 2048-rule multi-publisher policy set takes roughly 40-47 ms. Compilation is a
  control-plane operation, not a data-plane lookup: it walks every applicable rule, resolves every
  subject, verifies capabilities and produces an explanation. The compiling site is expected to do
  this on acceptance, not per request.
- The pre-verified configuration (bundles already verified at acceptance, so the compiler validates
  structure only) measured **no improvement** within noise on this workload (22.5 vs 21.6 compiles
  per second). It remains available as a trust decision, and this document does not advertise it as
  a performance feature, because the measurement does not support that claim.
- A durable append costs about a millisecond because it is flushed before it returns; replay of 201
  records costs about 8 microseconds in total. Durability is the expensive part, and it is the part
  that makes a receipt real.

## Platform support and limitations

- **Windows**: built and tested with MSVC 2022 (x64, Debug and Release) and MinGW-w64 GCC 14.
  Windows offers no portable directory flush, so sync_directory is a documented no-op after
  an atomic replace; files themselves are flushed with FlushFileBuffers (_commit) before publishing.
- **Linux**: supported by the portable code paths (POSIX sockets, fsync, fsync of the directory
  after a rename) and built in CI with GCC and Clang; it was **not** run on this machine, so no
  Linux result is claimed here.
- **No timeouts anywhere**: there is no receive timeout, no CTest TIMEOUT, no shell timeout wrapper
  and no watchdog. Shutdown and partition detection work by closing sockets. A hanging test is
  treated as a defect.
- **Single-threaded coordinator accept loop**: the coordinator serves one site session at a time and
  answers each sync exactly. Horizontal scale is a deployment concern outside this boundary; the
  protocol is request/response so a session multiplexer can be added without changing semantics.
- **Reconnects are pull-based**: a site reconciles on connect and on explicit sync. There is no
  push channel in this version, and therefore no claim of sub-second propagation.
- **Sanitizers are unavailable on this host**: the MinGW GCC 14.2.0 toolchain fails to link with
  "cannot find -lasan", and the MinGW Clang 19.1.1 toolchain lacks
  libclang_rt.asan_dynamic.dll.a for the windows-gnu target. No local sanitizer run is therefore
  claimed; ci.yml runs AddressSanitizer and UndefinedBehaviorSanitizer on Linux with both GCC and
  Clang.
- **Membership truth is an input**: a member-scoped delegation cannot be resolved against a
  site-scoped request without a membership binding. The absence of that truth is reported, never
  guessed.
- **Language surface**: JSON numbers are integers only. A document containing a fractional or
  exponent number is refused rather than rounded, which keeps digests and receipts comparable.

## Relationship to adjacent boundaries

- **Facility Policy Engine (site)**: consumes effective policy and its explanation from this
  boundary; it decides how effects are executed. This boundary never executes them.
- **Federation membership**: consumed as explicit truth (which member owns which site). Membership
  alone grants no policy authority here.
- **ASI (Accelerated Systems Infrastructure)** and **DFI (Distributed Fabric Infrastructure)**:
  referenced only through explicit contracts -- capability identifiers, versions, identifiers,
  digests and requests for effects. No ASI or DFI internal state is read, mirrored or inferred; if
  a capability's existence or version is unknown, that is reported as unknown.
- **DCCP facility boundaries** (identity, topology, assets, capacity, power, cooling, lifecycle,
  policy, tenancy, failure/recovery, observability, economics): this boundary federates *policy*.
  It consumes their published facts as scope, capability and conflict-domain vocabulary, and stays
  independently useful and swappable.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
