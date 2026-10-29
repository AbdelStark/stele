# E5-03a native static-record completion audit

Author/reviewer: codex-root. Same-author cqis-numerics and soundness-auditor
review, not independent audit. The implementation and its Accepted RFC-0022
contract are merged in [PR #139](https://github.com/AbdelStark/stele/pull/139)
and [PR #138](https://github.com/AbdelStark/stele/pull/138), respectively.
This record closes only the four original E5-03a acceptance criteria.

| Acceptance criterion | Evidence |
|---|---|
| Exact static derivation from separate checked parameters | [Record](../../crates/stele-cqis/src/bounds.rs) takes checked Requant/Format or function Descriptor values, delegates to the closed [schema](../../crates/stele-cqis/src/bounds/schema.rs), and exposes immutable complete bytes. No supplied schema, modulus, observed magnitude or raw-record constructor controls expected derivation. Another function rejects. |
| Full bytes and every column field match 10000 configurations per schema | [check_encoding.py](../../research/cqis-bounds/check_encoding.py) independently derives scalars and roles, checks every digit/carry/side field against its packed-polynomial oracle, and compares all 20000 complete encodings plus seven boundary records with the native adapter. The required CI invocation has no reduced-count option. |
| RFC-0022 §6 boundaries, mutations and resource failures | [Native tests](../../crates/stele-cqis/tests/bounds.rs) change every byte and truncate every prefix of each boundary record; trailing/oversized records, field-congruent aliases, role order and different valid expected parameters reject. They preserve static RMSNorm bounds above u128. Internal Record tests check strict p/2 endpoints, capacity preservation and arithmetic overflow. [u160 tests](../../crates/stele-cqis/src/bounds/wide.rs) cover 10000 independent full-width products, all 160-by-160 bit pairs, cross-word carries and high-word rejection. |
| no_std and required repository gates, without full E5-03 credit | The exact-head hosted evidence below includes no_std, dependency bans, fmt/clippy/workspace tests, digest, controls, soundness accounting and the full native byte corpus. The existing [implementation review](cqis-native-static-records.md) documents checked arithmetic, fixed 8192-byte storage, at most twenty columns, allocation-free comparison and immutable expected authority. |

The deterministic corpus uses seed 2612 and retains checksum
`6ebb4c66a125e60a031f6ba76aaf75e330dc21f96ac1f2509a7fa1f8352503e0`.
The generic arithmetic helper retains all high words and rejects overflow;
closed-schema bounds never authorize silent truncation. No native dependency,
implementation, fixture or gate is changed by this completion record.

## Exact merged evidence

Head `89a14e1ea747092fd9ad6daf33c25c26067fd9a9` passed
[CI run 40847974418](https://github.com/AbdelStark/stele/actions/runs/40847974418):
`gates` job 123360062116, `poseidon2-reference` job 123360062405 and
`simd-throughput` job 123415915079 all completed successfully. GPU and nightly
jobs were skipped by their configured conditions; this supplies no GPU parity.
Merge `0bd0b8d7dbcc01f12c23864b3d5918e4108d1844` has exactly the tested
head's tree, verified before and after merging. This status-only follow-up
requires its own repository gates and exact-head CI before merge.

## Preserved obligations

No new public protocol item, challenge, emitted claim, binding, mask, certificate
instance or soundness loss is introduced by this status update. Fixed role and
byte order, canonical zero extension and checked integers retain determinism.
No GPU code, cost-model constant, weight pass, commitment or benchmark changes.
The implementation remains no_std; glossary and original task criteria remain.

I tried to break the audited boundaries with changed expected parameters,
field-congruent integer encodings, malformed lengths and overflowing arithmetic;
the cited native tests reject them for their stated errors. These are primitive
checks, with no new catalog-control credit or Workflow 08 exception.

Static metadata validation does not authenticate its parameters or enforce
source, whole-value, digit, carry, lookup, branch or output relations. NC-0109
and all actual consumers remain requirements of full E5-03. The quantiser,
complete CQIS identity, forward pass, model fidelity, private PCS, joint ZK,
Fiat-Shamir and end-to-end inference proof remain unfinished. Only E5-03a is done.
