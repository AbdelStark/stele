# E2-00 transcript primitive review

Scope: RFC-0012 A1 implementation, both-field KATs, decoder boundaries, and gate
integration. Roles: pcs-engineer (hash owner) and soundness-auditor, performed by
the author. This is not an independent audit or a Fiat-Shamir security proof.

- Public items: `Transcript`, sealed `ChallengeField`, closed `AbsorbLabel` and
  `ChallengeLabel`, and the additional typed errors implement RFC-0012 A1.
  Only QM31/OM31 implement the private target trait; no caller degree, label
  string, state import, alternate registry, or random-byte provider is accepted.
- Challenges/absorbs: construction validates the fixed registry and absorbs
  nonempty public-input bytes after hashing the initialization domain. Each
  request hashes the current state, tag 1, registered label, and degree byte.
  Sampling examines at most 64 masked LE words, rejecting p instead of reducing
  it. The tag-2 update binds degree, consumed count, and canonical coefficients
  before return. Tags, lengths, state width, basis order and update bytes match
  the independent Python framing oracle for both fields at every event.
- Claims/consumers: this primitive emits field challenges, not polynomial claims.
  Consuming protocols must validate public inputs/profiles and enforce their
  Accepted schedule. It deliberately cannot infer that schedule itself.
- Bindings/controls: NC-0801 still rejects one duplicated production registry
  label. Primitive tests cover omitted/reordered/changed final messages and
  repeated challenges, but receive no NC-0800/0802 or proof-binding credit.
- Ledger: one registered challenge maps to SC plus FS/H. Exact field denominators
  and conditional sampling uniformity follow A1. No new error term or certified
  profile budget; the Q12 FS/H obligation remains open. The actual accounting
  gate now runs these primitive tests as well as registry validation.
- Bound certificates: no integer reduction or new certificate instance.
- Padding/masks: no tensor padding, lookup or zerocheck. The 31-bit candidate mask
  implements the specified two-preimage sampling, with both rejected words tested.
- Determinism: ordered fixed buffers, ordinary unkeyed pinned BLAKE3, canonical
  field serialization. No native-endian reads, map iteration, or external RNG.
  Errors precede the only state assignment. Exhaustion is forced in the pure
  decoder; no test RNG is added to the production transcript. State preservation
  on that unreachable-in-normal-tests XOF event is checked structurally.
- Parity: the same committed KATs run on local ARM and hosted x86. No GPU was
  modified and no GPU proof-parity result is claimed.
- Cost model: A1's fixed initialization hash, framed absorbs, request XOF and
  update hash contribute to T_misc. No measured constant or benchmark claim;
  constant working storage, no allocation in the primitive.
- Verifier: unchanged; hash crate remains `no_std` and forbids unsafe. Checked
  frame lengths return `LengthOverflow`; array bounds follow sealed degrees
  4/8, at most 64 candidates, and the accepted-count stopping condition.
- Glossary: existing transcript/challenge/registry and canonical field terms.

I tried to break it by duplicating a registered label, and the control NC-0801
rejected it with `DuplicateLabel`. Decoder tests additionally reject exhausted
streams, while KATs detect wrong framing, field basis or state updates.

Validation: tests were first run against the missing API and failed to compile;
implementation then passed nine core tests and the closed-field compile-fail
test. Histogram diagnostics use 10,000 deterministic inputs per field and do not
prove uniformity. The oracle checks core-fixture equality and shares the official
BLAKE3 backend, so it is independent framing/sampling code, not an independent
hash implementation. Workspace and hosted gate receipts are recorded in the PR.
