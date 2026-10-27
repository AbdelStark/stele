# E2-02 Merkle implementation review

Reviewer: codex-root, also the author; PCS-engineer and soundness-auditor passes,
not an independent audit. Governing contract: RFC-0012 A3.

Acceptance evidence:
- Production construction and path generation reproduce all ten committed
  Python byte vectors, for both kinds and counts 1,2,3,5,8.
- Actual verification checks every vector path and batch; mutations cover payloads,
  each sibling, root, index, id, kind, count, lengths and batch order/completeness.
  Equal payloads still bind their positions; absent padding cannot be opened.
- NC-0602 runs the actual builder/path producer and verifier for both kinds.
  Each hook changes exactly one byte, leaving the expected root/index fixed.
  Column fixtures include substitution of another leaf differing in one byte.
- An actual child-root/column composition accepts, while the same column opening
  fails against the other child's root. This does not establish shard semantics.
- The control gate runs Rust authentication/vector tests and regenerates the
  vectors with Python. Isolated root-comparison and batch-authentication bypass
  mutations must fail that gate; no scaffold fingerprint is refreshed.

I tried to break it by replacing one leaf byte and one sibling byte, and the
control NC-0602 rejected each with RootMismatch for both tree kinds.

Workflow 03 checklist:
- Public items: Descriptor, Kind, Digest, Opening, Tree, Error, verify and
  verify_batch implement A3; raw proof-container decoding remains RFC-0016 work.
- Challenges/absorbs: none added. Query selection and root absorption belong to
  future PCS schedules; membership is not evidence for NC-0601/0803.
- Claims/consumers: authentication binds bytes at the caller's descriptor/root/index.
  Child roots require a separate child path, as the composition test demonstrates.
- Bindings/controls: NC-0602 is registered and executed; other PCS controls remain.
- Ledger: no new challenge/algebraic line. Existing PCS ε_Merkle/H and Q12 remain
  uncertified; these checks do not establish codeword validity or a profile budget.
- Certificates/padding/masks: no integer relation or mask added; tree padding is
  absent data. Unopened padding and tensor selectors are not certified here.
- Determinism/parity: fixed bytes and ordered levels; Rust/Python vector parity.
  No GPU implementation, distributed parity or independent hash implementation claim.
- Costs: A3 hash counts and 32*(2*P-1) logical digest storage; borrowed payloads,
  allocation-free verification, checked construction/path allocation. No timing,
  fitted constant or weight-pass change; no performance acceptance line is present.
- Verifier: no_std and forbid(unsafe_code) retained. Shapes are validated before
  hashing; fixed arrays enforce digest widths. Batch shapes are checked before
  authentication and success requires every requested opening. Max depth is 63.
  Builder indices stay within checked total capacity and completed levels;
  Tree's private construction invariant guarantees a nonempty root.
- Glossary: no new exception. Q12/Q17 and PCS/inference/ZK obligations remain open.

Validation passed locally: fmt, all-target/all-feature clippy, workspace tests,
24 infrastructure tests (including both Merkle bypass mutants), digest, controls,
accounting, ledger, RFC-status, links, glossary and Rust-policy gates. Coverage is
7/67 controls, one configuration-only; 3/17 broad categories have proof controls,
not a complete claim graph.
