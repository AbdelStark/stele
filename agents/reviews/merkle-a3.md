# RFC-0012 A3 review

Reviewer: codex-root, also the author. These soundness-auditor, RFC-author,
PCS-engineer and distributed-systems-engineer passes are not independent audit.
Scope: authentication bytes and research checks, not production E2-02 completion.

Soundness-auditor: fixed-width headers, tags, indices, levels and ordered children
make the framed tuples unambiguous. Absent leaves differ from real all-zero
payloads. Exact depth/range checks prevent unused path suffixes and padded-index
openings. Two accepted values at one fixed root/index imply a hash collision;
this conditional argument neither establishes BLAKE3 security nor bounds Q12.
No algebraic challenge/loss is added. Membership leaves PCS codeword validity,
canonical field decoding and unqueried subtree contents to their consumers.
Sign-off: approve the byte contract; no aggregate profile certification.

I tried to break it by changing each sibling in an otherwise honest path, and
the research control rejected it with RootMismatch. The same study rejects
changed payloads, indices, descriptors and malformed batches. These checks receive
no NC credit; production NC-0602 for both kinds is required before E2-02 is done.

RFC-author: Accepted text before A3 is unchanged. A3 states the authenticated
object, exact messages and algorithms, cost formulas, conditional binding
argument, profile limits, controls and open questions. Existing task acceptance
criteria remain. Q17 explicitly records the shard/digest ambiguity discovered
in review; this primitive does not silently redefine E4-07. Sign-off: approve.

PCS-engineer / stele-hash owner: byte-oriented payloads reuse BLAKE3 without
importing another prover or inventing a field encoding. Caller-owned descriptors,
indices and roots are explicit trust boundaries. Full paths are a sufficient
baseline; no compressed multiproof option is needed. The builder can store a
flat digest tree; verification needs only one current digest and a borrowed path.
Size conversions and allocation arithmetic must be checked. Future PCS query
sampling and field decoding remain mandatory. Sign-off: approve for E2-02.

Distributed-systems-engineer: child-root positions are ordered by the plan;
arrival order cannot choose them. A child opening must be checked against the
exact authenticated child root. Changing the logical root list changes the
commitment; Q17 must establish canonical partition/device semantics before
E4-07 claims 1-versus-N-shard digest parity. No GPU/distributed behavior is added
here. Sign-off: approve this fixed-list primitive, not distributed parity.

Workflow 03 checklist:
- Public items: no core API added; A3 governs future Merkle APIs.
- Challenges/absorbs: none; no transcript label or query sampler added.
- Claims/consumers: byte membership at the requested position; a kind-2 result
  authenticates a child root, whose separate column path is still required.
- Bindings/controls: existing NC-0602 clarified for both kinds; remains todo.
- Ledger: PCS ε_Merkle/H remain conditional and uncertified; Q12 unchanged.
- Certificates: no integer identity, dynamic bound or bound certificate added.
- Padding/masks: tree padding is typed absent data; cannot be queried. Tensor
  selectors and ZK masks are unaffected; unopened padding is not certified.
- Determinism: fixed layout, byte framing, child ordering and path order.
- Parity: candidate vectors only; no Rust/GPU proof parity claim.
- Costs: explicit hash counts/payload bytes; no measurement or fit change.
- Verifier: core unchanged; future API rejects malformed shapes before hashing.
- Glossary: existing vocabulary, no new exception.
