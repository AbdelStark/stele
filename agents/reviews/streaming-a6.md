# RFC-0006 A6 / RFC-0014 A1 complete-contract review

Reviewer: codex-root, also the author; sumcheck-prover-engineer / stele-sumcheck
owner, rfc-author, soundness-auditor and negative-control-author passes.
The cuda-kernel-author / stele-gpu planning-owner pass reviews RFC-0014 A1's
device-budget boundary; it supplies no GPU implementation or measurement.
Not an independent audit. Scope: accept the completed deterministic strategy
contract for gated merge; production streaming and its delivery gates remain open.

- Public items/RFC: the source layout/interface, explicit schedule, bounded path,
  capacity/error contract and delivery criteria are specified in formal/streaming.md.
  The former Draft open items are resolved there, rather than silently omitted.
  No production API or strategy is added by this specification change.
- Challenges/absorbs: the full A1 Instance, delta+1 Round nodes, m challenges
  and all Final values are retained. Absorption precedes each draw. Zero-degree
  uses one wire endpoint despite a two-node internal grid. Continuations match.
- Claims/consumers: every original input survives the tail in canonical order,
  including unused inputs. Source metadata, file permissions and replay assertions
  cannot replace the original authenticated consumer. This remains true for a
  malicious or concurrently changed prover source; no trust is added to the verifier.
- Bindings/controls: NC-0210 is specified as an actual original-value rejection
  through the real Streaming prover/public consumer and ProverHook. It is todo,
  not credited by the ten research mutations. Format/EOF/I/O/capacity failures
  are separate constructor/source tests and cannot substitute for that control.
- Ledger: no new label, challenge, loss or profile claim. The exact m*delta/p^d
  conditional A1 bound remains; Q12, PCS and ZK obligations are unchanged.
- Certificates: field-only operations; no integer-inference identity or CQIS
  certificate. Checked sizes are resource/addressability guards, not range proofs.
- Padding/masks: source reversal changes storage order only. Tail placement uses
  the original suffix index; no inference padding or mask convention changes.
- Determinism: fixed schedule/layout/nodes and exact K arithmetic. Shape/id/full
  Instance checks prevent stale cached descriptors. Failed attempts are discarded.
- Parity: 60 indexed-source and 72 sequential-file QM31/OM31 cases agree with
  Dense, the original consumer and continuation. The same field/transcript oracle
  is reused; independent production Rust/Python decisions remain required. The
  frame lengths are checked against the existing A1 encoder, not a new wire format.
- Capacity: disjoint window regions need b^w+a*2^w+2a cells; tail uses
  a*2^(m-S)+a. Reuse takes their maximum, with full supplied capacity charged.
  A preallocated Proof and canonical byte buffer prevent hidden return/frame
  allocation in the bounded path. Ordinary allocating Summand wrappers cannot
  claim that bound. The actual Rust execution must test unchanged capacities
  and pointers; a formula checked against an estimator is explicitly insufficient.
- Complete memory/cost: source/descriptor/schedule/proof/caller buffers, inline
  state, preparation and consumer peaks are included separately. Allocator/OS/RSS
  are not equated with payload capacity. The device 40% rule still needs full
  actual GPU evidence and byte parity. No physical-disk or performance number is
  inferred from read counts, and no second weight pass is authorized.
- Preparation: the adapter reads each original record once and writes to its
  reversed output offset using bounded record storage. Tests retain originals,
  reject malformed input and existing outputs, and remove failed new outputs.
  Fixture/reference allocations remain visible; no complete-process bound follows.
- Verifier: unchanged, with existing no_std and A1 length/error requirements.
- GPU planning: RFC-0014 A1 retains full actual device allocation/transfer
  lifetimes, canonical integer outputs, fixed reduction order and the unchanged
  CPU/CUDA gate. CPU workspace capacities alone cannot approve the 40% device
  condition. No kernel, lazy reduction, atomics or device benchmark changes.
- Glossary: no new cut, authenticated claim, profile or intermediate commitment.

I tried to break it by substituting one unused source value, and the control in
the research public consumer rejected it with ClaimMismatch. This sentence
describes research evidence, not completed NC-0210 or independent review.

Sign-off: approve A6/A1 for gated merge. E3-05 becomes ready for implementation,
not done. Require the bounded path, file adapter, all parity/control tests and
complete cost/memory ledgers before declaring the task complete.
