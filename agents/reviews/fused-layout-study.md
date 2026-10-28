# Fused layout study review (Q28)

Reviewer: codex-root, also author. Same-author pcs-engineer, soundness-auditor
and rfc-author passes; not independent review or approval of a production layout.
RFC-0010 A6 / RFC-0007 A1 remain Draft and every E4-03/E4-04 criterion remains.

The rank proof allows any nonlinear source codec but assumes fixed affine
decoders for all original coordinates. Taking differences at zero/unit inputs
forces a rank-T identity, so fewer than T message coordinates cannot suffice.
The result does not exclude extra private proofs, nonlinear decoding or one
selected functional. The positive selected-functional test checks that boundary.
The signed direct layout and short-column low fold use independent axis padding;
raw byte storage is distinguished from signed field messages throughout.

Workflow 03 checklist:
- Public items: research prototype/derivation only, no admitted source or PCS API.
- Challenges: fixed seeded test points, not transcript challenges; no new label.
- Claims/consumers: exact signed and split matrix identities are checked against
  dense tables. Source/passport/range, actual phase/B binding and PCS consumers
  remain missing; a value/read counter cannot authenticate them.
- Bindings/controls: signed, internal padding, low-point order and repeated-read
  mutations fail the targeted checker. These earn no NC-0305/0603/0605 credit.
- Ledger: no loss, setup/proximity or profile decision changes. The rank and
  linear identities are deterministic; omitted protocol work still needs accounting.
- Static bounds: signed width/shape determine the candidate representation.
  This does not supply a verifier bound certificate or private range proof.
- Padding: each axis independently padded; internal holes and scalar axes tested.
- Determinism: fixed source/axis/bit order, fixed seeds, immutable row/B tuples.
- Parity: 2,000 full-QM31/OM31 cases compare independent dense folds, each split
  coordinate, tensor evaluations and arbitrary column functionals. No native,
  transcript-byte, Rust/Python protocol or GPU parity claim.
- Cost: exact symbols/MACs and two payload terms only. The retained count excludes
  transient Python allocations, code/hash/PCS state, native process/GPU memory.
  No measured constant, benchmark comparison or proof-size optimum is asserted.
- Verifier: no production/no_std changes. Native supported lengths, checked
  arithmetic/allocation and trusted descriptor derivation remain required.
- Glossary: uses existing source, functional, weight pass and fused opening terms.

I tried to break it by embedding negative weights as unsigned bytes, moving
internal axis padding, reversing the low-point order and rereading the source,
and the control check_boundaries rejected each isolated implementation mutant.
The final full study, RFC status, documentation links, glossary, CI-scope
regression and diff checks pass. Hosted CI is still required before merge;
no result from that future run is claimed here.

Delivery bookkeeping: E4-08's complete native encoder evidence merged in PR #84
after exact-head CI run 40715805543 succeeded; its benchmark runner merged in
PR #83 after run 40714214290 succeeded. The merged trees were checked against
their tested heads before dependent merges. E4-08 may now be marked done.
E4-01 remains blocked on registry/provenance/consumer admission; nothing in this
study or that encoder delivery completes PCS, ZK or end-to-end inference.
