# Native code A4 review

Reviewer: codex-root, also author; same-author skill passes, not independent audit.
Soundness-auditor: approve exact encoder arithmetic, identity and resource contract.
The finite induction and capped-stream coupling are explicit in the formal notes;
check_expander.py regenerated all twelve degree pairs and 200431782 event bounds.
check_sampler.py passed framing, cap boundaries, regeneration and all-seed checks.
Neither test proves concrete BLAKE3, PCS proximity, quantum FS or a complete profile.
The all-seed error is descriptive metadata; no admission or loss registry is enabled.

I tried to break it by changing a canonical setup coefficient and by enlarging the
seed universe, and the control check_sampler.py rejected it. This research evidence
earns no production NC credit; native tests and complete ledgers remain required.

RFC-author: approve A4's explicit adoption of the full encoder/identity task with
native budget and errors. A1/A3's remaining PCS, commitment and profile requirements
are retained. No acceptance criterion of E4-01 or its consumers is removed.
PCS-engineer (code/hash owner): approve closed identities, fixed setup domains,
regenerated graphs and field types; no raw-graph callback or caller metadata is
accepted as authority. Preparation is explicit and graph budget is not total memory.
Sumcheck-prover-engineer (future fused consumer): approve isolation from native
transcript and weight passes. Fused u=B and arbitrary functional obligations remain.

Workflow 03 checklist:
- Public items: CodeId/Code/encoder metadata, prepared code and fixed setup blocks
  implement RFC-0010 A4; field/hash edge is RFC-0020 A4.
- Challenges: none. Fixed setup expansion is not proof Fiat-Shamir randomness.
- Claims/consumers: no protocol claims emitted; full identity is consumed by the
  actual native factory, not by a PCS commitment verifier yet.
- Bindings/controls: no NC-06xx credit; encoding/registry mutation tests required.
- Ledger: separate conditional setup metadata only; A7/Q12 composition remains open.
- Certificates: no CQIS integer identity; all dimensions derive from fixed IDs.
- Padding: no implicit row/size padding; exact non-systematic base preserved.
- Determinism: fixed levels, matrices, rows, sorted neighbors and coefficient order.
- Parity: native M31/QM31/OM31 and independent direct-map tests required, no GPU claim.
- Cost: complete c_c/T_misc preparation, sparse work and recursive memory ledgers
  required before E4-01 completion; no numerical performance claim at acceptance.
- Verifier: no_std core, fixed recursion depth, checked sizes and fallible allocation.
- Glossary: code, commitment, distance, proximity and profile remain distinct.
