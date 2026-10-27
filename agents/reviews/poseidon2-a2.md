# RFC-0012 A2 skill reviews

Reviewer: codex-root, also the author. These are same-author skill passes, not an
independent audit or a wrapper security theorem.

Soundness-auditor: approve the exact permutation definition. Fifth-power
invertibility follows gcd(5,p-1)=1. The external layer combines invertible M4
blocks with I+J on four blocks; the internal determinant follows the diagonal
matrix determinant lemma. Exact integer checks verify nonzero determinants.
These facts prove permutation structure, not random-oracle or collision bounds.
Q14 prohibits inferring a wrapper budget from these KATs. Q12 remains unchanged.

I tried to break it by omitting the initial layer and changing one round constant,
and the control `check_poseidon2.py` rejected it. This research comparison earns
no NC catalog credit and verifies no protocol statement.

RFC-author: approve append-only A2. Width, matrix orientation, simultaneous-update
semantics, round order and all 142 constants are fixed. Encoding is field-array
only; no digest or challenge construction is silently selected. E2-03 retains
its original KAT acceptance; E14-01 retains its full protocol obligations.

PCS-engineer (hash/wrapper owner): approve the pinned default permutation and
reference corpus. Plonky3 is isolated in vendor-ref with dev-dependencies only;
core must implement A2 independently. MIT attribution accompanies constants/KATs.
The wrapper feature is a compilation choice, not a security isolation boundary;
native callers remain forbidden from using it as a replacement for BLAKE3.

Sumcheck-prover-engineer (native transcript consumer): approve the isolation
contract. No sumcheck label, degree, absorb, challenge, or SC mapping changes.
The permutation API cannot be used as a challenge source; native sumchecks
continue to use RFC-0012 A1's Transcript.

Workflow 03 checklist:
- Public items: none in core yet; the proposed permutation implements A2 only.
- Challenges/absorbs: none added; native A1 is unchanged.
- Claims/consumers: none emitted; E14-01's wrapper protocol remains pending.
- Bindings/controls: none added; NC-1203 and all existing gaps remain incomplete.
- Ledger: no error formula/count changes; accounting gate retains A1 mapping.
- Bound certificates: no integer identity or new instance introduced.
- Padding/masks: no tensor rows, lookup or zerocheck introduced.
- Determinism: ordered fixed arrays and locked reference; exact output comparison.
- Parity: Python versus executed scalar upstream reference, not GPU proof parity.
- Cost: 142 fifth powers, nine external and fourteen internal layers; no measured
  constant changes, performance claim or benchmark ledger.
- Verifier: unchanged; core no_std/panic rules still apply at implementation.
- Glossary: existing field/transcript/commitment terms retained.
