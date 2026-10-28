# Q22 sequential-file source review

Reviewer: codex-root, also the author; sumcheck-prover-engineer, rfc-author and
soundness-auditor passes. Not independent review. Approve the research evidence
for gated merge; A6/A1 remain Draft and E3-05 remains blocked.

- API/RFC: research only under RFC-0006 A6 / RFC-0014 A1. The original indexed
  oracle keeps its default path; an injected block iterator supplies the same
  partially evaluated inputs. No core source or Strategy API is introduced.
- Challenges/absorbs: identical A1 Instance, Round and Final processing. All
  transcript continuations match Dense in both fields; no label or loss changes.
- Claims/consumers: tail placement restores canonical suffix order, including
  unused inputs. The original public consumer uses the original source values,
  not the substituted files. Prover preparation never authenticates the claim.
- Bindings/controls: ten single unused-source value changes keep rounds equal
  and alter one final claim; ClaimMismatch rejects. No production NC credit.
  Malformed lengths/limbs fail in the actual reader, without reducing bad limbs.
- Ledger: no new field challenge, SC loss or profile admission. Deterministic
  prefix interpolation and reordered exact sums preserve the A1 argument.
- Certificates: field algebra only; no integer-inference certificate supplied.
- Padding/masks: original m/coordinate order is retained; no inference mask or
  padding policy is introduced. No-input and m=0 cases are tested explicitly.
- Determinism: fixed seed, fixed file layout, exact canonical extension limbs.
  File positions and original-index inventories are checked for every visit.
- Parity: 72 file-source cases match Dense proofs/points/continuations and the
  public consumer. The existing 60 indexed-source cases remain required. Neither
  is Rust/GPU implementation parity or an independent field/transcript oracle.
- Costs: a*N*4*d bytes per visit, measured from returned file data with checked
  positions. This is not disk traffic or a benchmark. Full source preparation,
  host/device storage, object capacities and transition overlap remain open.
  The observed scratch list length cannot substitute for actual peak bytes.
- Verifier: unchanged, including no_std behavior and supported proof bytes.
- Glossary: no new cut, commitment or weight pass. Replaying these research
  files does not authorize weight replay in the future inference pipeline.

I tried to break it by changing one unused source value, and the control in the
research public consumer rejected it with ClaimMismatch. This is research
rejection only. The reader does not establish immutable source identity, a full
allocation bound or bounded-memory preparation; those are still acceptance gates.
