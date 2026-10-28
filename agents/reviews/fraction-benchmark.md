# Fraction primitive benchmark review (E3-07a)

Reviewer: codex-root, also author. Same-author benchmark-runner and
soundness-auditor passes, not independent audit. RFC-0008 A3 / RFC-0018 §1.

Workflow 03 checklist:
- New public items: benchmark executable/controller only, no production API.
- Challenges: actual native Transcript and reduction engines; fixed synthetic
  fixture recipe and descriptor precede proof draws. Fixture-generation draws
  belong to a separate public synthetic-data generator, not proof accounting.
- Claims: actual original leaf arrays consume both tree outputs; original public
  selector and all columns consume selected-product outputs, including beta=0.
- Bindings: no new protocol binding. Existing controls and shared corpus remain
  mandatory before measurement. Python admission tests remove original claims,
  Gamma/Fold accounting, canonical bytes and charged cost fields and must reject.
- Ledger: actual complete scoped tree/leaf records checked against static formulas.
  No new loss, integer identity, bound certificate or profile admission.
- Padding/masks: Boolean fixture selector only; no complete lookup statement.
- Determinism: every sample's complete proof bytes and continuation agree; both
  fields and scalar boundaries tested. No GPU change or parity claim.
- Cost: c_sc/T_misc primitive baseline only; no fitted constant, c_lu or weight-pass
  change. Complete timer starts before preparation and ends after source/proof
  cleanup. Remaining validation/result construction overhead is charged separately.
- Memory: fresh native process peak includes all preparation, retained levels,
  Dense/equality copies, encodings, consumers and allocator retention. It is a
  whole-operation measurement, not an attributed prover peak or host-memory bound.
  Named capacity fields cover only actual original/encoded Vec allocations.
- Verifier: unchanged no_std production implementation, actual canonical decoder
  and public consumers. Local harness uses checked bounded benchmark dimensions.
- Glossary: existing terms; no inference/PCS/private source/ZK/FS claim.

I tried to break it by removing unused original columns and Gamma/Fold records
from measurements and understating complete time/buffer capacity; the ledger
admission controls rejected them. Publication requires clean-commit measured
ledgers; harness implementation alone does not complete E3-07a.
