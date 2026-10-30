# Consumed limb products — same-author review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is not independent audit. Scope: Draft RFC-0004 A3 /
RFC-0008 A2 / RFC-0012 A8, using unchanged Accepted RFC-0006 A1/A3 and range_8.
Evidence: [product study](../../research/cqis-bounds/LIMB-PRODUCT.md).

- Public items: expected source/output/schema derivation, actual range composition,
  polynomial arithmetic producer and full revealing verifier. The conditional
  core helpers do not authenticate ranges or accept a complete statement alone.
- Challenges/absorbs: all original roots and completed input/output/carry range
  states precede fresh rho. Three ordered A1 instances absorb all finals, with
  1+a+2h new Sumcheck draws; no new registered label, retry or random inverse.
- Claims/consumers: both main virtual claims reach digit sumchecks. Their power
  claims use exact public evaluation; their source claims use u+[side]+t against
  the bound original, with the same row point. Output/carry target evaluation is
  an exact functional of authenticated arrays. Every nested range claim remains.
- Bindings/controls: changed roots/openings reject commitment checks. Actual false
  products and legal-range wrong carries reject Product. Coherent wrong-source
  arithmetic, zero-factor cancellations and swapped row pairing reject actual
  source consumers. Coordinated power/source finals reject PowerClaimMismatch.
  Malformed shape/field, id aliases and capacity controls earn no native NC credit.
  Full proofs with C0=1 or nonzero ignored output padding satisfy the core
  equations but fail their actual range endpoints; neither zero is assumed.
- Ledger: conditional polynomial degree K-1 adds (K-1)/|Kfield|; three degree2
  A1 records add (2a+4h)/|Kfield|. Preserve all nested range/lookup terms; no
  nonidentity error is squared. K=1 retains a zero identity loss and rho draw.
  Exact records/draws are checked; binding, FS/H and joint ZK remain additional.
- Static faithfulness: original whole-input ranges imply certificate digit caps.
  Actual output/carry ranges enforce both column-side bounds and zero endpoints.
  Each false integer column is a nonzero field coefficient; high planes vanish,
  giving the static polynomial degree. Integer telescoping proves the product.
- Padding/masks: each input family's padding and high planes are zero under the
  input consumer. Output/carry S-padding is zero under actual caps; ignored high
  positions are therefore enforced, not assumed. No model selector is inferred.
- Determinism: fixed scope ids, byte framing, root/state order and A1 schedule.
  Frozen corpora, both fields/repetitions and exact original-coordinate checks.
- Parity: research Python only. Public powers match 10000 independent table folds,
  including edge coordinates; field/lookup/Merkle engines are shared and disclosed.
  Native inference/GPU code is untouched and no independent private prover claimed.
- Costs: core O(NP+S) field work and O(NP) original consumption, plus complete
  inherited range work. No replicated digit-pair grid, benchmark, fitted constant,
  production cut or new physical weight pass. Fused weight integration stays open.
- Verifier: production no_std untouched; expected capacities precede payload work.
  Every core shape/field is checked before replay. This object proof is not an
  admitted native wire parser. No plaintext multiplication accepts the statement.
- Glossary/history: append-only Draft evidence/accounting; original criteria remain.
  Signed/model-source contracts, native lowering, private PCS/ZK and FS stay open.

I tried to break it by using B-squared arithmetic with valid ranges in place of
the authenticated A*B, and the control LeftSource:SourceClaimMismatch rejected it.
A changed interior carry cancels at a fixed radix evaluation but the real fresh
transcript challenge instead produced Product:FinalEvaluationMismatch.
