# Static row codes — same-author review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is not independent audit. [Evidence](../../research/cqis-bounds/STATIC-ROW-CODE.md).

- Public items: RFC-0004 §5.5 / Draft A3/A8, unchanged RFC-0006 A3 and range_8.
  Static public scale, actual signed sources, bounded division and sign transfer;
  no production cut, physical packed root, native reduction or private admission.
- Challenges: seven roots and five verified child states precede three A3
  invocations. Each follows Instance, ZeroWeight, rounds/Sumcheck and Final;
  scalar dimensions retain Instance/Final. No new labels, retries or inverses.
- Claims: all ten parent finals have actual source/public/view consumers at
  their emitted point. Q shares output magnitude's root. Padding, broadcasts,
  extensions and carry packing derive from verified arrays, never supplied views.
- Bindings: one-value input/output raw/magnitude, Q/R/T and public-scale controls
  reject. Every final is mutated, including coordinated changes preserving the
  equation and factors multiplied by zero. Genuine wrong-source Q and wrong-sign
  children also reject. Original native controls remain separate.
- Ledger: own A3 numerator8a+3c; full121a+26b+7br+12c+25. Both full A3 label
  counts51a+10b+3br+5c+11; nine lookup identities/reductions remain separate.
  Matrix assertions check each term/draw/claim. No reduction is squared, no A1.
  Binding, FS/H and joint private composition remain additional. Accounting gate
  is required with the other local gates before this change is reported passing.
- Bounds: P=max(input bytes,remainder bytes), NP<=4096, sides<=66813<p/2.
  Actual Q/R/T ranges give faithful integer division. The static gated domain
  follows afterward from Mag<=floor((255*S-1)/2), never a runtime assumption.
  Actual signed output plus Q<=127 closes the asymmetric -128 endpoint.
- Padding: original sources have cap0 padding, public S is masked there and
  carries are3. Zero extension preserves all R high bytes at S65535. Terminal
  C0=CP=0 closes difference carries even when both full sides exceed256^P.
- Determinism: fixed child/plane order, exact integers and little-endian context.
  Independent rounding corpus, complete field/repetition matrix and public MLE
  agreement cover ragged/zero/endpoints; all resource bounds precede payloads.
- Parity: native CPU/SIMD/CUDA unchanged. Small naive/folded A3 parity and
  reference integer checks are research evidence, not independent native audit.
- Costs: O(NP) witness/views/folded parent producer plus all nested consumers in
  c_a/c_sc/c_lu/T_misc. No measured constant/bench claim or extra weight pass.
- Verifier: production no_std unchanged. Schemas, lengths, roots and canonical
  limbs are checked. Arithmetic assemblers confer no acceptance; full verification
  rejects false children even when all parent equations hold.
- Glossary/history: append-only Draft/accounting evidence; original task status
  and criteria unchanged. Public S-byte/mask MLE gets10000 random-point checks.
  Physical/model-source ownership, native and private integration remain open.

I tried to break it with an M31 whole-word alias and fractional field carries,
and the control Carry:SourceCopy:RoundSumMismatch rejected it. Separate actual
quotient/remainder consumers reject -128 and an excessive half-tie remainder
while every parent Boolean-row equation holds.
