# Eq-factored zerocheck and univariate skip (Q19)

Question: which schedule and final obligations complete E3-03? The affected
terms are c_sc and T_misc. Kill criteria: treating the hybrid final as an MLE,
dropping slice claims, excluding zero challenges without accounting, or
accepting false public rows. No timing or improvement claim is made here.

Primary source: [Angus Gruen, ePrint 2024/108, §§3,5–6 and Appendix A.4](https://eprint.iacr.org/2024/108).
We use the paper's weighted degree-δ rounds and bounded first skip. Full endpoints
avoid the paper's division by alpha_i. Integer interpolation nodes avoid an
unavailable power-of-two subgroup in M31. Original tensor slice evaluations
close the hybrid functional without a new commitment or an unimplemented PCS
interface. The [argument](../../formal/zerocheck.md) accounts for all challenges.

Reproduce: `uv run --locked --script research/zerocheck/check_zerocheck.py`.
`--write-vectors` regenerates the committed candidate bytes. The oracle reuses
independent Python field/transcript arithmetic, imports no core implementation,
and computes round polynomials from exhaustive residual sums. Public consumption
uses independent eq-weighted full-table evaluation, not the prover's folding.
The exact bytes, all claims, three SC records and final transcript states are
recorded for both fields, eq-only, partial skip and complete skip cases.

Checks cover degrees 0..4, m=0..4, all eligible k, full-extension data, fresh
false-row proofs, one-value skip/tail/unused-slice tampering, malformed shapes,
noncanonical limbs, invalid descriptors, node interpolation and zero/one endpoint
weights. A real A1 research continuation detects an omitted ZeroFinal through
one changed final value. For s=4,u=4, L_0 L_3 differs from L_1 L_2: the hybrid
weights cannot be eq weights at any two-coordinate MLE point.

Recommendation: accept A3/A5 after skill review; implement both strategies,
production consumers/controls and reference parity, then measure complete costs.
The s-fold final payload and original-table retention are explicit costs.
Research checks earn no NC, GPU, performance, independent-audit or profile credit.
