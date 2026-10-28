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

Checks cover 130 honest cases with degrees 0..4, m=0..4, all eligible k, full-extension data, fresh
false-row proofs, one-value skip/tail/unused-slice tampering, malformed shapes,
noncanonical limbs, invalid descriptors, early weights, node interpolation and zero/one endpoint
weights, plus empty zero/nonzero constant relations. An A1 research continuation detects an omitted ZeroFinal through
one changed final value. For s=4,u=4, L_0 L_3 differs from L_1 L_2: the hybrid
weights cannot be eq weights at any two-coordinate MLE point.

Recommendation: accept A3/A5 after skill review; implement both strategies,
production consumers/controls and reference parity, then measure complete costs.
The s-fold final payload and original-table retention are explicit costs.
Research checks earn no NC, GPU, performance, independent-audit or profile credit.

The vector set now records every one of the 130 honest cases, including the
verifier-owned descriptor/tables and the first challenge after ZeroFinal. These
inputs support production parity tests; the research checks still earn no NC credit.

E3-03 now adds a shared [314-case decision corpus](corpus.jsonl). Regenerate with
`uv run --locked --script research/zerocheck/check_zerocheck.py --write-corpus`;
verify with the same command using `--verify-corpus research/zerocheck/corpus.jsonl`.
The Rust `zero_corpus` example calls the actual public verifier and, for accepted
cases, compares the actual prover's proof. Both gates compare exact errors, every
ordered original slice claim, all three SC records and the next challenge.
The corpus includes fresh false rows (including zero-sum residuals), changed
coefficients/ids/order/dimensions/skip, short/long proof dimensions, canonical
field parsing, public shapes, unused tables/slices and empty/constant relations.
Complete-skip proofs disclose every original slice; changing an id or term order
can preserve a true assertion and its proof while changing the transcript and
metadata. Those cases require acceptance and exact updated receipts, not rejection.
These checks add no NC credit and complement the seeded reference comparisons below.

The CPU reference test now checks 1,000 seeded cases per polynomial degree 0..4
in each of QM31 and OM31 (10,000 total). It computes residual sums directly from
original slice MLEs, without dense hybrid construction or tail folding. Cases
cover every eligible (m,k) through m=4, full-extension and Boolean tables, mixed
and repeated factors, zero coefficients with conservative degrees, term ordering,
constants and unused inputs. Both modes must match proof values, every original
claim must pass public consumption, and prover/reference/verifier continuations
must agree. Both control/accounting gates require each field's named test to run;
a missing-field-test mutation must fail. This is finite algorithm parity evidence;
complete prover/consumer and memory measurements remain E3-03 requirements.
