# Q22 — What does the streaming fallback actually promise?

Question: complete RFC-0006 §5 / RFC-0014 §4 without mistaking indexed input
visits for two physical reads or an input-excluding space formula for peak memory.
Terms at stake: c_sc/T_misc, retained input and working memory, source read bytes,
and T_witness when a source recomputes virtual tensors. INV-7 still forbids extra
weight passes without an RFC-0007 amendment.

Kill criteria set before the study: any A1 proof/final/continuation disagreement;
any omitted or duplicated input visit in a claimed logical scan; or a claim of a
universal two-pass budget that fails even the grid/tail lower bounds. No production
implementation may rely on an unresolved physical source or memory contract.

## Primary sources and the mismatch

[Dao, DeStefano, Bagad, Domb and Thaler, §5.2/Figure 2/Appendix C](https://quangvdao.github.io/papers/authored/speeding-up-sum-check-proving.pdf)
describe multiple round windows followed by a materialized dense tail. Later
windows emulate partially evaluated inputs from the original source using prefix
equality weights. Their schedule has time-constrained and space-constrained
phases; it is not a universal two-physical-pass promise. The paper's streaming
model assumes small-space enumeration. The lower-degree generalization and the
fixed nodes 0..delta used here require our own parity argument.

[Baweja et al., Time-Space Trade-Offs for Sumcheck](https://eprint.iacr.org/2025/1473)
study streaming prover tradeoffs and distinguish ordinary interactive sumcheck
from a separate polynomial-oracle protocol. The latter is not an A1 strategy.
The named authors include Zitek-Estrada but not Rothblum. The existing shorthand
in RFC-0006 does not identify an exact algorithm or its source-access contract;
an append-only amendment must provide that contract rather than infer it from
the shorthand. No third-party prover code was imported.

## Reproducible algebra experiment

Run `uv run research/streaming/check_windows.py` from the repository root.
The script reuses the existing research field/transcript/public-consumer oracle;
it is not an independent end-to-end implementation. It builds each window by
direct Boolean interpolation in K, without the paper's optimized product engine.

For S completed challenges and window width w, form
`q(X) = sum_z P(f_0(r[:S],X,z), ..., f_(a-1)(r[:S],X,z))` on the grid
`{0,..,b-1}^w`, where `b=max(2,delta+1)`. Every factor is multilinear and P has
degree at most delta, so q has individual degree at most delta. Grid interpolation
and summation over remaining Boolean window coordinates give the original A1
round polynomial. This remains true after every challenge by induction. The
tail materializes every original f_i at the complete prefix, including unused
inputs. All original final obligations and their order therefore survive.

The 60 directed cases cover QM31/OM31, degrees 0..4, non-base inputs and
coefficients, repeated/mixed factors, zero coefficients, constants, unused inputs,
zero-dimensional instances, one/two windows, and empty/nonempty dense tails.
They compare every round, final value, challenge point and continuation with dense
A1 and check acceptance by the original public consumer. Ten cases alter exactly
one unused tail value after all rounds: all round messages stay equal and the
consumer rejects ClaimMismatch. This earns no production NC credit.

Every window visits each original `(input,index)` once, and final materialization
does the same: `a*N*(number_of_windows+1)` logical reads, `N=2^m`. The script records
and checks the complete visit multisets. It also checks that access order can be
nonsequential. It retains reference inputs, full visit logs and temporary lists;
it is expressly not a streaming memory implementation or an RSS measurement.

## A concrete budget obstruction

For this evaluation-grid family, one prefix of width k followed by a dense tail
requires at least `b^k` grid elements and `a*2^(m-k)` tail elements, even before
scratch, retained capacities, proof, source buffers or transition overlap.
For `m=20`, `a=3`, `delta=4` and separate limits of 1024 elements on each object,
no k satisfies both inequalities. The script exhausts every possible k.
This is an algebraic counterexample to a universal one-window fallback, not a
lower bound against every conceivable two-pass algorithm.

Multiple windows address the grid/tail tension at the price of more source
visits. They do not by themselves prove sequential storage access, bounded source
buffers, efficient recomputation or preservation of the one weight pass.

## Recommendation and remaining gates

Amend RFC-0006 A6 and RFC-0014 A1 together. Keep E3-05 blocked on those Draft
contracts until source layout/rewind/recompute behavior, integer window selection,
capacity-inclusive peak bounds, transition lifetimes and exact error behavior
are specified and reviewed. Do not replace the advertised fallback with an
unaccounted full-input rescan per round. A one-window specialization may be called
two logical visits only when its complete budget fits; physical reads need their
own evidence. No universal impossibility or optimality claim is made.

Acceptance must retain production A1 reference parity, original claim consumption,
actual misuse controls, a test of the real memory bound, and clean-source complete
cost/memory ledgers including the source and consumer. No timing, throughput,
physical I/O, GPU, soundness-profile or inference result is measured here.
