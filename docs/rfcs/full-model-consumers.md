# RFC-0025 operation and consumer inventory

Status: Draft. Part of [RFC-0025](RFC-0025-full-model-cqis.md), Q26/E5-03b.
This inventory defines required numerical/source obligations. It is not an
Accepted proof plan, transcript schedule, source-fixation construction or native
consumer implementation. Every row below remains mandatory in the final lowering.

## 1. Authority, expansion and ranges

Model fixes family, layers, all physical roles and numerical choices. Scales and
Registry supply independently authenticated parameter/table definitions. Bounds
is derived from those objects, using context capacity n and full format ranges.
An actual request fixes its real token count N<=n and public positions, masks,
prompt/continuation boundary, decoding inputs and stopping condition. It cannot
tighten a bound using observed values. Actual stage geometry/zero padding is
derived from that authenticated request; arbitrary supplied dimensions reject.

Operation order is fixed below. A named operation covers every real position,
head/group/channel of its declared shape, even when identical numerical parameters
or records repeat. Each layer retains its own role identity. Actual reductions
are stacked across those axes under RFC-0006; this inventory does not authorize
independent per-layer transcript loops. Grouping may not lose original layer,
head, position, block or channel provenance.

Every field-valued integer identity requires a complete static range on both
sides and a difference in (-p,p), or its complete byte-column/carry proof. Every
wide word includes sign, all low/high bytes, whole range and boundary carries.
A range established by an actual dominating lookup may be reused only for that
exact owned source and view. A table id, numerical output, claimed root or parsed
bound record supplies no range evidence. A multiply-by-zero cannot erase a
source join, configured parameter, high-byte requirement or binding edge.

When several reductions emit claims on one virtual tensor, the prescribed batch
consumer must merge those claims before that tensor's producer runs. Preserve
the exact point objects and original source owners at all joins. No rehashed
metadata, relabelled tensor or equal numerical value establishes that identity.
Physical source verification, private/virtual fixation, range discipline and
point linkage are actual E3/E4/E6/E7/E8 prerequisites, not properties of this table.

## 2. Complete fixed model expansion

Begin with `embedding`: bind every input token and absolute position, gather
token codes/scales and, for GPT-2, learned-position codes/scales. Apply the one
aligned rounding into R_0. R_0's committed cut must be the same value consumed
by the first norm; a separate numerical reconstruction is insufficient.

For layer l in increasing model order the semantic operations are:

1. `norm1`, then whole-row `convert.first`.
2. `project.Q`, `project.K`, `project.V`, each with its original required bias
   for GPT-2. Llama then has `rotate.Q`, `rotate.K`; GPT-2 has no rotation.
3. Whole-row `convert.Q`, `convert.K`, `convert.V`. Head/group views inherit
   these exact scales. There is no independently converted head row.
4. `attention.score`, `attention.maximum`, `attention.exp`,
   `attention.probability_sum`, `attention.weighted_values`, optional fixed
   `attention.block_round`, `attention.global_sum`, `attention.normalize`,
   `attention.assemble`, then whole-row `convert.attention`.
5. `project.O`, then `residual.mid` with the incoming R_l.
6. `norm2` on that middle residual, then whole-row `convert.second`.
7. `project.up`; Llama also has `project.gate`. GPT-2 applies tanh-GeLU to up;
   Llama applies SiLU to gate, then `gated_product` with up. Whole-row
   `convert.ffn` consumes the int16 activation or the exact int32 product.
8. `project.down`, then `residual.out` with the same middle residual, producing
   the next committed residual cut R_(l+1).

Finish with `final.norm`, whole-row `convert.final`, `project.head` and the
selected decoding relation on the appropriate previous-position logits. The
head is unbiased in both mandatory families; GPT-2 references physical token
record zero, while Llama references its distinct physical head record.

The numerical role counts are: one embedding; (6L+1) GPT-2 or (7L+1) Llama
projections; 7L+1 row conversions; 2L residual alignments; 2L+1 norms; one
activation per layer; L gated products only for Llama; two rotations per Llama
layer; and every listed attention operation in each layer, including block
rounding exactly when configured. Greedy or sampled decoding is explicit.
The absence of a family-specific role is prescribed by Model, never chosen by
the supplied collection. Norm/activation/function identities retain every role
even when their unique Registry entries are deduplicated.

## 3. Required relations, sources and consuming dependencies

| Operation | Required source, arithmetic and branch checks | Consuming implementation dependency |
|---|---|---|
| Physical matrix/vector | Complete expected record, symmetric code or int16 vector ranges, exact physical layout, scale association, original artifact/passport/root and source-map transform. No equality-based alias except prescribed tied token/head. | E5-03 preparation; E6 configured source derivation; E7-02 weight source/pass scheduling; E4/E12-05/E14-02 PCS/passport/hash binding. |
| Embedding/position | Token< v, position< n; both original row gathers and row mantissas/exponents; one exact aligned sum/round; int16 result; same R_0 cut. A learned position is a learned source, not a public RoPE coefficient. | E7-08 gather/LM head, new wide rounding, E6/E8 input/cut joins. |
| Norm source and statistic | Original residual row and gain/bias roles. RMSNorm: exact sum of X². LayerNorm: same original X in S=sum X, Q=sum X², C=dX-S and V=dQ-S². Never independently supplied/rounded mean or RMS substitution. | E7-03; original source/range producers and new LayerNorm statistic/centered consumers. |
| Norm reciprocal | N/P from those statistics and configured positive epsilon; same bounded a in both factors; full A=M D+R, strict R<D, M in [16384,65535], original selected rsqrt membership and J range. No generation-only lookup substitute. | E7-03 arithmetic, E3-07/E3-08 configured table/lookup/source closure, and required new LayerNorm consumers. |
| Norm output | Original X or C, original gain, same J/a, product signs/zeros and full-width shifts. LayerNorm includes the original bias before its single rounding. All output ranges and same row conversion source. | E7-03 wide output/affine consumers; E6 function/role binding. |
| Row conversion | Signed source, canonical absolute values, attained first maxabs, all comparisons; dynamic exact ceiling 0<=127s-M<127 and zero iff M=0; zero codes/no division at s=0; otherwise signed single rounding, code range [-127,127]. Static mode binds its exact scale and rejects overflow. | E7-09 attainment and E7-01 conversion; E6 view/scale source binding. |
| Projection | Same converted row codes/scale and original matrix channel codes/mantissa/exponent; exact dot and ranged accumulator; complete wide scale product; optional original bias and its units; one signed rounding and output range. | E7-01 signed matmul, E7-02 stacked weight phase and required configured wide affine rounding; E6/E8 joins. Existing narrow Requant cannot substitute. |
| Rotation | Actual absolute position, pair layout/width and group/head coordinate; complete expected coefficient definition/data; both signed products/sums and one Q14 division/rounding; unchanged tail and complete int16 output. | E7-04, E6 public-MLE/padding derivation, actual public coefficient consumer. |
| Score | Original Q/K code views, inherited per-row scales, GQA group floor(t/(h/g)); exact dot and dyadic multiplier; int32 range, common exp-input units, full signed rounding. | E7-06 score arithmetic and original projected-source consumers. |
| Mask/maximum | Verifier-owned causal position selector; every real query has its own unmasked key. Maximum is attained at an allowed key, dominates all allowed scores and uses the first tie. Unallowed/padded rows cannot enter selection or lookup. | E7-06 mask/max and E3-06/E6 public-mask/position closure. |
| Exponential | Same score minus the same attained maximum; complete inclusive domain; selected FunctionId/RepresentationId; all hi/lo/correction or direct memberships, terminal-index condition and exact integer recombination. Masked probability is zero. | E3-07/E3-08 lookup/registry and E7-06 exp/range/source composition. |
| Probability sum | Sum of those exact masked probabilities; all local/global source links and exact wide carries. Positive Z comes from an allowed attained maximum with exp(0)=2^E, not an asserted nonzero flag. | E7-06/07, shared maximum/exp/row-sum consumers. |
| Weighted values | Original V code and its row scale in the same units, same masked probability, every per-head/group/channel product. Absolute 1024-key blocks include masked zero slots; no key compaction. | E7-06/07 weighted-source and restored-scale consumers. |
| Block/global sum | Configured exact/block mode; in block mode each full signed partial has the configured drop, tie rounding and int16 bound. Global sum binds every configured absolute block, including all-zero blocks, signs and high carries. Exact mode has no intermediate block rounding. | E7-07 full block/global arithmetic and source closure; no advice cut inferred. |
| Attention normalization | Same global T and positive Z, exact configured numerator/divisor factors, signed quotient/remainder, strict division and half-away increment, int16 output. All heads assemble in fixed order before whole-row conversion. | E7-06/07 wide normalization/output and E6 head/row view binding. |
| FFN activation/product | Actual up for GPT-2 tanh-GeLU or actual gate for Llama SiLU; exact configured membership and units. Llama product uses that SiLU output and actual up without narrowing; signs/zero/ranges reach the same int32 row conversion. | E7-05 gated product and required GPT-2 activation consumer; E3-07/E3-08 tables; E7-01/09 conversion; E6 FFN-family/source binding. |
| Residual alignment | Original two signed int16 sources in their actual fractions, complete aligned sum with one rounding, target int16 range and next norm's units. Middle residual remains virtual; only the named outer R_l is a cut. | Required aligned arithmetic and E7-10 residual/RLC glue; E6/E8 residual/virtual source closure. |
| Final/head | Same final R_L, original norm/gain/bias, whole-row conversion and prescribed physical head/tie; all vocabulary channels and shared logit fraction. | E7-03/E7-08, E6/E8 output and tied-source scheduling. |
| Greedy | Original previous-position logits, ranged chosen token, least id attaining max and every ordered comparison, prompt boundary and exact stopping condition. | E7-08, E6/E8 request/logit/output linkage; NC-0107. |
| Sampled | Same logits/maximum, exact temperature and configured exp outputs; full vocabulary permutation/order, every prefix, minimal inclusive top-p boundary, positive retained mass, exact CDF quotient/remainder and strict selected bucket. | E7-08 sampled reduction plus E3/E7 arithmetic/table/source consumers. |
| Seed and stop | Original request's seed commitment, all exact draw hashes and absolute positions, same selected token, generated EOS included, prompt EOS ignored, maximum_new/context bounds and exact stop cause. | E7-08/E13-04 and actual E8/E14 request/hash/wrapper consumers; NC-0108, complete H accounting and privacy obligations. |

Every listed dependency denotes required implementation work. It is not a claim
that a same-named existing primitive already consumes these sources, proves all
the integer relations or supports its full dimensions. Any missing Accepted
protocol/source schedule must be supplied before production instantiation.
The current E7-03 title covers RMSNorm, and E7-05 covers the SiLU/gated path;
their names do not silently grant LayerNorm or GPT-2 activation coverage. The
acceptance DAG must explicitly add that work and the new aligned affine/position
relations. E13-04's original top-k extension remains required separately; this
temperature/top-p contract does not complete it.

## 4. Cache and stopping consistency

Cache storage retains the exact K/V codes, row scales, absolute positions and
authenticated configuration. It may not recompute per-head scales, change rotary
pairing, remove an absolute block, renumber a key or substitute a different model.
The dense targets keep the complete prefix. Full/cache equality is checked using
the same integer operations, including evaluation of the returned EOS token;
it is not an alternative proof statement or an exemption from intermediate joins.

The request's real continuation is exactly the selected sequence: no continuation
beyond the first generated EOS and no unexplained early stop below maximum_new.
At maximum_new=0 the output is the prompt with limit reason. Prompt plus configured
maximum_new fits context capacity. Every generated token is derived from logits
at its previous absolute position. Output/tokenizer/traffic commitments remain
separate authenticated boundaries; numeric token ids alone cannot prove text I/O.

## 5. Acceptance and costs

The final static collection must cover this entire expansion and all shapes,
ranges, source views, branches and selectors, with canonical closed fields and
independently derived counts. A family-name list or correct collection hash is
insufficient. The complete proof plan additionally binds actual accepted consumers,
owned sources, transcripts, conditional losses and resource schedules.

This inventory adds no challenge, loss record, cut, profile or measured constant.
Preserve the complete original H/FS/Q12/Q29/privacy accounting and one physical
weight pass, including tied token/head. Charge each real arithmetic/lookup/source
consumer to its T_witness/c_a/c_lu/c_x/PCS terms and all preparation to T_misc.
Unimplemented source, byte, mask or branch work is not zero-cost work.
