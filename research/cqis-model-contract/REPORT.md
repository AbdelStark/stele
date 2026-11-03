# Q26 — Complete model contract evidence

Task E5-03b; [RFC-0025](../../docs/rfcs/RFC-0025-full-model-cqis.md) is Draft.
This work closes the numerical and identity gaps for the original GPT-2-small
and Llama-3.1-8B targets. It does not replace them with a smaller model.

Question: can the exact numerical choices and canonical authority chain cover
both complete architectures, with every arithmetic/source/range/branch/index
obligation enumerated before native implementation? The affected terms are
T_witness, c_a/c_x/c_lu and preparation T_misc. There is no measured performance
claim, new random challenge, production admission or new intermediate cut.

Kill criteria, recorded before the prototype: reject a proposed definition if
independent exact arithmetic disagrees, a rounded mean or separately rounded
bias changes its purported result, a static bound misses a legal intermediate,
or configuration can omit/substitute a required physical role or operation.
Do not treat agreement of a numerical prototype as proof-source authentication.

The first evidence checks the new exact-mean affine LayerNorm, single-round
biased projection and learned-position sum. The candidate uses integer sums,
products and shifts. The independent oracle uses rational centered variance,
an exhaustive exponent selection, monotone search for rsqrt and adjacent-integer
distance comparison for signed rounding. It does not call candidate arithmetic.
The oracle checks intermediate bounds even when final int16 conversion fails.
The candidate exposes no partial numerical output on a failed evaluation.

Run `python3 research/cqis-model-contract/check_numerics.py`. The result is a
correctness receipt with case counts and a SHA-256 corpus digest, not a benchmark.
The full model flows, complete codecs/identities, static-consumer expansion and
sampled-decoding integration remain E5-03b work. Existing research and frozen proof campaigns
are neither rewritten nor rerun by this checker. Native Rust/NumPy parity,
NC-0109, actual named-model inference/fidelity and complete private proof delivery
retain their original acceptance gates.

## Executed numerical evidence

Seed 2653 checks 10017 LayerNorm cases: 8339 successful complete results and
1678 matching output-range rejections. This includes 10000 randomized cases,
constant/alternating endpoint rows at dimensions 1, 2, 768, 4096 and 16384,
and both extreme epsilon ratios. All original-input statistics, normalization
branches and affine numerator bounds are checked even for rejected outputs.
The independent oracle agrees on the exponent, mantissa, reciprocal and every
successful output; the candidate's complete pre-rounding rational also agrees.

The same seed checks 10000 biased projections (2101 accepts, 7899 rejections)
and 10000 learned-position sums (2754 accepts, 7246 rejections). Explicit controls
cover both half-tie signs, zero scale with nonzero accumulator, bias-only rows,
int16 endpoints/overflow, invalid epsilon/shape/Boolean inputs, d=1 and one-round
addition. For X=[0,1], exact centering produces [-7,7] at the fixed checked
parameters. The affine norm example yields [0,1], where separately rounding its
norm result and bias would yield [0,2]. Two quarter-unit embedding/projection
terms round once to one half-unit's signed result, not two individually rounded
zeros. These cases distinguish the proposed numerical choices.

Complete retained corpus SHA-256:
`6c09367f05d6d28fb33967f331042c82a12fabbf9ca94b7fda383ef7653d3c9e`.
Candidate source SHA-256:
`b110c9d7ad7025e940114b5f043c32a77d18b2c677cdc893252abe2e15908541`.
Checker source SHA-256:
`3c6720a1a9e0a3b177b9e11d879b6f529d683c607e7e9a2b7801ca5fccea16f9`.
The initial successful check and the expanded all-outcome bound check are retained
separately. Both produce the identical corpus receipt; neither runs an earlier
frozen proof campaign. These counts and digests are correctness evidence only.

## Source-map and physical-role evidence

The [encoding appendix](../../docs/rfcs/full-model-encoding.md) now fixes the
physical role order, source transforms, exact fused partitions and tied-head
alias rule. The prototype checks this part only; the newly drafted full runtime,
scale/registry and artifact frames still need their own complete codec evidence.

Run `uv run --no-project --python 3.12 --with blake3==1.0.11 python -B
research/cqis-model-contract/check_source_map.py`. Seed 2671 checks 10000 maps:
5108 GPT-2 and 4892 Llama, including 2588 fused Q/K/V maps and 2569 tied-head
aliases. The independent oracle uses literal architecture role lists, struct
framing and row/column coordinate transforms. Complete bytes, decoded metadata
and extracted raw scalar arrays agree. Tests reject every strict truncation of
the selected complete fixture, missing/extra roles, fused-part/dtype substitutions,
partial partitions, unauthorized aliases, changed alias bytes, source-set errors,
noncanonical names/ignored ordering and Boolean pseudo-integers. A valid renamed
source changes its map identity; it cannot authenticate the original map.

The metadata-only named-shape cases retain 196 GPT-2 physical records and 291
Llama records, including all layers and physical roles. GPT-2's vocabulary and
dimensions agree with its [published configuration](https://huggingface.co/openai-community/gpt2/blob/607a30d783dfa663caf39e06633721c8d4cfcd7e/config.json);
Meta's [pinned architecture](https://github.com/meta-llama/llama-models/blob/0e0b8c519242d5833d8c11bffc1232b77ad7f301/models/sku_list.py)
and [model card](https://github.com/meta-llama/llama-models/blob/0e0b8c519242d5833d8c11bffc1232b77ad7f301/models/llama3_1/MODEL_CARD.md)
supply Llama's architecture/context. These are role-expansion cases only: no named
checkpoint is downloaded, converted, evaluated or proven by this checker.

Partitioning before quantisation matters. In a fused source with Q values 1 and
K/V values 2^30, the full-tensor maximum forces a shared exponent of 8 under
int8 conversion, making the Q codes zero. The separate Q matrix instead uses
exponent -22 and retains nonzero codes. This follows directly from the exact
minimal-exponent rule; source slicing is not a post-quantisation view choice.

Corpus SHA-256: `c8347908238b9f6a32ea46d8bb37181dedf32fc9f16029a174e50ccdf4db6c8f`.
Candidate source SHA-256: `8e649d9767bdf3570cf0a2c326b165ebb7d4a8a06079ad7849db5be8243b3c9f`.
Checker source SHA-256: `7720c62a1c415bd8a420c0082ab33356028d540c47f43799ba8720e8f410d099`.
Raw extraction deliberately precedes finite-scalar decoding: these tests do not
claim to revalidate container parsing, source authentication or quantisation.

## Sampled-decoding arithmetic evidence

The [decoding appendix](../../docs/rfcs/full-model-decoding.md) specifies one-round
temperature scaling, sorting by actual integer weights with vocabulary-id ties,
the minimal inclusive top-p prefix, floor CDF endpoints, and seed/draw framing.
Run `uv run --no-project --python 3.12 --with blake3==1.0.11 python -B
research/cqis-model-contract/check_decoding.py`.

Seed 2672 checks 10000 positive-mass weight arrays against a rational oracle that
computes ranks by comparisons and selects an explicit CDF interval. Every bucket's
fixed-point mass error is checked. The same corpus checks temperature arithmetic:
5938 cases succeed and 4062 reject the selected exp domain, matching independent
rational rounding. It also checks complete seed commitment/draw preimages and
low-word reduction. BLAKE3 is shared; this is framing evidence, not a second hash
implementation or a sampling-fairness claim.

Boundary controls cover exact top-p equality, equal-weight tie order, zero mass,
CDF boundary draws, maximum draw, nonreduced/invalid rationals, signed temperature
ties, inclusive exponential endpoints, and seed/position/type errors. A separate
1048576-token integer-weight case checks the legal empty bucket near the end of
the CDF. This is a vocabulary-sized numerical case, not a model forward pass.

Corpus SHA-256: `7514972d1c5d5270deb6b9cdd1be0e72f248da8fdaeefd5c4f7a730f98ad4f84`.
Candidate source SHA-256: `c67fdea7dc89728382a55452b4a1f772144f917a260a3cbb111817a5c87e7a44`.
Checker source SHA-256: `98263da7467b52fcc8e3ade42ec0f144aad573ae6d755b0e501f93b33c5e79cf`.
The weight-array helper is conditional on actual configured exp outputs; it does
not generate those tables or supply their lookup/source proof. Full exp/model/
request integration, seed-hash proof consumers, ledger/control review and complete
full/cache sampled decoding remain required before native delivery or acceptance.

## Affine and position static records

The [static appendix](../../docs/rfcs/full-model-bounds.md) adds closed records
for the configured affine projection and the single-round token/position sum.
The question is whether their entire integer relation can retain exact high
bits, including different weight exponents, cancellation, zero multipliers and
rejected int16 results. The original static-bound kill criterion applies: a
missed legal intermediate, supplied bound authority or lost source/branch fails.
No old RFC-0022 record, frozen source or historical proof campaign is changed.

Run `python3 -B research/cqis-model-contract/check_arithmetic_bounds.py`.
Seed 2673 checks 10000 configurations per schema. The independent scalar oracle
uses rational coefficients and their common denominators. The column oracle
multiplies cap polynomials in radix 2^40 to recover nonoverlapping coefficients;
the candidate explicitly convolves the cap arrays. A separate check constructs
actual maximal whole-word operands and verifies every integer column/carry.
Independent struct/word encoding matches the entire record for every case.

The sampled affine inputs produce 3923 in-range rounded outputs and 6077
out-of-range results; embedding inputs produce 3967 and 6033 respectively.
All numerator/offset bounds are checked in both outcomes. Successful outputs
also satisfy the quotient, strict remainder, half-tie gap and signed-output
bounds. These are arithmetic input cases, not complete model executions or proof
rejections. Source/row/lookup membership is still a consuming obligation.

The corpus reaches 2146-bit scalar values, 269 columns and a 43758-byte record.
A separate maximal-exponent-difference case retains those 269 columns and all
zero extensions. The appendix supplies domain-wide analytic bounds separately:
these observed maxima are not used as the certificate limits. Targeted byte
changes, truncations, suffixes, changed valid expected parameters, over-capacity
inputs, invalid shapes/exponents and Boolean aliases reject.

Corpus SHA-256: `0a5e8bc2b9a7c302da9203fb46e58327ecfa622682ef58d36f67bf1dc3eb8967`.
Original candidate source SHA-256: `0c69e8e448c4d00e5e2f5367ded4a0c3f5c0560bf7f533be909ebb0d6a0b5891`.
Checker source SHA-256: `b6b2ec4f3e27e30cfe4a1b1de1c2a773bc6ac8ad84d14b9e638b4ce1cd534882`.
The [full operation inventory](../../docs/rfcs/full-model-consumers.md) now names
the consumer dependencies across both architectures. The remaining families/
collection, runtime/outer codecs, native/source
consumers and original full-model delivery remain open. No NC/profile credit.

## Exact-mean LayerNorm static record

The static appendix §6 defines schema 3: 28 scalar bounds and 33 closed arithmetic
roles, with one complete record for all normalization branches. Each role retains
its exact operands, byte caps, whole bounds, carries and final zero. The same
original row feeds both S and Q, then centered C and variance V. The normalization
and output factors derive jointly from one a; the original gain, reciprocal and
bias reach the single final rounding. This remains numerical metadata, with
every actual source, range, tuple and lookup consumer required at native delivery.

Run `python3 -B research/cqis-model-contract/check_layernorm_bounds.py`.
Seed 2674 checks 10000 configurations across the full parameter domain, including
dimensions 1 and 16384. The independent oracle uses rational coefficients and
common denominators for the branch factors, polynomial multiplication for the
column bounds, and struct/word framing for the complete bytes. It also checks
actual source products and every integer column on rows represented by one/two
value groups with exact multiplicities summing to d. No smaller dimension is
substituted in those statistic/row-sum checks.

The sampled source coordinates yield 12262 in-range and 4452 out-of-range rounded
outputs; these are arithmetic cases, not model or proof outcomes. All upstream
source relations and bounds are checked in both outcomes, with the output
division/rounding roles checked on successful results. Separate cases attain
every a in [-23,9]. At d=16384, the statistic's largest side is 1073709311,
strictly below p/2; the capacity case reaches 21 columns. This field margin is
checked exactly, without floats or observed-data tightening.

All 10000 sampled configurations distinguish the actual Ubar(a) from global
Ucap. The checker binds the signed numerator to Ubar and verifies the exact
rational output before rounding. Replacing that offset by Ucap would change
the represented integer. The independent whole-column checks retain zero
operands, d=1, original sign endpoints, variable denominators and strict gaps.
Byte mutations, truncations, suffixes, changed valid Gb, non-reduced epsilon,
out-of-domain dimensions and Boolean parameters reject. These checks earn no
native negative-control or proof-admission credit.

The randomized record corpus reaches 55991 bytes, 166-bit scalar values and
21 columns. The separate analytic limits in the appendix, rather than these
sampled maxima, bound every supported configuration.
Corpus SHA-256: `2cabc658d1fae9d08fb6e1b6bdf358612f040b51a64b0a55ed9109d3e7ab67ce`.
Candidate source SHA-256: `37e0b0e4a05d2e24a07db3994a7841ebe95dfa7c6af7f1706ff9e783d4f82c09`.
LayerNorm checker SHA-256: `19623ad8c4042b20969c34a6f098ceccb81f9ac6bf789a9f2123cb880d2d7d51`.
It also imports the unchanged column/framing helpers from the affine checker
whose source hash is recorded above. The original numerical module and its
evidence are unchanged. Full collection/runtime identities, operation integration,
native parity, named-model fidelity and actual proof consumers remain required.

After adding the LayerNorm dispatch, the unchanged affine/embedding checker was
run on the same candidate hash above. Its complete 20000-record corpus, counts,
maxima and SHA-256 remain exactly those of the original qualification. The old
schemas retain their bytes; the new LayerNorm schema does not reinterpret them.

## Row, residual and gated flow records

The [flow appendix](../../docs/rfcs/full-model-flow-bounds.md) adds schemas 4–6
under the existing arithmetic frame. Their parameters come from independently
expected full-model roles. The row schema covers wide int16 and the exact
gated-product domain, with static scales through 65535 and 8454661 respectively.
It retains the first attained maximum, complete-row index/source association,
zero-scale semantics, strict remainder and signed output. The residual schema
aligns both original sources and rounds their sum once. The gated schema retains
the full signed product, including 2^30, before the same complete-row conversion.
None supplies a native proof consumer or changes an existing advice cut.

Run `python3 -B research/cqis-model-contract/check_flow_bounds.py`.
Seed 2675 checks 10000 configurations per schema, comparing exact rational
coefficients, polynomial column derivation and independent full-byte framing.
Actual maximal whole operands and every column/carry are checked. Sampled row
inputs use up to three constant groups whose exact counts sum to the configured
dimension; endpoint coordinates cover both sides of the selected first maximum.
Those cases retain the complete declared row, including dimension 16384.

There are 8015 entirely in-range sampled rows and 1985 out-of-range static rows,
including 535 dynamic zero rows. Sampled residual coordinates yield 3568
in-range and 6432 out-of-range outputs. Every upstream source/offset/sign bound
is checked in both outcomes; target-constrained division roles are checked on
successful results. These are conditional integer cases, not native rejection
controls or full model executions. Separate endpoint cases cover high gated
static/dynamic scales, both half-tie signs, all-zero rows, cancellation, single
rounding and the positive gated endpoint. A later tied maximum requires a
negative gap at its earlier source index and cannot satisfy the specified range.

The shared word-predicate study checks 10000 cases: 8329 valid bytewise range
relations and 1671 impossible strict comparisons. Among valid ranges, 3297
words are zero. Byte sides stay <=511, carry bits stay Boolean and the final
carry is zero. Nonzero words retain their first nonzero byte and bounded index.
The explicit 255+1=0+256 case demonstrates why discarding the final zero carry
would admit an invalid bound. These arithmetic checks do not instantiate the
actual source/range/selector reductions required by the proof plan.

The randomized schema maxima are 16576/17096/7244 bytes and 5/6/5 columns for
row/residual/gated respectively. The analytic residual domain includes seven
columns; sampled maxima do not choose any certificate capacity. Byte mutations,
truncations, suffixes, different valid expected dimensions, invalid scale/mode
combinations, Boolean fractions and unsupported dimensions/fractions reject.
Corpus SHA-256: `2930613cd1d3a64d9281124553bb015a8b84ae407227214bf69f63d7235d189f`.
Flow candidate SHA-256: `cf644436212873df0f30e9573b0cc873cd01c476fe3a29122873ba675b2d0923`.
Flow checker SHA-256: `f2d559ef76dac4bc1e11a0d16482b206eeab766102a741d30e48d42b6ca1c670`.

The private shared encoder was extracted without changing its serialization
body or the earlier derivations. An exact syntax-tree comparison against
`d1477bb8350a4b9ab58d8886e134124c7719eb58` checks both properties and the complete
parameter/argument transfer. Nine affine/embedding/LayerNorm boundary records
also match their independent byte oracles, including extreme exponents and
dimension 16384. Their corpus SHA-256 is
`f8c3040b9b2bb5aa3f3958d6c2859cc966ffcf68ea6cfff60e67d67748fc0f03`.
The shared candidate now has SHA-256
`017a00724d79f6d25a48efc6e1bc5f66e5db0d25936a85f4068533837c3d24bb`.
The numerical and earlier checker modules are unchanged. Prior full-corpus
receipts retain their original source hashes; the extraction qualification is
separate. No historical proof campaign was rerun. Remaining bound families,
collection/runtime identities, native consumers and all original named-model
delivery gates remain open.

## Rotary and attention-input records

The [attention-input appendix](../../docs/rfcs/full-model-attention-bounds.md)
adds schemas 7–9. Rotary retains the original head/pair/position mapping,
coupled coefficient envelope, application rounding and full source indices.
The score schema retains RFC-0004 A6's static worst-case int32 admissibility,
whole-row conversion policies, GQA views and every signed-output byte. The
maximum schema binds the causal first maximum, original masked scores,
complete differences and the inclusive ascending-domain exp index. Product
hi/lo splitting still uses the same original difference under RFC-0021.

Run `python3 -B research/cqis-model-contract/check_attention_input_bounds.py`.
Seed 2676 checks 10000 complete records per schema against independent rational
coefficient/policy bounds, polynomial columns and full-byte framing. Another
6727 candidate score configurations fail the independent static bound and
reject with ScoreBound in the candidate; zero actual inputs cannot rescue them.
The successful score configurations include 4274 zero worst-score bounds.

Score input cases numerically convert complete Q/K rows, preserving their
scales before selecting a query head and its actual GQA group. They compare
every restored product, division and signed word to exact rational rounding;
3037 sampled pairs include a zero scale. Maximum cases retain the configured
complete dense key span using constant intervals, split at causal/selection
boundaries. They produce 7901 in-domain cases and 2099 domain failures. These
are conditional arithmetic cases, not proof-source authentication or inference
on a named checkpoint.

Rotary application uses nearest Q14 values of exact rational unit-circle
points, then exact signed application rounding. Among 20000 sampled output
coordinates, 12880 fit int16 and 7120 overflow; a native complete operation
must reject if any coordinate overflows. These inputs exercise the coupled
envelope, not configured base/linear/llama3 frequency generation. Of the
randomized records, 614 have coefficient pair indices above p. The explicit
largest supported shape retains pair index 2^33-1 and payload byte index
2^35-1 without materializing the coefficient table. No research materialization
cap is substituted for the full semantic domain.

Boundary cases retain a width-one score and a denominator at shift -122,
inclusive exp index 2^31, complete high zero bytes and an int32 score change
of exactly p. The latter has equal field residues but unequal required word
results. The complete masked/first-tie/index joins remain mandatory at actual
consumers; these arithmetic examples earn no native negative-control credit.
Byte mutations, truncations, suffixes, changed valid fractions, absent/odd
rotary widths, invalid GQA groups, domain bits and Boolean fractions reject.

Randomized maxima are 10708/21408/9485 bytes and 5/15/5 columns for rotary,
score and maximum respectively. The appendix derives capacity limits from
all permitted parameters separately. No sampled maximum supplies authority.
Corpus SHA-256: `4cfdd242129bb1f6bc457a598eadd32e190a74a45e0ba3115e97145878f8d413`.
Candidate SHA-256: `dea9a5014bc410ac9cc963d7262711e84d74b26dc7d2091538ce593c96e674ec`.
Checker SHA-256: `dfcc449ba960707c5c7491187d05b296c35dcc870e8656dae89138581118c5f2`.
Shared arithmetic/numerical/checker helpers are unchanged from their earlier
qualified versions. Canonical frequency generation, exp/table/weighted/block/
global normalization consumers, collection/runtime identities, native parity,
named-model fidelity and complete private inference proofs remain outstanding.

## Exponential and activation records

The [function-bound appendix](../../docs/rfcs/full-model-function-bounds.md)
adds closed schemas 10/11. Exp retains original difference/index words, exact
hi/lo splitting, quotient/remainder/correction arithmetic, selected component
order and complete real/padded table addressing. Activation retains the full
FFN width, original signed int16 input/output words, i32 sign extension, row
ordinal and configured function. Whole-table generation/admission and actual
lookup/source consumers remain mandatory; these records cannot supply them.

Run `python3 -B research/cqis-model-contract/check_function_bounds.py`.
Seed 2677 checks 10000 configurations per schema against independent polynomial
columns and complete struct-based framing. It also checks actual maximal
operands, every carry and final zero, plus selected numerical point entries
from the unchanged RFC-0021 rational certifiers. Those point entries supply
data for recombination/source arithmetic, not new full-table validation.

The exp cases cover 3301 direct, 3340 product and 3359 corrected records,
including 1429 masked cases and 438 product/corrected configurations with Q=1.
Selected corrections are -1,0,1; the complete static operand/column checks
retain Coff up to 3 (C up to 2), independently of sampled corrections. The
activation cases cover all five accepted definitions: 2008 sigmoid, 1976 SiLU,
2004 softcap, 2042 GeLU and 1970 tanh-GeLU. Of the selected entries, 9397
certify with int16 outputs and 603 overflow; no selected case reaches the
precision limit. Successful points do not certify their complete tables.

Boundary cases include B=31's complete delta/index and terminal hi/lo pair,
all real/table-padding endpoints, masked exp(0), and the exact maximum table
byte address 524349. A changed delta/index sum differing by p has the same
field residue but unequal required words. Every activation kind checks both
int16 endpoints, -1,0,1 and full width 16384. The source check compares signed
packing with complete i32 sign extension and demonstrates why unsigned W32
modulo p is the wrong signed lookup lift. SiLU/GeLU/tanh-GeLU configurations
with F=0,E=14 succeed at zero yet overflow at 32767. Sigmoid(0) is nonzero
even at E=0, so operation padding requires its disabled lookup selector.

Byte mutations, truncations, suffixes, different valid fractions, mutable or
oversized byte buffers, forbidden wide nearest/corrected domains, inactive or
invalid splits, Boolean fractions, excessive FFN width and invalid cap/kind
parameters reject. These are research controls and earn no native NC credit.
Randomized maxima are 30938/12223 bytes and 5/4 columns for exp/activation;
the appendix separately proves complete-domain capacities below 42000/16000
bytes. No sampled maximum defines those limits.

Corpus SHA-256: `a364b47658c12dceeba5eb3e0bf33f8910e3c41687b51899d530be44896a184a`.
Candidate SHA-256: `892aedae62336ecc33ef345cd42b260e71b54fa58d9c699041de2f3a18a65805`.
Checker SHA-256: `6c0043057afaf4f0d39606fbeea9a550881622552d85648b8a8ce183609210a8`.
The shared framing, numerical helpers and existing certified function modules
are unchanged; prior receipts retain their exact source scope. No historical
proof campaign is rerun. Weighted/block/global normalization, decoding bounds,
the full collection and outer identities, native consumers/parity, named-model
fidelity and complete private inference proving/verification remain open.

## Complete weighted attention and normalization records

The [weighted appendix](../../docs/rfcs/full-model-weighted-bounds.md) adds
schemas 12/13 with fixed radix 16. The full context domain remains 1..2^20,
with complete V-row policies and GQA coordinates. Exact sums retain the actual
S*Z offset. Block mode retains RFC-0004 A6's full 1024-slot static bound, every
absolute block, signed rounding, global probability/total joins and all raw
work when rounding erases a block. Normalization consumes the same total/sign/Z
with exact variable division, strict remainder, half ties and int16 output.

Run `python3 -B research/cqis-model-contract/check_weighted_bounds.py`.
Seed 2678 checks 10000 records per schema against independent rational policy/
rounding formulas, polynomial columns and complete framing. Actual maximal
operands exercise every column/carry. Another 1664 block configurations fail
the independent full-block bound and reject in the candidate. The accepted
configurations contain 5820 exact and 4180 block cases; 2723 block records
have static rounded bound zero. These are configuration/arithmetic checks,
not actual proof acceptance.

Dense numerical cases represent every configured key slot with constant
intervals split at the real-request, causal-mask, capacity and block boundaries.
Full V rows use a repeated three-coordinate pattern whose first coordinate
attains the complete-row magnitude, before selecting the actual GQA coordinate.
Interior identical blocks use counted runs; boundary blocks are checked
separately and all block counts feed the global sums. No keys or zero blocks
are removed. The probability vectors are conditional in-range inputs with an
allowed Q entry, not authenticated score/exp outputs. Thus this evidence does
not discharge actual function or model-source consumers.

Across these cases, 132868 nonzero blocks round to zero while retaining their
raw/source/remainder checks. Normalization produces 8630 int16 outputs and
1370 range failures. The checker also covers exact half ties, conditional
int16 endpoints/rejections, the full context/width endpoint, Dmax=2^64 and
drop=62 with a zero global bound. Capacity one still rejects a drop that fails
the full 1024-slot rule. A reachable boundary uses one allowed P=1 and original
V=127: block rounding R(127/8)=16 gives normalized output 128. Bounding its
quotient by Umax/Dmax=127 would reject it; the specified Dmin bound admits it.

Randomized record maxima are 37705/23185 bytes and 16/23 nibble columns for
weighted/normalization. The appendix proves separate complete-domain bounds
below 64000/36000 bytes and strict M31 column faithfulness. Byte mutations,
truncations, suffixes, changed valid source/output fractions, invalid GQA
groups, inactive drop and Boolean fractions reject. No native NC credit is
claimed. Corpus SHA-256:
`a61fdf5a04e69ba50abd391c255e534829b9754132e7e01a5825a17130284581`.
Weighted candidate SHA-256: `839e8b164432e0990e1997361cf0dfe886f258d397f85fc8a1e7e5b607463da5`.
Checker SHA-256: `153c2a7b34eb3f7a1d521df7e085f8057ad1a778f963354e9c73d24cff71ae85`.

The private cap/column/encoder helpers now accept the fixed radix selected by
their closed callers. Their default remains eight bits. Against `19cfdc2`,
exact syntax-tree comparison preserves every other declaration/body; replacing
the new default parameter with 8 and folding its constant expressions recovers
all three prior helper bodies exactly. Sixteen independently encoded boundary
records cover every earlier schema 1–11, with corpus SHA-256
`4480dc009f311424a9b77829304dcd8cc8308b6957c756f4fa2dc1d83f8b6477`.
Shared arithmetic SHA-256 is now
`cba19049f1775e8e193a932568af2873cf1373754873178d058df1776f8f35aa`.
Earlier full-corpus receipts retain their original hashes; no historical proof
campaign is rerun or presented as a current-source rerun. Original RMS-family
integration, decoding bounds, the full collection/outer identities, native
consumers, full named-model inference/proving/verification and benchmarks remain.

## Original RMSNorm obligations in the complete frame

The [RMSNorm appendix](../../docs/rfcs/full-model-rms-bounds.md) adds schema 14
without changing RFC-0021 §2.3 semantics. It retains complete original input/
gain words, the full squared statistic, epsilon numerator, normalized numerator/
denominator, exact remainder and selected reciprocal. The same original exponent
determines every normalization/output factor. Product signs, zeros, one signed
rounding and output range reach the subsequent complete-row conversion.

Run `python3 -B research/cqis-model-contract/check_rms_bounds.py`.
Seed 2679 checks 10000 complete records against independent rational factor
maxima, polynomial column arithmetic and full struct-based framing. Counted
coordinate groups represent exactly d original input/gain pairs for the
statistic. Exact Fraction arithmetic independently selects its exponent and
compares each represented output with signed half-away rounding. Reciprocal
point entries satisfy the original two-sided integer isqrt inequalities;
these point checks do not replace whole-table admission or a lookup proof.

All 10000 randomized statistics have nonzero division remainder, retained
without rounding. Among group representatives, 21412 outputs fit int16 and
2043 overflow; any overflowing coordinate rejects its complete operation.
The cases include 10181 zero products, 92 exact ties and 2586 negative products
rounded to zero. These are representative-coordinate counts, not full-model
inference results or proof acceptance counts.

Randomized exponents cover -13..8. Separate original-input/epsilon boundary
cases reach every a from -23 through 9, including the maximal-u32 epsilon
endpoint. Further cases cover a successful exact left shift, positive/negative
half ties, zero input with negative gain, negative input with zero gain,
full dimension 16384 and both signed-int16 source endpoints. The maximum
statistic side is 1073709311, retaining RFC-0022's strict M31 margin. Canonical
table addressing retains the final byte 524349 and real mantissa row range.

An explicit tuple combines individually valid factors from different exponents;
it belongs to no joint tuple. This demonstrates the need for the original shared
index, not rejection by a native consumer. A high-word change by p likewise
preserves a field residue while changing the required integer. Byte mutations,
truncations, suffixes, changed valid gain fractions, mutable/oversized frames,
unsupported dimensions/output fractions, Boolean fields and invalid epsilon
encodings reject in the research validator. They earn no native NC credit.

Randomized maxima are 46719 bytes and 19 columns; the independent domain proof
allows 20 columns and bounds the complete record below 76000 bytes. These
sampled maxima do not select capacities. Corpus SHA-256:
`f9d53fc7a240080ed463d40cd829e64888c75fb3a38bddee44e171fb8afe126e`.
Candidate SHA-256: `b90a408989f4c5ac32f9397b5199f32166641af94498b09e0b62f71efd498402`.
Checker SHA-256: `c4a9d7924c8d2d157b05903ef9f5e60ba93d229a30e6d8b3432fd448ba85fec5`.
Shared arithmetic/numerical/checker helpers are unchanged from the preceding
qualified versions. No historical proof campaign is rerun. Decoding records,
complete collection/outer identities, actual native consumers/parity and full
named-model inference/proving/verification/benchmark delivery remain open.

## Full-vocabulary decoding static records

The [decoding-bound appendix](../../docs/rfcs/full-model-decoding-bounds.md) adds
schemas 15–17 for original logit maxima, one-round temperature and complete
sampled selection. It preserves the full permutation/inverse, source weights,
every prefix, least inclusive top-p boundary, original retained mass, exact CDF
division and strict chosen bucket. Hash bytes reconstruct the full draw word;
seed/hash/request ownership remains a separate mandatory consumer.

Run `uv run --no-project --python 3.12 --with blake3==1.0.11 python -B
research/cqis-model-contract/check_decoding_bounds.py`.
Seed 2680 checks 10000 configurations per schema, with vocabulary sizes 1..32
for complete randomized witnesses. Independent rational rounding, rank-based
selection, polynomial column arithmetic and struct framing agree. Actual source
values exercise every role's byte columns and carries. The selection vectors
are conditional exp outputs with an attained Q; they do not prove the selected
exp table or its original logit sources.

Temperature has 4547 successful vectors and 5453 matching exp-domain failures.
All original numerator words are checked even on failure. Across these vectors,
14407 nonmaximum logits round to zero. Sampling checks 106207 unretained real
ranks with canonical zero CDF auxiliaries while preserving their original
weights, order and prefixes. These are arithmetic counts, not proof results.

A separate full 1048576-token fixture checks every permutation entry and CDF
endpoint using a linear exact oracle. Its last three endpoints are
`4294967295,4294967295,4294967296`: the positive penultimate weight has an empty
bucket, and maximum draw selects the final token. Complete counted original
weights feed the sum's byte-column check; endpoint product, bucket and four-byte
draw roles are checked separately. This fixture does not claim every role's
byte columns were replayed at every rank. Other boundary cases cover singleton
vocabulary, ties, int16 endpoints, exact/failed exp endpoints, top-p equality,
zero-weight suffixes, full configuration domains and field-congruent draw words.

Randomized record maxima are 7527/14027/31187 bytes and 3/10/7 columns. The
separate analytic proof bounds records below 12000/20000/40000 bytes; selection
at full vocabulary retains nine columns. Byte changes, truncations, suffixes,
changed valid expected fractions, mutable/oversized input, invalid vocabulary,
nonreduced/invalid rationals and Boolean fields reject. No native NC credit.

Corpus SHA-256: `f40da432521ab5038450c1cb1ea3f5d3af1c3ffa809bb3b1ef11ed9b4815766a`.
Candidate SHA-256: `8a03dc21173b69ffb16959fc97c85ea4a0b19526c23a9cbb1216865fdfb96a13`.
Checker SHA-256: `9809815ff5600acd58524233b85b42bcb4767be48d68f22e24ade42669efb40f`.
All shared helpers and earlier numerical sources are unchanged. Exact stopping
and outer request schemas, the full collection/consumer plan, native controls,
full model parity and original proving/verification/benchmark delivery remain.

## Request boundaries and exact stopping

The [request appendix](../../docs/rfcs/full-model-request.md) adds schema 18,
canonical RequestBoundary/TokenIO frames and an explicit sorted EOS set. It
retains the first generated stop token, ignores prompt EOS, gives EOS precedence
at the limit and requires limit reason for zero requested tokens. The same
original token sources, full previous-position logits, seed/draw hashes and
complete returned-token model states remain required consumers.

The multiple-EOS choice follows Meta's pinned tokenizer/generation sources;
GPT-2 retains its named singleton EOS. The appendix cites those exact sources.
TokenIO's length/reason framing and public-policy subrecord are proposed through
RFC-0001 A1, without editing Accepted text. The complete public-input/passport/
private-commitment frames remain separate acceptance work.

Run `uv run --no-project --python 3.12 --with blake3==1.0.11 python -B
research/cqis-model-contract/check_request_bounds.py`.
Seed 2681 checks 10000 configurations across the full vocabulary/context domains,
using short complete prompt/continuation witnesses per randomized request.
Independent replay, struct framing and polynomial byte-column arithmetic agree.
There are 4965 greedy and 5035 sampled requests, 4426 limit stops and 5574 EOS
stops. In 7958 cases the prompt contains EOS; 397 terminate at EOS exactly at the
token limit. No numerical logits, seed preimage or model are evaluated by this
boundary checker; valid sampled metadata does not authorize a sampled token.

The sparse public EOS-mask formula matches an independent dense-table fold on
10000 random M31 points, with non-power-of-two vocabulary padding included.
Singleton and full-vocabulary Boolean endpoints are checked separately. This
does not implement a native public-source handle or establish extension-field
and profile parity. The full context fixture round-trips 1048576 tokens; the
full EOS-set fixture round-trips 1048576 ids. Their exact maximum frames are
4194337 and 4194381 bytes respectively, without the old entry-product cap.

Controls reject altered prompt prefixes, early limits, continuation after EOS,
wrong stop reason, Boolean pseudo-integers, invalid EOS sets, inactive/missing
seed data, every truncation of the selected fixtures, suffixes, malformed
counts and a u32 token change congruent modulo M31. Splitting the same flat
tokens at a different prompt boundary changes io_digest. Changing a limit while
retaining an earlier valid EOS changes RequestBoundary even when TokenIO is
identical; the public statement must bind both objects. BLAKE3 is shared with
the independent framing check, not independently implemented here.

The record reaches 28231 bytes and four columns. The appendix proves an analytic
capacity below 40000 bytes and strict field faithfulness. The first complete
run passed; a parser review then moved prompt/limit validation before EOS
materialization. The repeated focused run retains the same corpus and counts.
Corpus SHA-256: `68af41d1ddae474998d25fd99feb1ab0991b90742e8f2ef21ec0af4146a3588c`.
Final candidate SHA-256: `4f995ff7f0356a718f52755084d97e6e902bd840aa90a2cbc4034dcc8c1a246e`.
Checker SHA-256: `781d29115d5fe649e3a6160c4e33dae9f4a0e3e9d1a28900f81c32439efd689f`.
No historical proof campaign or shared helper is changed or rerun. The complete
bound collection, runtime/outer identity codecs, native model/proof consumers,
full-model fidelity, private PCS/ZK and benchmark delivery remain required.

## Complete structural Model codec

The [encoding appendix](../../docs/rfcs/full-model-encoding.md) now distinguishes
structural Model parsing from complete Registry/Bounds/source admission. The
codec checks every physical ordinal, shape and format, all norm gain/bias and
residual-unit joins, family-specific projection/activation/rotation choices,
complete policies and decoding metadata. It rejects conflicting representations
for one FunctionId. Successful parsing supplies no execution or proof authority.

Run `uv run --no-project --python 3.12 --with blake3==1.0.11 python -B
research/cqis-model-contract/check_model_codec.py`.
Seed 2682 checks 10000 complete Model frames, split equally between the two
families, with 4985 sampled configurations. Independent physical-role expansion,
struct framing and Function/Representation/TableId assembly agree byte for byte.
The oracle shares parameter constructors and BLAKE3, but does not call the
candidate encoder or its function-identity helpers to assemble expected bytes.
Randomized models contain one to four layers; their largest frame has 4374
bytes and their largest physical-role count is 68.

Each randomized frame receives one bit change. Structural validation rejects
9697; the remaining 303 decode to different canonical models and reject against
the original expected H(Model). That digest comparison is only a content join:
the expected value still needs authentication, and complete cqis_id also binds
Scales, Registry and Bounds. No full table, rotary data or static arithmetic
certificate is admitted by this codec.

Separate complete GPT-2-small/Llama-3.1-8B shape fixtures retain all 196/291
physical records and produce 11532/30619-byte Model frames. Their randomized
numerical settings do not constitute named checkpoint presets or fidelity
results. The Llama embedding retains all 525336576 element coordinates without
materializing payloads. Two 128-layer boundary fixtures retain 2052/1155 records
in 117236/121144 bytes. The appendix independently bounds every Model below
220000 bytes, within the 1 MiB parser cap; sampled maxima do not define capacity.

Targeted controls reject missing records, altered norm fractions, residual-unit
mismatches, wrong activation families, inactive policy/drop fields, malformed
inner lengths, field-congruent physical dimensions, changed representations,
missing rotations and nonreduced rationals. All strict truncations of the
selected complete fixture reject. Boundary cases retain full u64 rotation
rationals and gated static scale 8454661. These are research checks without
native NC, profile, parity, privacy or performance credit.

Corpus SHA-256: `a80fee9a1fdce38f6c68102255ecd648238d820bac192ac08698417d68e8ca24`.
Candidate SHA-256: `20d3649cbef3a983d42b826e2dc7ec51040840a176956462322f103e041123ef`.
Checker SHA-256: `3076ce37404edc522324ee3ab46889a37775d89c5e9c27cfbe7d0c471df242a9`.
Shared helpers and historical campaigns remain unchanged. Scales and Registry
codecs, the complete bound collection, outer identity/source admission, native
consumers and full named-model inference/proving/verification remain open.

## Complete public Scales codec

The Scales codec implements [encoding appendix §5](../../docs/rfcs/full-model-encoding.md).
It derives every matrix ordinal and channel count from the complete checked
Model, validates exact total length before reading entries, and compares the
full H(Model). Each exponent retains [-1099,1024]; every channel mantissa is a
positive u16. Immutable packed words preserve all channels without expanding
them into retained Python integer objects. There are no vector entries or extra
tied-head records, and no shape-only substitute for the Model identity.

Run `uv run --no-project --python 3.12 --with blake3==1.0.11 python -B
research/cqis-model-contract/check_scales_codec.py`.
Seed 2683 checks 10000 complete randomized Scales frames, split equally between
GPT-2 and Llama. Independent role expansion and struct framing, including the
independently assembled Model preimage, agree byte for byte. BLAKE3 is shared.
Randomized shapes have one to four layers, vocabulary/context up to 64, and at
most 1550 channels; the largest randomized Scales frame has 3274 bytes.

The full named-shape fixtures separately retain all 74/226 matrix entries and
134225/1632768 channels, producing 268800/3266494-byte frames. Maximal-domain
fixtures retain 770/898 matrices and 6815744/16777216 channels; exact lengths
13634622/33558078 match the independent analytic bound. Every mantissa is
validated, with both exponent endpoints and u16 endpoints represented. These
fixtures use patterned scale values, not scales converted from named checkpoints.

Single-bit changes produce 1286 structural rejections and 8714 legal changed
Scales objects that reject against the original expected digest. Targeted cases
reject wrong matrix ordinals, missing/extra records, zero mantissas, out-of-range
or Boolean exponents, malformed lengths, mutable data and every truncation of a
complete small fixture. Changing only Model's logit precision rejects the old
Scales frame despite unchanged physical shapes. A Llama head cannot adopt the
token matrix's ordinal. Source-dependent scale minimality is deliberately not
claimed from structural parsing; source/artifact/passport joins remain required.

Corpus SHA-256: `1fffb27012a8922f55e1bc96e2b66bf7206d177583ce4dd3438ed621cf0900b1`.
Candidate SHA-256: `370404bf7d45ccae359799cad1d98b7cb5c97e0401d50a5640fab12b5718b634`.
Checker SHA-256: `8458e7bc1a0cd608c435f699f27d1fb441aa7d4cad3876f86500d274db7fa408`.
The qualified Model codec and all shared helpers are unchanged. No historical
proof campaign is rerun. Registry regeneration, complete Bounds expansion,
outer/source identity admission, native consumers and full named-model delivery
remain required; this codec earns no native NC, privacy, parity or proof credit.

## Registry with regenerated data

The Registry codec implements [encoding appendix §6](../../docs/rfcs/full-model-encoding.md).
It derives every ordered function/representation reference and the sorted unique
definition sets from Model. It retains each layer's rotation reference, even
when multiple layers use one definition. Exact metadata and total length are
checked before data generation; every table/rotation digest is then compared
with the complete regenerated definition. Supplied digests cannot populate
the bounded caches, and no callback or flag can skip generation.

Component bytes use the unchanged certified-table generator, with LayerNorm
selecting the original rsqrt component through its proposed mode 4. Rotation
data has the new configured prefix/identity and streams every position/pair
through the unchanged integer-certified point generator. It has no additional
whole-table size cap. Pairing participates in the identity even when coefficient
values coincide. Rotation host fields validate before cache lookup so Boolean
pseudo-integers cannot reuse an integer key.

The independent oracle assembles role/function/representation/component bytes
without calling the candidate codec helpers. It uses Arb real intervals for
every table entry, including exp components/corrections, SiLU, tanh-GeLU and
rsqrt, and retains all canonical padded rows. The unchanged independent rotary
point oracle supplies complete row bytes under the new data framing. Shared
parameter constructors and BLAKE3 are not independent implementations.

Run `uv run --no-project --python 3.12 --with blake3==1.0.11
--with python-flint==0.9.0 python -B
research/cqis-model-contract/check_registry_codec.py`.
The fixed-seed framing campaign uses 10000 configurations with one to four
layers and randomized norm/Model parameters. Its table pool uses exp B=7,
F=E=0 and split 4 when present, plus F=E=0 activations. Additional full-data
cases cover nontrivial F=E=7 activations/corrections and the largest B=31,
split-16 exp components. These are explicit parameter sets, not an exhaustive
qualification of every possible table configuration.

The initial campaign passed. Review then added wider rotation rows and nonzero
correction cases; the latter exposed an error in the new oracle, which rounded
the product instead of applying RFC-0021's floor division. The unchanged
candidate follows the RFC. The corrected oracle retains t=-126 at B=F=E=7,
split 4: its correction is 1, while the erroneous rounding gives 0. Initial and
failed expanded receipts and exact oracle sources are preserved separately.

The corrected full run passes. Seed 2684 retains 5000 configurations per family;
direct/product/corrected modes occur 3334/3333/3333 times. Every Registry matches
the independent complete bytes and verifies; one bit change per randomized
record rejects. The largest randomized record is 4159 bytes. Both successful
runs retain corpus SHA-256
`e970640b93b6d6a153469d9ba4f1d059fb59632446dbf50dadbf395d35325f2c`.

The complete data checks cover 15 distinct component definitions and 53 rotation
definitions. The nontrivial correction fixture has 47 nonzero entries. Wider
rotation fixtures cover width 8 over 17 positions in base/linear modes, width
128 over three positions in llama3 mode, and a complete width-16384 row at
position zero. A separate width-2 table streams all 65537 positions, exceeding
the former research generator's 65536-pair cap; its data digest is
`9d9eb601cb448ce9ceddf0a547f50a40d8b0e6a4d538fcc175db448c8f232d9a`.
No early frequency/angle rounding is introduced.

All strict truncations and all 1842 single-byte mutations of the selected
complete fixture reject. Targeted cases cover all six data-digest slots, a
digest recomputed from corrupted padded rsqrt data, changed Model identity,
oversized/mutable frames, full activation-table overflow and a Boolean cache-key
alias. Metadata-only named fixtures retain 49/130 ordered roles in 13811/42037
bytes; 128-layer fixtures retain 514 roles in 148566/165252 bytes. These latter
fixtures do not regenerate their complete table/rotation data, select a named
numerical preset or establish checkpoint fidelity.

Candidate SHA-256: `8417f0e688e10fa0c78f88184673e86a2d823fd317387a5ec53a3531d4afc427`.
Final checker SHA-256: `6ce2c572f07f0a73554dc4a9526510a0bc6ea8abec7a77b1c7617b3f6a937f7f`.
The candidate and shared sources remain unchanged across the three runs. Only
the new checker gained coverage and its floor-division correction. No historical
proof campaign is rerun. Complete Bounds expansion, artifact/passport/source
admission, full named-model regeneration/fidelity and native proof delivery
remain open. These checks provide no native NC, privacy, profile, parity or
performance credit.

## Complete physical record addresses

The [physical appendix](../../docs/rfcs/full-model-physical-bounds.md) adds schema
19 for each canonical physical tensor role. It retains flat coordinates, packed
payload and record-relative byte addresses, both int4 nibbles, signed source
words, and original matrix exponent/mantissa bytes. Whole-word ranges and byte
columns preserve indices beyond M31. Model/Scales/Artifact authority and actual
source ownership remain required; this record does not supply them.

Run `uv run --no-project --python 3.12 --with blake3==1.0.11 python -B
research/cqis-model-contract/check_physical_bounds.py`.
Seed 2685 checks 10000 full records against independent role expansion, address
arithmetic, polynomial byte columns and struct framing. Formats include 2914
int4 matrices, 2844 int8 matrices and 4242 int16 vectors. Actual coordinate,
code, sign, scale and exponent values exercise every applicable column role.
Twelve randomized record addresses exceed p; they retain complete integer words.

Separate named-shape fixtures check all 196/291 physical roles, and maximal
shapes check all 2052/1155 roles. These include each role's final coordinate and
negative source endpoint, without allocating tensor payloads. The maximum
flat index is 17179869183, with final record byte 17181966384. Subtracting p
gives a distinct in-range index with the same field residue. Actual source/column
consumers must therefore retain all high bytes. This observation
does not claim rejection by a native proof consumer.

The three-element int4 fixture retains its zero final high nibble and excludes
that nibble as a real element. Unsigned word and ranged-offset equations exclude
matrix codes -8/-128 while retaining vector -32768. Malformed record bytes,
truncations, suffixes, mutable/oversized frames, changed expected fractions,
invalid formats and Boolean fields reject in the research record validator.
Neither byte framing nor these static bounds establish quantisation minimality.

The largest randomized record is 34294 bytes with five columns. The separate
domain proof gives a strict 36000-byte cap and column sides below p/2.
Randomized corpus SHA-256:
`360f4433714196c9696c80dfab24c62c4463e6fd094c305fcfa7284cdb5172a0`.
Complete named/maximal role corpus SHA-256:
`8d839dd0ae1742d582f5908c5efbf0e5ec57ad588b8014587fc5f628952eb90b`.
Candidate SHA-256: `d2bf013fa0a43afbaa24d45e7054e4798a30380da1997cef781a3223cc5272e5`.
Checker SHA-256: `0b26cd5cd7c5fdb2f3c9e145f2138b9f0d849fe3e1f97a99f0e8256cebe36a5e`.
Shared helpers and previous codecs are unchanged. No historical proof campaign
is rerun. Complete Bounds assembly, Artifact-global/source-container joins and
native consumers remain open; named-shape address checks do not establish
checkpoint conversion, fidelity, privacy, parity or full proof delivery.

## Canonical Bounds collection

The [collection appendix](../../docs/rfcs/full-model-bound-collection.md) fixes
the nineteen schemas' complete physical/operation slots and parameter joins.
The prototype validates Model, every Scales entry and complete regenerated
Registry data before deriving its records. Score and full-block admission remain
mandatory. It hashes all three complete inputs; using a maximum channel mantissa
for a bound does not discard the other channels from identity or source checks.
Expected ordinals and records derive from the model, with no supplied op list.

Run `uv run --no-project --python 3.12 --with blake3==1.0.11
--with python-flint==0.9.0 python -B
research/cqis-model-contract/check_bound_collection.py`.
Seed 2686 checks 10000 complete parameter selections against a separate role
expansion and source-policy propagation algorithm: 5000 per family, 4998 sampled,
and 3334/3333/3333 exp representation choices. Complete Model/Scales/Registry
inputs also match their existing independent framing/data oracles.

Twenty-two selected collections compare every complete record and outer byte
against the independent schema/struct oracles, validate, and reject a changed
byte. Other randomized cases compare all expected parameter objects; they do
not repeat each unchanged schema's earlier arithmetic campaign. The largest
randomized layout has 130 records; the largest fully encoded selected frame is
2948707 bytes. Qualified schema implementations and shared helpers are unchanged.

Separate named-shape and maximal-domain fixtures retain every slot, including
sampling. Every record matches its independent byte oracle and is hashed in
order, without tensor payload allocation. They produce these record streams;
the sizes exclude the fixed collection header:

| Shape fixture | Records | Record-stream bytes |
|---|---:|---:|
| GPT-2-small dimensions | 481 | 11065815 |
| Llama-3.1-8B dimensions | 1164 | 27386449 |
| Maximal GPT-2 domain | 5005 | 114583459 |
| Maximal Llama domain | 4620 | 109291214 |

These fixtures use patterned scales and configured numerical parameters. They
do not regenerate named Registry data, claim complete admission for those
configurations, convert checkpoint payloads or establish named-model fidelity.
Their private layout check introduces no fake Registry input or public bypass.

Controls reject each omitted/duplicated slot, changed hashes/counts/ordinals/
lengths, malformed frames and stale records under a changed matrix format even
with a correct new header. A changed nonmaximum scale leaves derived record
parameters unchanged but changes the full Scales hash, so the old collection
rejects. Forged Registry data, a full activation-table overflow, an excessive
score bound and an invalid block bound at n=1 all reject through collection
entry points. A duplicated final record rejects as Trailing; an initial smoke
test expected Encoding and was corrected without changing the candidate.

The complete stream must be exhausted before its hash or validation can succeed.
The separate domain proof bounds the frame below 496000000 bytes, within 512 MiB.
No resource timing or benchmark is claimed. Full Artifact/source/view indexing,
actual consuming reductions, outer identity/passport/private statements and
native/full-model execution remain required. These results grant no native
NC coverage, proof/privacy/profile/parity or performance credit.

Configuration corpus SHA-256:
`daa7ce200d54e8a5a83ec1971f86b5113c2f23fbdea0a7ad0a01cee865aa4810`.
Selected complete-frame corpus SHA-256:
`f202bc1ffa7a8c2d8587a190c0f6ca3756bb40bd9919357ad15002dffe811086`.
Named/maximal record-stream corpus SHA-256:
`ee840619777a30ee91bb9fae5d71edea9d055addd6bdc9d257d64da553cacc8e`.
Candidate SHA-256: `daa798f6e34e4cb38821402a4071252bc5227cd3540dfae23bd524039e8ee302`.
Checker SHA-256: `7e47fee94a985d225a27e4c7511e4eb907eb73abe1e585db5e94ba723ba49118`.
