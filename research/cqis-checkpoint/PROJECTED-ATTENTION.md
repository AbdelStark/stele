# Q26: projected attention, GQA and absolute cache positions

Question: can one exact candidate compose Q/K rotation, row scales, score units,
GQA, restored V units and output assembly with identical full/cached results?
Cost terms: c_x/c_a/T_misc; security properties: source/scale/head association,
mask and position scope. Kill criteria: oracle disagreement, head-local scale
substitution, wrong GQA group, lost absolute block position or partial output on
an overflow. Prototype only; no native inference or proof admission.
Review: [same-author skill passes](../../agents/reviews/projected-attention-draft.md).

## Candidate composition

`projected_attention.py` takes wide projected Q/K/V rows, not weights or tokens.
A frozen configuration fixes head/group widths, rotary width/layout, integer
rotation tables, Q/K source units and conversions, explicit score multiplier,
and the previous attention row configuration. All arithmetic is exact integer.

For each head/group, rotate the first r channels with signed Q14 coefficients:
adjacent pairs (2j,2j+1) or split pairs (j,j+r/2); leave the remaining channels
unchanged. Round each result once, signed nearest with ties away, and reject
int16 overflow. Convert the whole projection row once. Scales are per position
across all heads/groups, not recomputed after slicing. Cached K contains rotated
codes and the corresponding whole-row scale; V retains its whole-row scale too.

For query head t, group floor(t/(h/g)) supplies K and V. Scores are
R(dot(q,k)*sq*sk*m_score*2^(e_score-fq-fk+F)), with public positive integer
m_score<=65535 and e_score in [-62,30]. This chooses a dyadic physical multiplier
before exp's argument scale; it does not silently compute inverse sqrt(d_h).
Computing all scores is safe under static int32 admission, independent of masks.
The prior row function supplies restored-value output normalization. Concatenate
all wide head outputs, then quantise the complete row for the O projection.
The shared `wide_row` helper performs no int8 conversion. A rejection-order test
catches premature head conversion before another head's domain validation.

The rotation tables are supplied integer fixtures, not canonical RoPE generation.
Shape/range checks do not prove trigonometric origin or model identity. No QK-norm,
softcap, batching/sequence-id, projection weights, output matmul, full layer or
model is implemented. Source/table authentication and canonical config bytes
remain open. The explicit full configuration comparison on a cache is local
syntax, not a commitment or proof consumer.
A legal substituted cache position is deliberately accepted: unchanged key codes
then give maximum 0 instead of 32 for the correctly rotated key. A future source/
rotation/position consumer must reject that association, not merely validate indices.

## Positions and bounds

Caches retain strictly increasing absolute positions in [0,2^20). Evicted keys
can be absent; surviving keys retain their public rotation and block j//1024.
Masks are supplied booleans; the caller owns the intended causal/window policy.
Every real query needs an allowed key. The returned attained index is absolute.
Future padded query rows still need canonical zeros and selector exclusion.

For sparse caches, use the explicit `position_span` argument to `attention.bounds`:
with N cached rows and static span L, the block count is at most
min(N,ceil(L/1024)). Z<=N*2^E. The default span=N is for contiguous prefixes only.
Example: 1024 keys at positions 1024*j, each value 127 with E=0,c=2, have
T=1024*R(127/4)=32768. The contiguous-row bound 32512 is too small. The test
exhibits this mismatch and checks the corrected span-dependent bound. Runtime
positions or observed values do not authorize any future certificate field.

Rotation numerators have magnitude <=2^30. Let Sq,Sk be the static restored
bounds from the selected conversions. Before shifting, score magnitude is at
most d_h*Sq*Sk*m_score<2^62; the shift lies in [-122,60]. Widened operations
fit below 2^123. Admit only configurations whose rounded score bound is <2^31,
so masked future keys cannot cause a full/prefix overflow discrepancy. These
are shape/parameter bounds, not implemented field/limb certificate schemas.

## Evidence, costs and remaining work

Run `uv run --locked --script research/cqis-checkpoint/check_projected_attention.py`.
Seed 2628: 10,000 exact/NumPy cases, 9,191 accepted and 809 required rejections.
SHA-256: `9a245ada8dfc2f1ee4f40fa859f80d59825afe19b624d575f23325bb338ee55d`.
Each case checks query rotation directly; accepted cases also check cached K
codes/scales. The oracle independently rotates, converts whole rows, uses NumPy
int64 dot products and Fraction score/output rounding. It shares the Accepted
certified-exp primitive; this is not independent transcendental validation.
Ten additional cases compare oracle, full causal cache, prefix and evicted window
across absolute block boundaries, both accumulation modes and GQA. Explicit
checks cover whole-row head scales, both layouts, partial rotation, signed ties,
absolute attained indices, duplicate positions, cache scope, masks, score bounds
and rotation overflow. The original attention corpus retains its exact digest.

Preparation is O(N*g*d_h), one query O(N*h*d_h), and cache storage O(N*g*d_h).
The supplied tables use O(L*r) entries; this prototype does not claim efficient
RoPE table storage. The query uses O(N) score/probability state per head and
O(h*d_h) output state, never an N-by-N matrix. Each head also copies an
O(N*d_h) V view; this research allocation is not a streaming proof schedule.
Validation rescans the cache;
configuration equality may compare O(L*r) entries. No timings, GPU parity,
weight-pass change or measured constant is claimed. Production row/source/range/
lookup/PCS consumers, joint ZK, native forward and model fidelity remain required.
Recommendation: continue Q26 and retain RFC-0004 A6 / RFC-0009 A2 as Draft.
