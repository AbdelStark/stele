# Masked attention maximum bounds — Q26 research

Status: Draft RFC-0004 A3/A6 and RFC-0009 A2 evidence, retaining RFC-0009 A1's
attained unmasked maximum and full exponential domain. E5-03 stays blocked;
all original acceptance criteria and NC-0109 remain unchanged.

Question: can a static schema enforce the first attained allowed maximum and
nonnegative score differences without int32/M31 aliases, including sparse
absolute positions and masked scores? Security property: static integer
faithfulness and canonical mask/selection behavior. Cost term: T_attn/c_x;
no measured constant or proof-consumer claim.

Kill criterion, stated before implementation: drop the candidate if a modular
alias admits an unattained maximum, false difference or later tied key; if
bounds depend on actual data; or if it disagrees with the independent integer
and NumPy references. Source/mask/position ownership and function/range proof
consumers remain required beyond conditional numerical checks.

## Static schema and source scope

The expected Spec fixes absolute span L in 1..2^20, score magnitude S in
0..2^31-1, exponential domain B in 7..31, and score fraction F in 0..30.
In the model adapter, S is recomputed from the same projected-attention
score policy as the score template. It is not copied from a supplied bound
record or measured from actual scores. B/F come from the configured function;
F records the units but does not change integer maximum/difference arithmetic.

Let H=2S, D=min(H,2^B). Every score, including a masked score, is in [-S,S].
Inputs are separately expected query position, strictly increasing unique
absolute key IDs, scores, Boolean masks and selected absolute ID. Actual count
is in 1..L; IDs and query position lie in [0,L). At least one key is allowed;
the selected key must occur and be allowed. The selected ID is a conditional
claimed source, not a newly public or committed intermediate. Source ownership,
causality and the completeness of the supplied key set are outside this checker.

The witness duplicates query/key positions and selected ID for exact source
checks, supplies a maximum in [-S,S], and gives delta/gap pairs in [0,D].
Masked pairs must both be zero. No compacted position or unused tail is added.

## Relations and soundness argument

A shared byte-column role decomposes maximum+S. Its canonical result digits
must equal those of selected_score+S. All values lie in [0,H], so this
establishes integer attainment even if two signed values alias modulo p.
For each key, let M be its separately expected mask and let
b = 1 exactly when M=1 and absolute_key_ID < selected_ID. Enforce:

```
M*(score+S) + delta = M*(maximum+S)
gap + b = delta
```

The first equation uses a two-term byte sum with operand cap H; the second
uses a two-term byte sum with operand cap max(D,1). All right operands are
0 or 1. Right-hand sides compare canonical digit arrays, with the mask applied
to each maximum-offset digit. No wide equality is compared modulo M31.
The prefix bit is derived from expected IDs/mask/selection, never supplied as
a free witness. A proof implementation still needs the actual index comparison
consumer when these source values are private.

For an allowed key, delta is exactly maximum-score. Its nonnegative bound
proves maximality, while delta<=2^B enforces the complete inclusive function
domain. At an allowed earlier key, gap>=0 and b=1 require delta>=1. Hence
selection is the first allowed maximum in absolute-ID order. This first-tie
rule matches the Draft numerical reference; RFC-0009 A1 itself requires an
attained allowed maximum. At masked keys, delta=gap=0 and both equations
reduce to zero. Masked scores retain their source/range checks.

H<=2^32-2 and D<=2^31. Each source/gap fits four bytes; generic two-term result
caps are below 2^33 and use at most five bytes. All comparisons use eight
canonical bytes, so no high part can be truncated. Every column coefficient
is <=2*255=510, every internal carry <=1, and both sides are <=511<p/2.
The existing limb engine recomputes tighter column caps and enforces both
zero carry boundaries. This argument is static, including S=0 and B=31.

No random challenge, degree loss, commitment or proof claim is added. The
arithmetic checker treats expected sources, whole ranges and byte digits as
plaintext obligations; it is not a succinct source/range/PCS consumer.

## Encoding

The tag is `stele/research/q26/attention-max-bounds/v1` plus NUL (43 bytes).
The parameters are little-endian u32 L/S and u8 B/F. Then come u32 p,
u8 radix bits (8), u8 scalar count (7), and seven u64 scalars in this order:
position_max, score_offset_max, domain_max, delta_max, gap_max, prefix_max,
entry_capacity. The last scalar is the fixed 2^20 ceiling, not actual count.

The shared/entry groups have counts 1/2, each encoded as u8. A role carries
local u8 ID, u32 term count, u64 left/right/result maxima, three u8 digit
lengths, byte digit caps, then u32 carry/lhs/rhs caps. With at most five
result digits, a role is at most 106 bytes. The fixed portion is 117 bytes,
so even three full-size roles total at most 435 bytes, below the enforced
512-byte capacity. Validation recomputes exact bytes; extra, truncated or
altered bytes cannot choose parameters, roles or field authority.

One template per layer is named `layer.i.attention_max`. Correctness checksums
frame count, role-name length/name and record length/bytes under
`stele/research/q26/attention-max-bounds-checksum/v1` plus NUL. A complete
certificate set and authenticated relation to the score template remain open.

## Controls and evidence

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py
--attention-max` for corpus/models/controls, or `--attention-max-controls`.
Tests were written first and failed with the missing implementation module.
Independent Python integer and NumPy int64 selection/difference references,
packed-polynomial column bounds, struct framing and NumPy digit convolution
cross-check the arithmetic. Shared generic numerical primitives and fixtures
are disclosed; this is not an independent audit.

The seed2651 corpus has 10000 configurations: 5874 accepted and 4126 expected
Domain rejections. Its frozen SHA256 is
`69618915e68d73e044eed4f5148e0cfd788170fe23cd38221101522b4f158999`.
Thirty seed2652 models yield 28 valid replays and two arithmetic-overflow
rejections. Separate controls retain positions 1023/1024/2048, mask a larger
score, choose the first allowed tie, cover S=0, and accept delta=2^B exactly.

Coherent adversarial controls rebuild all columns:

- With S=2147385345 and selected_score=-S, a forged maximum of 98302 differs
  by p and passes a direct field attainment equation. Canonical digits reject.
- With scores (S,-S), the true difference 2S exceeds 2^31. Subtracting p makes
  the claimed difference fit the domain but the exact difference relation rejects.
- At two allowed equal scores, selecting the second key and setting the earlier
  gap to p-1 makes gap+1=0 modulo p. Canonical first-maximum digits reject.

One-value controls cover source scores/masks, positions, selection, maximum,
deltas, gaps, masked nonzero pairs, ranges, carries, metadata and serialized
bytes. All-masked rows, invalid selected IDs, malformed Boolean masks, duplicate
or unsorted positions and out-of-range masked scores reject for named reasons.

The model checker takes scores checked after whole-projection conversion and
GQA slicing. Checked maxima/deltas feed probability evaluation in the raw-sum
model checker, composing with block rounding/aggregation and normalization.
The pinned fixture adds two records, 676 bytes, checksum
`ad6a99e9f516f63b72b6f48bbf2dbe5e68f49d34f1d80b62f20aeeeb6a192fed`.
All prior baseline and separate block-variant fields remain unchanged. These
are correctness/serialization observations, not performance measurements.

## Recommendation

Continue Q26 with complete bound-set/source contracts and an explicit audit of
remaining operator coverage, then native parity and proof consumers under
reviewed amendments. This closes the conditional score/max/sum/block/division
arithmetic chain, not the attention claim graph. Function membership,
source/mask/selection comparisons, range enforcement, padding of query rows,
PCS/ZK/FS, full-model fidelity and original NC-0100/0101/0109/0500..0506 remain
mandatory. This checker handles real query rows; it does not admit padded rows.

The conditional checker uses O(actual key count) work/data, independent of an
unused absolute-position tail. No measured T_attn/c_x constant, weight-pass
count, cut, Accepted RFC-0022 field or task acceptance criterion changes.
