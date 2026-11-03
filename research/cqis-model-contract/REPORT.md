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
