# RFC-0025 Bounds collection

Status: Draft. Part of [RFC-0025](RFC-0025-full-model-cqis.md), Q26/E5-03b.
This closes the collection of the nineteen numerical/physical record schemas.
It does not supply a proof plan, source ownership or passport authority. Every
actual consumer in the [inventory](full-model-consumers.md) remains required.

## 1. Inputs and canonical frame

Derive the collection from the complete structurally checked Model, its exact
Scales frame and its complete validated Registry. Registry validation includes
regeneration of all selected component and rotation data. An opaque supplied
Registry digest or a structurally valid Model cannot authorize the derivation.
All Scales entries must parse against that Model before any maximum is taken.
The complete original channel mantissas remain required by actual consumers.

With the encoding appendix's B and H, define

    Bounds = ASCII("stele/v0.1/cqis/bounds") || H(Model)[32]
             || H(Scales)[32] || H(Registry)[32] || u16(record_count)
             || (u16(ordinal) || B(record)) for each expected slot.

Ordinals are exactly 0..record_count-1. The order below derives each slot's
schema and complete parameters independently; the supplied count, ordinal,
schema, parameters, lengths and scalar/column fields have no authority.
Compare the entire record with its deterministic rederivation. Omission,
reordering, duplication, changed metadata and trailing bytes reject. Identical
record bytes may repeat at distinct prescribed slots; deduplication cannot
remove a role. The frame contains no supplied role names or alternate op list.
Its header never includes cqis_id, so the outer identity has no hash cycle.

All arithmetic records use their existing complete frames without changes.
The expected schema fixes the radix, field, parameter widths and column order.
No witness, observed code, activation maximum or actual request length is an
input to this collection. Bounds uses full context capacity n and declared
format ranges. A request retains its own real extent, masks and source views.

## 2. Physical and boundary slots

First include schema 19 for every physical record in Model order, selecting
its Shape, ordinal, bits and parameter from Model. GPT-2 has 16L+4 entries;
Llama has 9L+3. There is no second GPT-2 head entry.

Then include schema 2 for embedding: vocabulary v, context n, f0 and the
token matrix's bits, exponent and maximum channel mantissa. GPT-2 also
uses the position matrix's bits, exponent and maximum channel mantissa.
Llama's position parameters are absent. Each actual gather still uses its
original selected row and that row's own mantissa; a global maximum is only
the bound parameter, never a replacement scale in numerical execution.

After all layers, append these slots in order:

| Slot | Expected parameters |
|---|---|
| final.norm | Model's final LayerNorm (schema 3) or RMSNorm (14) |
| convert.final | Row(4), d, kind 0, final norm E, final policy |
| project.head | Affine(1), physical token for GPT-2 or head for Llama; source fraction final norm E, final policy, output logits_fraction; no bias |
| logits | Logits(15), v, logits_fraction; retained in both decoding modes |
| temperature, if sampled | Temperature(16), logits_fraction, exact tn/td and sampling exp |
| sampling.exp, if sampled | Exponential(10), Model's complete sampling exp |
| sampling, if sampled | Sampling(17), v, sampling exp E and pn/pd |
| request | Request Spec(18), v, n and Model's decoding mode |

## 3. Per-layer slots and parameter joins

Use the projection order from Model: Q,K,V,O,up,down for GPT-2; Q,K,V,O,up,
gate,down for Llama. Their fractions are fQ,fK,fV,fO,fu,[fg],fd. Let p0..p6
be the seven whole-row policies. The incoming residual fraction is f0 for
layer zero or the preceding block's out fraction. Each layer emits this order:

| Slot | Schema and parameters |
|---|---|
| norm1 | 3/14, exact first norm, with its Model-checked incoming fraction |
| convert.first | 4, d, kind 0, norm1.E, p0 |
| project.Q, project.K, project.V | 1, respective physical matrix/bias, kind 0, source norm1.E, p0, respective output fraction |
| rotate.Q, rotate.K, Llama only | 7, respectively h/g heads, a, rotation.width, n, rotation.layout, fQ/fK |
| convert.Q, convert.K, convert.V | 4, widths d/g*a/g*a, kind 0, fQ/fK/fV, p1/p2/p3 |
| attention.score | 8, h,g,a,n,fQ,fK,exp.F,p1,p2,score_m,score_e |
| attention.maximum | 9, n, the derived score bound, exp.bits,exp.F |
| attention.exp | 10, the exact attention exp, including n and representation |
| attention.weighted | 12, h,g,a,n,fV,exp.E,p3,accumulation,drop |
| attention.normalize | 13, that same Weighted parameter object and attention_fraction |
| convert.attention | 4, d, kind 0, attention_fraction, p4 |
| project.O | 1, physical O/bias, kind 0, source attention_fraction, p4, fO |
| residual.mid | 5, d, incoming residual fraction, fO, mid_fraction |
| norm2 | 3/14, exact second norm, with Model-checked F=mid_fraction |
| convert.second | 4, d, kind 0, norm2.E, p5 |
| project.up, then project.gate for Llama | 1, corresponding physical matrix/bias, kind 0, source norm2.E, p5, fu/fg |
| activation | 11, exact configured activation; GPT-2 uses up, Llama uses gate |
| gated_product, Llama only | 6, f, fu, activation.E |
| convert.ffn | 4, f, kind 0 for GPT-2 or 1 for Llama; fraction activation.E or fu+activation.E respectively, p6 |
| project.down | 1, physical down/bias, same kind/fraction/p6 as convert.ffn, fd |
| residual.out | 5, d, mid_fraction, fd, out_fraction |

Every Affine selects its inner dimension, bits, exponent and maximum mantissa
from its own physical matrix and Scales entry. Each GPT-2 block projection
selects its physical bias's fraction; Llama projections and both heads have
no bias. Norm gain/bias fractions already join Model's corresponding C_i.
No caller supplies a different matrix ordinal, source policy or fraction.

Score derivation must reject a worst absolute score >=2^31 before selecting
Maximum's bound. Weighted derivation must enforce the full 1024-slot static
block bound, even for n=1. Normalization retains exactly those same parameters.
A descriptor's legal fields, zero runtime data or short request cannot bypass
either admission check. Exp-domain and output-overflow failures remain defined
numerical failures; the collection does not assert every request succeeds.

The Weighted record covers probability sums, weighted products, configured
block rounding and complete global accumulation. Normalize also covers fixed
head assembly. These semantic consumers do not become optional because their
bounds share a record. Function/rotation Registry deduplication likewise retains
every ordered operation reference, complete source and layer-specific consumer.

## 4. Counts, resources and validation

Each GPT-2 layer contributes 23 arithmetic records, each Llama layer 27.
Embedding and the non-sampling final/request slots contribute six; sampling
adds three. Thus total counts are 39L+10+3[sampled] for GPT-2 and
36L+9+3[sampled] for Llama: at most 5005 and 4620 respectively.

Each arithmetic record is at most 131072 bytes; each physical record is below
36000. With at most 2953/3465 arithmetic and 2052/1155 physical records,
including six bytes of ordinal/length framing per entry and the fixed header,
the complete collection is below 496000000 bytes. Its cap is 512 MiB.
These are domain bounds, not observed sizes. Every length/addition fits u64.
Expected counts bound iteration; no supplied count causes allocation.

A streaming producer may emit one complete expected record at a time. An
incremental hash is complete only after all slots and final length checks.
A partial iterator, prefix digest or successful early record is not successful
collection validation. Validation checks the input cap first, then the complete
parameter sources and all expected bytes, with exact exhaustion. Native
fallible allocation and adversarial parsing remain required delivery work.

This collection adds no challenge, cut, profile or weight pass. Derivation and
Registry generation are preparation T_misc; no measured constant is asserted.
Artifact-global/source-container addresses, E6 owned source/view geometry,
actual range/branch/point consumers and the complete passport/private statement
remain separate obligations. Neither a matching H(Bounds) nor these numerical
records authenticate their own Model/Scales/Registry inputs or admit a proof.
