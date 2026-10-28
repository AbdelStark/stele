# Function and representation identity candidate (Q25)

Research for Draft RFC-0004 A2, extending the
[component table contract](cqis-table-identity.md). The candidate binds a
function's integer semantics separately from its selected implementation.
It does not define the whole model configuration, CQIS identity or passport.

## 1. Function descriptors

Replace the component descriptor's prefix by
ASCII("stele/v0.1/function/identity"); retain u16le name length, ASCII name,
u32le version, u16le parameter length and exact parameters. Version is exactly
1, and FunctionId is the first 32 bytes of ordinary unkeyed BLAKE3 of this
descriptor. Names/versions/parameters are closed; unknown or aliased encodings,
truncation and trailing data reject. Parser bounds are 128 total bytes, 32 name
bytes and 64 parameter bytes. Every schema below is smaller.

| Name | Exact parameter schema | Integer semantics |
|---|---|---|
| `exp_q/product` | u8 B,F,E,k | P_k of the wide exponential candidate |
| `exp_q/nearest` | u8 B,F,E | D of the certified exponential candidate, B<=15 |
| `rmsnorm_q` | u16le d; u8 F,G,E; u32le en,ed | total RMSNorm candidate with epsilon=en/ed |
| activation/range names from the component contract | identical parameters | that component's function |

Bounds, reduced rational epsilon/cap rules, rounding, overflow and precision
rejection are exactly those in the linked numerical studies. Norm dimensions,
all three scales and epsilon are part of FunctionId; the shared fixed rsqrt
table alone cannot bind them. Gain/input tensor values are operation inputs,
whose source/commitment binding is a separate mandatory plan relation.

Different splits change P_k and therefore its FunctionId. D is independent of
the decomposition split, so its FunctionId has no k. Corrected and direct D
evaluation may share that semantic identity only because both return the same
correctly rounded integer. P_k and D never share a FunctionId. Function and
component domains are separate even when names/parameters coincide.

## 2. Selected representation

A representation contains the immutable Function descriptor, mode and exact
representation parameters. Its encoding is

    ASCII("stele/v0.1/function/representation") || FunctionId[32]
    || u8(mode) || u8(parameter_length) || parameters || u8(component_count)
    || ordered component TableIds[32 each].

RepresentationId is ordinary BLAKE3-256 of these bytes. The complete mapping is:

| Mode | Function | Representation parameters | Ordered component roles |
|---|---|---|---|
| 0 | nearest exp, activation or range | empty | corresponding direct component |
| 1 | product exp | empty | exp hi, exp lo, using the function's B,F,E,k |
| 2 | nearest exp | u8 k | exp hi, exp lo, exp correction, using B,F,E,k |
| 3 | RMSNorm | empty | fixed rsqrt mantissa component |

Only these combinations are accepted. Mode 2 validates k under the exp bounds.
Parameters, component count, roles, order and full descriptors are derived;
none is adopted from supplied TableIds. Substitution, omission, extra bytes or
reordering reject. A valid encoding of another representation is still rejected
when it disagrees with the verifier-owned expected choice.

Equal FunctionIds do not make direct and corrected representations interchangeable
inside one configured proof. The chosen RepresentationId and exact component
closure must be bound in the canonical plan/configuration. This preserves
RFC-0005 §5 and INV-8 while allowing different explicit configurations to use
different, integer-equivalent representations. Product recombination, ranges,
norm statistic/limb/output relations and every actual membership remain required.
An identity hash does not prove any of those relations.

## 3. Function manifest and component closure

For a verifier-owned set of selected representations, reject duplicate
FunctionIds, including two different representations of the same function.
Order functions lexicographically by the raw 32-byte FunctionId. Derive the
union of all required component descriptors; reject any digest collision between
unequal descriptors and order components by raw TableId. No extra or missing
component is allowed. Counts must fit u32 without truncation. Encode:

    ASCII("stele/v0.1/cqis/functions") || u32le(function_count)
    || for each function: u16le(descriptor_length) || function_descriptor
         || u16le(representation_length) || representation_bytes
    || u32le(component_count)
    || for each component: u16le(descriptor_length) || component_descriptor
         || BLAKE3-256(canonical_component_data)[32].

Every component data digest is regenerated from the complete certified table
definition, including canonical padding. A syntactically valid function whose
table overflows or cannot be certified does not produce an admitted manifest.
Verification compares these derived canonical bytes to the supplied manifest;
it never adopts untrusted counts, shapes, digests or configuration choices.
The independent test reader checks every framed length, both sorts, exact
closure and recomputed data digests. Empty sets have both counts zero.

This manifest describes a function set, not operation order or tensor sources.
The complete CQIS configuration must additionally authenticate each operation's
function/representation reference, dimensions, source tensors, scale tensors,
architecture and canonical plan. Passport table code/Merkle roots must derive
from these exact validated data under separately bound code/layout parameters.
A matching manifest digest beside arbitrary roots is not sufficient; no full
passport/CQIS identity or private opening protocol is claimed here.

## 4. Reproduction, costs and remaining work

Run `uv run --locked --script research/cqis-tables/check_functions.py`.
The [artifact](../research/cqis-tables/function-identity-candidates.json) records
six function frames, five representations and a four-function manifest.
Tests cover every frame truncation, wrong/ordered components, changed split,
norm dimensions/scales/epsilon, unknown mode/parameters, duplicate functions,
manifest tampering and representation substitution. Direct and corrected D at
split 6 agree with an independent exact oracle on every example-domain input.
Independent manifest parsing checks all lengths, orders, components and data.

One-time generation/validation hashes complete component data and contributes
O(sum Lc) to T_misc, plus linear manifest work. Native lookup and arithmetic
costs remain in c_lu/c_a. No measured constant, challenge, soundness-budget
admission, weight pass or new commitment is introduced. Native implementation,
registry/plan/passport consumers, MLE parity and full A2 review remain required.
