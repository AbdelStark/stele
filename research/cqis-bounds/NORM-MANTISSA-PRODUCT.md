# Consumed RMSNorm mantissa product — Q26 / Q31

Status: revealing research under Draft RFC-0004 A3. RFC-0021 §2.3 and
RFC-0022 §2.3 require M in[16384,65535] and MD=M*D. This consumes the
closed normal_product role with actual mantissa/divisor sources. It does not
establish A=MD+R, strict0<=R<D, a normalized interval, rsqrt or full inference.

Question before implementation: can an actual lower/upper mantissa range and
the full independently expected divisor root feed the existing closed product
while preserving every source, high byte and original/public claim? Cost terms:
c_a/c_sc/c_lu/T_misc for affine/byte views and all inherited range/product work.
Kill criterion: a subminimum mantissa, inactive-factor substitution, ignored high
divisor byte or whole-field product alias survives its actual consumer.

Expected metadata is the full closed norm Spec(d,F,G,E,en,ed), retaining all
original domains. External roots bind M as one canonical-u32 field value,
D as16 canonical-u32 byte slots, and MD in the8/16/32 output slots derived
from the closed normal_product role. This M representation is suitable for
the subsequent actual(M,J) lookup source; it is not a packed physical tensor.

First fully verify a scalar wide-range child with cap49151 for the offset
M-16384. Its two actual byte words, source/cap/Boolean-carry/terminal claims
and lookup remain consumed. Derive M=16384+lo+256*hi only from those verified
bytes, then require its one-slot root to equal the independent expected M root.
The actual offset range gives16384<=M<=65535<p/2. This exact affine source
view supplies the lower bound absent from the product's generic upper cap.

Read the actual product source's right byte planes and reconstruct the full
16-slot D root with exact zero extension. Any excess right planes must be zero;
never compare only a prefix. Derive every left plane from verified M, compare
the complete source vector exactly, then fully verify the product against the
derived source root and independently expected MD root. Zero D does not remove
the mantissa source join. Both actual whole-input ranges, packing, output/carry
ranges, zero boundaries, fresh polynomial identity and three A1s remain.

The product's right whole bound is exactly Dmax; D>0 and its configured origin
require the separate divisor consumer with the same external root. This bounded
role permits D=0. After actual integer product acceptance, MD<=65535*Dmax follows
and can occupy140 bits. Independent result digit caps cannot supply that fact.
No parent arithmetic challenge, additional Accepted role or production cut is added.

Namespace: identity<2^44, base=2^63+2^18*identity. Offset source base+1,
derived product source base+2. Wide-range id4096*identity+1 has span atbase+64;
product id64*identity+1 has span atbase+4096. Descendant roots/invocations are
disjoint within the parent span. External M/D/MD ids are distinct u64>=2 outside
it. Prefix stele/research/q26/norm-mantissa-product/v1 plus NUL, version/field/
repetitions, four u64 ids and complete expected norm function bytes seed the
final parent state with five roots and two verified child states. Parent draws none.

Account before implementation: offset a=0,b=1 range contributes A3 numerator7.
For product planes2^b and output slots2^g, product A3 is9b+18g+31; total
9b+18g+38. Four separate lookup dimensions2,b+2,g+3,g+3 retain identities
[(2^m+255)/|K|]^r and reductions r[F(m)+F(8)+3m]/|K|. Product identity C-1
and product A1 loss4b remain separate, unsquared and unrepeated with r. Full
nonlookup ZeroWeight draws16+4b+8g, Sumcheck17+6b+8g, including product rho
and both plane A1s. Exact joins add no algebraic loss conditional on binding;
FS/H, remaining norm roles and physical/model/private composition are additional.

Tests first:10000 independent NumPy products and int64 byte convolutions, all
field/repetition pairs with M endpoints, D=0/1/Dmax, and actual maximum140-bit
MD. Check exact accounts/draws and all original/public claims. A genuinely
valid product with another mantissa at D=0 must fail its source join. Products
below M=16384 must not bypass the actual offset source; wrapped offset slack
must fail the terminal consumer. MD+p with valid ranges must fail the actual
product identity. Preserve all16 D slots when product planes number4 or8, and
every output/carry slot. Compose the actual upstream configured divisor proof;
a genuine changed-divisor product under its pinned root must reject. Metadata,
namespace, malformed roots/fields/lengths and supplied authority must reject.

Recommendation: continue Q26/Q31 with A=MD+R and strict0<=R<D, retaining
these same M/D/MD roots and the paired scaled A root. Then consume the entire
rsqrt table and final output branches. Original blocked criteria, native controls
and private/model inference obligations remain open.

## Reproduction and evidence

Run `uv run --locked --script research/cqis-bounds/check_norm_mantissa_product.py`.
Tests first failed with the missing module. Seed2694 then passed10000 varied
NumPy object-integer products and int64 byte convolutions over305392 source
cells, including both endpoints and zero divisors. Frozen corpus SHA-256:
`be8aa319006f98f8b825a2b886b32df0f4302d13192f9c5c93282ba6ff84ca47`.

Same-author review identified an affine helper accepting canonical inputs whose
derived one-field result was noncanonical. A focused failing control reproduced
that encoding gap; an explicit canonical-result check now rejects it before
root encoding. Actual verifier range-first ordering already bounds valid M by
65535 and is unchanged. The focused regression and full corpus passed on the
guarded code with the same digest; no valid source or transcript state changed.

All16 main and4 intermediate-width proofs passed across both fields/repetitions,
with exact loss/draw checks. They cover4/8/16 source planes and8/16/32 output
slots, including actual140-bit MD with nonzero byte17. Frozen proof-state hashes:
main `b509898977efa6706180a20733d691f8f07a324f4787da7f470808c873b73eb5`;
intermediate `97529418aaddcb487717ddf01794a508ec941fb9794b6ae086a5c00940238547`.

All controls and actual configured-divisor composition passed. Independently
verified products using M=16383 or another M at D=0 fail Product:SourceJoin;
wrapped offset slack fails Mantissa:TerminalCarry:FinalEvaluationMismatch.
Full D16 high-byte substitutions fail Divisor:CommitmentMismatch with4 or8
planes. Valid-range MD=p collides with the false zero product at fixed rho256
but fails Product:Product:FinalEvaluationMismatch at the actual challenge.
An actual D=3 upstream proof composes with M=21845,MD=65535; a genuinely valid
D=4 product under the pinned D=3 root rejects. No expected-reason repair was
needed. Required local gates remain pending; no benchmark, native control
credit, independent audit or full normalization admission is claimed.
