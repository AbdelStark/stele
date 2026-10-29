# CQIS table definitions and normalization

Question Q25: do the accepted table descriptions determine interoperable bytes
and a total RMSNorm rule on the stated input domain? The security property is
agreement between canonical inference and the integer relations being proved.
Kill criterion: a valid input has no stated representation, the table dimensions
contradict its domain, or two generators can choose different numerical rules.
All three obstacles are present. No production generator exists to repair.

## Exact counterexamples

Run `python3 research/cqis-tables/check_tables.py` (standard library only).
RFC-0004 §4's closed exp domain at B=14 has 16,385 entries, not 16,384.
Arithmetic `t >> 7` takes 129 values, -128 through 0, while `t & 127` takes
128 values. Biasing a signed array index cannot fix this cardinality. Omitting
zero also removes the attained maximum's required probability value. Endpoint
handling or a revised decomposition must be specified, not guessed by a generator.

For RMSNorm §5.3, valid int16 rows `(0)`, `(1)`, `(256)`, `(256,256,1)` give
S=0, 1, 65,536 and 131,073. None admits the stated integer M in `[2^15,2^16)`
and integer a with `S=M*4^a`. Padding these rows with zeros preserves the issue.
For positive S the equation forces `bit_length(S)=16+2a`; every power of four
therefore fails. Even the correct bit-length parity is insufficient: 131,073
forces a=1 and a noninteger mantissa 32,768.25. S=0 has no positive mantissa.
The script compares this criterion against independent exact rational search
on 139 boundary/statistic cases and verifies the concrete sum-of-squares inputs.
Its search range covers all possible exponents for 0<=S<=2^44, the stated
int16, d<=2^14 scope. This is a counterexample to totality, not a rounding proposal.

## Missing numerical and byte contracts

RFC-0004 §§2,4 and RFC-0017 name fixed-point scales and activation variants but
do not fix the closed-form generator functions, their supported parameters or
their rounding. E is an exp output scale; it does not determine the score input
scale or the two sub-table formulas. SiLU/GeLU/sigmoid/softcap need explicit input
and output exponents, GeLU variant, softcap parameter, rounding and overflow
rules. A1 defines requantisation; it does not specify transcendental table rounding.
RMSNorm additionally needs normalization remainders, zero behavior and the roles
of feature count and epsilon. A wider mantissa interval alone cannot solve exact
representation of arbitrary large statistics.

RFC-0008 §4 gives `TableId=H(name || definition_version || params)`;
RFC-0011 §1 puts table ids in the passport. Neither fixes the framing, parameter
encoding, row order, signed entry encoding or complete table definitions.
Stable ids require these choices and verifier agreement. The range tables have
an exact set already; that alone does not resolve their canonical bytes or the
other generators required by E5-02.

## Recommendation and limits

Amend RFC-0004 through Draft A2 and coordinate registry changes with RFC-0008,
passport changes with RFC-0011, and activation variants with RFC-0017. Retain all
E5-02 acceptance criteria. Error analysis needs a named real function, exact
parameters and units; finite precision evaluation must certify each rounded entry
or state and prove the selected approximation rule. A max-error number cannot be
derived from a function name alone. These are prerequisites to Rust/NumPy parity,
lookup controls and model fidelity, not substitutes for those gates.

No core arithmetic, challenge, claim, commitment, proof byte, benchmark or
cost-model constant changes. No research assertion earns NC-0104/0105 or
NC-0404/0405 credit. E5-01 signed scalar arithmetic remains valid independently.

## Certified exponential continuation

The [candidate argument](../../formal/cqis-exp.md) and
[exact artifact](exp-candidate.json) develop the exp portion of the complete
A2 contract. Run `python3 research/cqis-tables/check_exp.py` to regenerate all
evidence and compare the checked artifact. Positive-series reciprocal intervals
independently check 6,948 component entries and every one of the 16,385 corrected
example entries. Alternating-series/dyadic certificates prove rounding without
host floating point; all original domain endpoints are retained.

The two-table product is not necessarily monotone: for B=14,F=10,E=12, the
candidate drops from 1 to 0 between t=-9216 and t=-9215. It has 29 such decreases
and a strict absolute-error bound of two output units. The correctly rounded
candidate has error at most half an output unit and is monotone. Decomposed
evaluation requires a correction indexed by the full original domain, with
values in {-1,0,1,2}; it changes 5,517 example entries. This is an additional
lookup/table cost, not an implicit precision fix or a four-entry lookup.

F=10 is an example only. The study does not select a model's score scale,
authorize either representation, define canonical table/passport bytes or prove
model fidelity. A2's other activations, total RMSNorm and registry requirements
remain. Certificate/index/parameter mutations are research controls only.

## Strict activation-rounding investigation (Q25 continuation)

Question: can explicit sigmoid, SiLU and softcap candidates certify their signed
int16 outputs across independently chosen scales, including values arbitrarily
close to a rounding boundary? The security property is deterministic agreement
with the stated real function; table generation and direct lookup cost concern
c_a/c_lu/T_misc. Kill criterion: any uncertified rounding, substituted limit,
silent clipping or dependence on host floating-point behavior. Strict rational
enclosures and an independent positive-series oracle test this question.

The [candidate definitions and proof](../../formal/cqis-activations.md) retain
strict interval endpoints, including a rounded-to-zero exponential lower bound.
At (F,E,t)=(1,0,32767), SiLU rounds to 16383, whereas its limiting input value
rounds to 16384. A softcap with c=1/2,E=0 rounds every finite input to zero,
whereas its positive limiting cap rounds to one. Neither limit substitution
preserves the integer function, regardless of its small real approximation error.

`check_activations.py` compares every entry of three complete int16 tables
(196,608 entries) and 30,000 seeded scale/cap cases against independent positive
Taylor/reciprocal bounds. The [artifact](activation-candidates.json) records
exact extrema and digests. Each certified entry has absolute error at most
1/2 output unit; generation rejects overflow or unresolved bounded precision.
Parameter boundaries, strict endpoints, exact zero/ties and one-field
certificate/metadata/shape mutations are included. Direct tables have 65,536
rows each; no decomposition or protocol-byte identity is selected here.

Recommendation: continue Q25 with GeLU variants, total RMSNorm/rsqrt, authenticated
registry bytes and scale alignment, then complete A2 review and native delivery.
This continuation leaves A2 Draft and E5-02 blocked. No lookup/range binding,
native negative-control, static-certificate or model-fidelity credit is claimed.

## GeLU variant investigation (Q25 continuation)

Question: can exact GeLU and the explicitly parameterized tanh approximation
each receive correct signed integer rounding certificates, including their
Gaussian tails and half-unit limits? Kill criterion: a guessed pi/square-root
constant, uncertified tail, implicit variant substitution or floating-point
authority. The security property is definition agreement; direct-table costs
remain in c_a/c_lu/T_misc. A separate pi identity and positive integral series
checks the candidate; the complete A2 contract remains blocked.

The [definitions and argument](../../formal/cqis-gelu.md) certify exact GeLU
and tanh-GeLU as distinct real functions, with coefficient 8943/200000 exactly
in the latter. Machin pi bounds and exact integer-root inequalities certify
constants. Integrated alternating-series bounds and a strict positive Gaussian
tail bound certify the exact form; strict exponential transformations certify
the tanh form. No tail is replaced by zero, including at rounding boundaries.

`check_gelu.py` checks all 131,072 example entries and 20,000 seeded scale cases
using another pi identity, integer root bisection and a positive integral series.
The [artifact](gelu-candidates.json) records distinct digests and 108 differing
entries (one integer unit each) at F=E=8. The 1/2 output-unit error guarantee is
relative to each variant's own real function; it is not a bound on the model
effect of choosing tanh instead of exact GeLU. Whole-configuration overflow,
constant-cache type aliases, boundaries, altered certificates and wrong variant
metadata reject. Direct-table and eventual membership costs remain explicit.

Recommendation: continue Q25 with total RMSNorm/rsqrt and canonical registry
and passport bytes, then complete scale alignment, review and native delivery.
This is numerical evidence only, not production lookup/identity controls,
static certificates, Rust/NumPy inference parity or model-fidelity acceptance.

## Total normalization investigation (Q25 continuation)

Question: can a total positive-rational RMS statistic, unique even exponent and
bounded mantissa remainder support a certified int16 rsqrt table and explicit
signed output rounding, including the zero row? Kill criterion: an unrepresented
valid statistic, discarded remainder, guessed epsilon/dimension, wrapped output
or dynamic field-fit argument. The security property is exact integer semantics;
normalization/table/limb work concerns c_a/c_lu/T_misc. The candidate is
checked against independent rational normalization and integer-root bisection.
This study does not admit a native norm or complete A2/E5-02.

The [candidate and argument](../../formal/cqis-rmsnorm.md) define epsilon as an
explicit positive reduced rational, include the feature dimension, and retain
the normalization remainder. The mantissa interval spans both exponent parities;
all original zero/nondivisible counterexamples now normalize. An int16 rsqrt
mantissa and signed derived shift define the checked wide output. Negative
shifts and products exceeding int32 are not passed to the existing scalar API.

`check_rmsnorm.py` independently checks all 49,152 rsqrt entries, all 32 exponent
transitions and 10,000 row cases. The [artifact](rmsnorm-candidate.json) retains
uniform squared inverse-error bounds, exact example remainders and output
differences: 8,357 rows fit, while 1,643 reject overflow; 1,257 accepted output
elements differ from correctly rounded exact real RMSNorm, by at most two units
in this sample. The analytical error bound, not the sample, governs all inputs.
Zero input remains zero; no clipped or wrapped result is published.

Static magnitudes derive from parameters. The base-256 multiplication study
checks both sides below M31's centered half-bound, with fixed byte/carry ranges
and boundary carries. Altered remainders, exponents, entries, outputs, bounds,
limbs and carries reject for stated reasons. Native sign/addition/comparison/
shift/range consumers and bound schemas remain required under A3; these checks
are not production NC or INV-5 certificate credit.

Recommendation: integrate the candidate with canonical registry/passport bytes
and complete A2/A3 review, then deliver native generators/reductions and fidelity
evidence. No default epsilon, scale, architecture, benchmark constant, extra
weight pass or committed intermediate is selected by this research.

## Larger exponential-domain investigation (Q25 continuation)

Question: can the product construction cover larger integer score differences
without an exponential-size full table or an implicit change of integer
semantics? Kill criterion: either sub-table exceeds 2^16 rows, the inclusive
endpoint is lost, split-dependent rounding is hidden, or a full correction table
is treated as constant storage. Table/evaluation work concerns c_lu/T_misc;
integer index/recombination bounds remain mandatory. This extends the candidate
domain while leaving the complete attention and A2 contracts unadmitted.

The [wider construction](../../formal/cqis-wide-exp.md) supports B<=31 with an
explicit split k, two sub-tables of at most 65,536 rows each, and the same strict
two-unit absolute error bound. The split is semantic: at B=14,F=10,E=12,
k=7 versus k=6 changes 1,239 outputs, including 0 versus 1 at t=-9152.
It must be authenticated by the future table identity. The full u bound and
wide integer/limb obligations remain; small sub-tables alone do not prove them.

`check_wide_exp.py` checks 305,286 sub-table entries against independent exact
rounding, then endpoints/partition boundaries and 10,000 seeded draws per wide
case. The [artifact](wide-exp-candidates.json) records parameters, row counts,
sample counts and digests. These are cardinalities, not timing measurements;
the large virtual domains are sampled, not exhaustively enumerated. A strict
positive exponential-tail enclosure certifies large arguments without replacing
the real function by zero. Wrong split metadata, missing endpoint, altered
certificate, invalid domain and excessive correction allocation reject.

Recommendation: carry the explicit split and parameter/domain consumers into
the A2 registry contract. Direct/corrected D remains limited to B<=15 by this
research API because its indexed correction table has 2^B+1 rows; wider P_k
uses no such table. The original default-split outputs remain unchanged.
Attention score alignment, canonical bytes, native consumers/parity and model
fidelity remain separate delivery obligations. A2/E5-02 stay Draft/blocked.

## Table identity investigation (Q25 continuation)

Question: can every candidate component table have unambiguous version/parameter
bytes, deterministic signed row order and padded data, with definition validation
before admission? Kill criterion: metadata aliasing, an implicit variant/split,
unchecked rows under an honest identity, resource-controlled allocation from
untrusted lengths, or padding accepted as real membership. The property is
definition binding; generation/evaluation contributes to c_lu/T_misc. This
research does not supply a passport commitment, lookup, composition compiler or
whole CQIS identity. A2 and E3-08 remain uncompleted.

The [descriptor/data candidate](../../formal/cqis-table-identity.md) gives
closed names, exact version and parameter framing, ordinary BLAKE3 identities,
signed i32 row bytes and descriptor-derived padding. High/low/correction names
bind the exp split; correctly rounded direct exp excludes that irrelevant
parameter. Activations retain their variant/scales/cap, rsqrt fixes its versioned
mantissa function, and range tables have one column. No unbounded virtual exp
function is silently registered as a component table.

`check_identity.py` independently assembles all 13 descriptor frames and nine
complete table-data encodings; the [artifact](table-identity-candidates.json)
retains exact bytes/ids, shapes and data digests. Every descriptor truncation,
unknown/invalid parameter, huge declared length, altered id/row/order/padding,
trailing byte and alternate field-congruent integer encoding rejects. Table
admission regenerates the complete numerical definition; an identity or data
digest alone never authenticates arbitrary row contents. Whole-table overflow
also rejects even when its descriptor is syntactically valid.

Recommendation: integrate this component contract with complete function
composition/configuration identities and the passport's validated table roots.
Native registry/MLE evaluation parity, real NC-0404/0405/0701 consumers and the
full A2 acceptance remain. This study neither proves lookup inclusion nor
turns a research data digest into a passport commitment. No performance result,
new challenge, field-faithfulness exception or committed intermediate is added.
