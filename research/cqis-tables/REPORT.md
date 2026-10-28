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
