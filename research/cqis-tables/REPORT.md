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
