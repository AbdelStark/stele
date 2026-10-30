# Complete RMSNorm arithmetic composition (Q26 / Q31)

Revealing Draft RFC-0004 A3 research for all arithmetic obligations in
RFC-0022 §2.3 and the canonical integer operation in RFC-0021 §2.3.
Question: can complete consumers bind the same X/H/Y sources through the
statistic, numerator, unique normalized interval, configured reciprocal
lookup and selected output branch? Costs are c_a/c_sc/c_lu/T_misc. Kill
the design if a valid substituted child changes a reused value, a formula
replaces actual reciprocal membership, an incorrect exponent passes at zero
input, or a zero output suppresses any original consumer.

Retain seven complete children in fixed order: configured output, full
statistic, numerator, mantissa product, normalization sum, strict normalization
remainder and reciprocal lookup. The first child already includes complete
same-a factors, signed X/H/Y, canonical product sign, xy*J and the selected
whole left/division proof. The other children close its remaining arithmetic
obligations. Every child verifies from expected roots; supplied receipts or
producer normalization results never authorize acceptance.

Nineteen roots have fixed roles N,a,A,D,factors,X,H,xy,s,Y,q,J,t,qd,r,
S,M,MD,R. Here r is output remainder and R is normalization remainder.
The statistic consumes the same raw signed16 X root and emits the8-byte S
root consumed by the numerator. N=ed*S+en*unit uses expected parameters,
so positive epsilon establishes N>0 even when X=0. Configured factors bind
A=N*4^-min(a,0) and D=P*4^max(a,0). Mantissa product binds M in[16384,65535]
and MD=M*D; normalization sum binds A=MD+R; strict remainder binds0<=R<D.
Their interval therefore selects the unique a. The actual complete49152-tuple
reciprocal lookup consumes exactly M and J. The output child consumes the
same J and signed sources. All padded byte widths must match exactly across
these roles, including LP's strict next-power output padding.

Namespace before implementation: identity<2^24 and base=2^63+2^38*identity.
Configured output16*identity+1 reserves[base+2^34,base+2^35). Statistic,
numerator, mantissa-product and sum identities2^20*identity+1..4 each reserve
2^18 slots, starting at base+2^18 through base+2^20. Strict remainder
2^26*identity+1 reserves[base+4096,base+8192), and reciprocal2^26*identity+2
reserves[base+8192,base+12288). All nineteen distinct external ids remain
outside the full parent span. Child ids and source spans remain disjoint.

The parent draws no challenge. Its final transcript binds complete expected
function/role bytes, all nineteen roots and seven verified states. Concatenate
each child's lookup identities without combining or squaring reductions.
Add the actual reciprocal identity(98304/|K|)^r and reduction392r/|K|.
Retain separate range/A3, statistic A1, factor selection and limb-product
identity/reduction totals. Configured output, numerator, mantissa product
and normalization sum each keep their own product error event; aggregating
their numerators is a union bound, not a joint identity. Preserve all child
receipts and binding/FS/H/private losses separately. No profile is admitted.

Tests first:10000 integer cases checked against independent Fraction interval
enumeration, integer root bisection and NumPy signed rounding. Include epsilon
extremes, signed endpoints, overflow rejection, both branches and all static
byte-width joins. Check every root and genuine substituted statistic, numerator,
factor and lookup children. Both fields/repetition counts must retain the
whole reciprocal table, including rounded zeros and nonzero left output.
Require full16384-row wide/rounded-zero, nonzero left and nonzero right proofs.
No cached receipt, queried-row table or per-row proof loop is permitted.

Configured-output controls and its matrix are still running in the parent
worktree. Any parent fix must flow here by ordinary merge before publication.
Continue Q26/Q31. This is revealing arithmetic research, not private or model
inference. Native lowering, authenticated model/configuration/source ownership,
PCS/ZK/FS, fidelity, GPU/scale and original task criteria remain open. No new
Accepted cut, benchmark result or extra weight pass is claimed.
