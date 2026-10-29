# Q26: candidate exact scale policies

Question: which reproducible weight and activation conversions can complete the
numerical part of Draft RFC-0004 A3 without implicit calibration, saturation or a
zero-scale division? The security property is exact configured semantics; cost
lies in quantiser preparation and subsequent c_a scale/range work. Kill criteria:
an output outside the declared symmetric range, a nonminimal scale choice, a
rounding mismatch, a divided zero row or silent static overflow.

This is a candidate policy, not an Accepted contract or native implementation.
The existing source-scalar study supplies exact dyadic checkpoint values. Format,
tensor/channel order, modes and all scale parameters still need authenticated
canonical configuration and passport bytes. The prototype takes nonempty rectangular
channel arrays; native shape/resource admission remains a separate requirement.

## Weight scales

The configured width b is explicitly 4 or 8, with symmetric output limit
q=2^(b-1)-1, so outputs lie in [-7,7] or [-127,127]. This proposes excluding the
negative signed endpoint; no current field bound or range consumer is silently
tightened. For output channel j, let M_j=max_i |w_ji| and M=max_j M_j.
For M>0 choose the unique smallest integer e satisfying

    M <= q*65535*2^e.

Thus e=ceil(log2(M/(q*65535))), computed exactly with numerator/denominator bit
lengths and one comparison. Set m_j=max(1,ceil(M_j/(q*2^e))),
s_j=m_j*2^e, and W_ji=R(w_ji/s_j), with signed half-away R from RFC-0004 A1.
For an all-zero tensor, choose e=0 and all m_j=1. An all-zero channel inside a
nonzero tensor uses its shared e, m_j=1 and all-zero integer outputs.

By construction 1<=m_j<=65535 and M_j<=q*s_j. Therefore |W_ji|<=q without
clipping. Each successful value obeys |w_ji-W_ji*s_j|<=s_j/2. If M>0,
q*65535*2^(e-1)<M, proving minimality of e. When m_j>1,
q*(m_j-1)*2^e<M_j, proving minimality of that channel mantissa.
All inequalities are exact rational statements; no distributional assumption is
needed. Minimal e is a proposed deterministic precision policy, not a demonstrated
model-fidelity optimum. The chosen int4/int8 widths are explicit configuration;
there is no automatic selection or hidden calibration.

Finite binary64 source values give -1100<e<=1024, a conservative bound also used
by the independent search. This does not authorize those exponents in inference:
the full quantiser must still derive legal forward scales, alignment, shifts and
static certificates. A shared weight exponent is not a scalar Requant right shift.

## Dynamic and static input conversion

For a nonempty signed-int16 row X, let M=max_i |X_i| and s=ceil(M/127).
Keep s=0 exactly when M=0, and return all zeros without division. For s>0 set
Y_i=R(X_i/s). The identity 0<=127*s-M<127 holds and |Y_i|<=127;
|X_i-s*Y_i|<=s/2, including zero. The full format gives 0<=s<=259.
In particular, both int16 endpoints require s=259 because 127*258=32766.
The candidate does not replace the zero-row ceiling by a nonzero sentinel.
Future proof consumers must enforce attained M and every required range, and
handle the zero case explicitly. Observed M is not a static bound certificate.

Static mode selects an explicit integer scale 1<=s<=65535 in the same source
integer units, computes R(X_i/s), and rejects the entire row if any output lies
outside [-127,127]. It never saturates, changes the configured scale or switches
modes on failure. Accepted static outputs satisfy the same s/2 error bound.
Static and dynamic policies are different: s=258 suffices for the full int16
range after nearest rounding, while s=257 rejects X=-32768; this does not change
dynamic's exact ceiling definition. No calibration or automatic fallback rule is
inferred. Residual and per-tensor exponents still require their explicit contract.

## Reproducible evidence and recommendation

Run `python3 research/cqis-checkpoint/check_quantiser.py`. The independent reference
uses rational bisection for the shared exponent and each channel mantissa, and
distances to adjacent signed integers for rounding. The candidate instead uses
bit lengths, ceilings and magnitude quotient/remainder. Inputs come from decoded
finite words of all four candidate scalar formats, with extreme and zero cases.

10,000 tensors per width agree exactly, including all-zero channels/tensors and
the smallest/largest finite binary64 values. Every output also checks range,
scale minimality and its exact uniform error bound. Another 10,000 int16 rows
check the dynamic scale against a complete bounded search. All 10,000 static rows
match independent rounded decisions: 6,875 succeed and 3,125 reject overflow.
Explicit positive/negative half ties, zero rows, endpoint scales, malformed shapes,
wrong types, non-dyadic/out-of-format scalars and invalid configured scales are
also checked. These counts/checksums are correctness evidence, not benchmarks.

Continue Q26 by reviewing these choices alongside canonical quantiser/weight
bytes, tensor ordering, residual alignment, scale conversion and all per-reduction
certificate schemas. RFC-0003 A2 / RFC-0004 A3 and E5-03 remain blocked/Draft.
Do not import this prototype into core crates. Native Rust/NumPy parity, actual
NC-0102/0109 consumers and the full inference/fidelity criteria remain required.
No challenge, soundness-ledger term, new commitment, weight pass or profile
admission is introduced; there is no measured performance result.
