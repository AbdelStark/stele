# Batching reduction obligation (RFC-0006 A2)

Status: precise mathematical statement; not a machine-checked proof.
Let K have size q=p^d. Fix all tensors, ordered claims and descriptors before an
independent uniform gamma. Let s_b be each true Boolean sum in mode 0, or y(z_b)
in mode 1. If at least one v_b differs from s_b, then
E(T)=sum_b T^b(v_b-s_b) is nonzero of degree at most t-1. Consequently
Pr[E(gamma)=0] <= (t-1)/q. This includes gamma=0; no nonzero conditioning is used.

Mode 0's leading selector has Boolean sum one. Its coordinates are disjoint from
each member's real coordinates, so G has individual degree at most D even when
δ_b=4 and padding is present. For constant P, moving the selector inside P
would change the sum; A2 does not perform that transformation.
Mode 1's eq interpolation identity gives sum_x y(x)eq(z_b,x)=y(z_b), and G=y*A
has individual degree at most two. A is computed from the fixed points and gamma;
prover-supplied evaluations of A are not inputs to the final check.

Conditioned on E(gamma)!=0, apply the sumcheck round argument to this now-fixed G.
Each false residual polynomial either fails the Boolean-sum check or differs
from the true polynomial by a nonzero polynomial of degree at most D. Fresh
uniform round challenges erase the discrepancy with probability at most D/q.
Thus, for either mode,

`Pr[all checks pass AND every emitted evaluation is true] <= (t-1+M D)/q`.

The ledger conservatively records (t+M D)/q. Singleton and M=0 cases obey the
same formulas; no member is discarded when its random coefficient vanishes.
This is our application of the root bound and sumcheck argument in
[Thaler, Lemma 3.3 and Proposition 4.1](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf).
It is not a claim of Fiat–Shamir security, true downstream evaluations, ZK or a
complete profile budget. Q12 and real claim consumers remain necessary.
