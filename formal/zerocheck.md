# Zerocheck obligation (RFC-0006 A3)

Status: mathematical argument, not a machine-checked proof. Fix K of size q=p^d,
the descriptor and all original tensor functions before any challenge. Let
s=2^k, j=m-k, D=δ(s-1), and suppose one Boolean row violates C=0. All challenges
in this statement are fresh independent uniform elements of K; Fiat-Shamir is
not asserted. The event bounded below includes truth of every emitted claim.

Choose one bad prefix b*. Its residual polynomial
R(alpha)=sum_z eq(alpha,z) C(f_1(b*,z),...,f_a(b*,z)) is multilinear in j variables
and nonzero: at the bad Boolean suffix it equals that row's nonzero residual.
By Schwartz-Zippel, Pr[R(alpha)=0]<=j/q. When j=0 this event is impossible.
For k=0 there is just one prefix and this is the true initial weighted sum.

For k>0, conditioned on R(alpha)!=0, the true Q_0 has a nonzero evaluation at
b*. The verifier's interpolant has zeros at every b in B, irrespective of the
prover's outside values. Both polynomials have degree at most D, so their
difference is nonzero. A fresh u erases the discrepancy with probability at most
D/q. Sampling u in B is allowed and is included in this bound. There are D+1
interpolation nodes, all distinct because D<=60<p; δ>=1 ensures D+1>=s.
For δ=1 the transmitted outside list is empty but the zero polynomial and its
challenge are still bound. For k=0 there is no skip collision event.

Condition on a surviving discrepancy. The true next tail polynomial has degree
at most δ, with weighted endpoint sum equal to the true preceding residual.
A false preceding running value cannot pass the weighted check with the true
polynomial. Any accepted polynomial therefore differs nontrivially from the
true polynomial, and a fresh round challenge erases this difference with
probability at most δ/q. This argument also holds at alpha_h=0 or 1; neither
polynomial reconstruction nor the check divides by those weights. For δ=0 a
nonzero difference is constant and has no roots.

After j rounds, true slice claims force each w_i to equal F_i(u,r) by Lagrange
interpolation. The final check cannot conceal a surviving discrepancy. Union
bound gives (j+D+j*δ)/q; m=k=0 is deterministic. This adapts the elementary
argument of [Gruen, Appendix A.4](https://eprint.iacr.org/2024/108) with full
endpoint messages and original-tensor slice claims. It assumes no multiplicative
subgroup and makes no claim that hybrid interpolation is an ordinary MLE.

Every original slice claim must have an actual consumer, including zero-weight
and unused slices. Downstream soundness, consistent virtual tensors, padding,
integer bounds, PCS, ZK and the concrete FS/H budget (Q12) remain separate.
Both profiles use this proven algebraic bound; neither is certified by it.
