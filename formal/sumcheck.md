# Sumcheck reduction obligation (RFC-0006 A1)

Status: precise mathematical statement; not a machine-checked Lean proof.

Let K be QM31 or OM31, q=|K|=p^d. Let f_1,..,f_t be fixed multilinears on K^m,
P a fixed polynomial of total degree at most δ<=4, and v a fixed field element.
Let the interactive verifier check exactly the RFC-0006 A1 degree-bounded messages
and derive each independent uniform r_j after receiving its round message. Let
v_1,..,v_t be the final values, and require P(v_1,..,v_t) to equal the last running
claim. If v differs from the Boolean-hypercube sum of P(f_1,..,f_t), then

```
Pr[all round/final-composition checks pass AND all v_i = f_i(r)] <= m*δ/q.
```

Each round with a false current claim either fails the Boolean-sum check or
presents a degree-at-most-δ polynomial different from the true residual sum.
Their difference has at most δ roots. A union bound over m rounds bounds the
chance that the false claim becomes true. If it never does, true final input
evaluations contradict the final composition check. Degree zero and m=0 have
zero loss; the specified direct checks apply. No claim is made that all emitted
input evaluations are true merely because the round checks passed.

Source: Thaler, *Proofs, Arguments, and Zero-Knowledge*, §4.1. Applying Fiat–Shamir,
closing private evaluation obligations, composing instances, and providing ZK
require their separate accounting/proofs; Q12 is not discharged by this statement.
