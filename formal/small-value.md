# A1 parity of deferred small-value prefix folding (RFC-0006 A5)

Let K be QM31 or OM31 and embed M31 in K canonically. Let f_i be original
multilinear tables, and let P=sum_t c_t product_{i in t} f_i have total degree
delta<=4 in A1's ordered representation. Repeated factors count with multiplicity;
zero coefficients do not reduce the declared conservative degree.

Fix a prefix length k<=m and let b=max(2,delta+1). For a monomial t define

```
q_t(X) = sum_{z in {0,1}^{m-k}} product_{i in t} f_i(X,z)
q(X)   = sum_t c_t q_t(X).
```

For Boolean z, f_i(X,z) is multilinear in the k prefix coordinates. With typed
integer input tables its coefficients lie in the embedded M31. Hence q_t has
individual degree at most delta and M31 coefficients. Computing it modulo M31
and embedding the result commutes with sums/products in K. Multiplying by the
arbitrary K coefficient c_t after the suffix sum is exact distributivity.

The nodes 0..b-1 are distinct in M31, and b>delta. Evaluations on their Cartesian
grid uniquely determine q over K by tensor-product Lagrange interpolation.
Axis-by-axis extension of a factor uses its degree-one identity
f(u)=f(0)+u(f(1)-f(0)); forming products and summing then gives this same grid.
For delta=0 the width-two grid is redundant but still determines the constant.

After h<k challenges, the A1 round polynomial is precisely

```
g_h(T) = sum_{y in {0,1}^{k-h-1}} q(r[:h],T,y).
```

A grid fold evaluates the corresponding coordinate at the full K challenge.
Thus the sent nodes 0..delta equal the dense A1 nodes. Inductively the same
transcript absorbs yield the same challenges and running claims, including zero
and one challenges; no random inverse is needed. Constant/empty polynomials keep
A1's doubled sole endpoint and their ordinary m challenges.

At the prefix boundary compute every f_i(r[:k],z) directly using the Boolean
prefix eq weights in K. These are exactly the states obtained by k ordinary
multilinear folds. Dense tail rounds and every original final value therefore
agree. Unused inputs remain necessary final obligations. Instance/Round/Final
encodings and the continuation are identical; k is not a new statement field.

This proves deterministic algorithm equivalence over the stated fields, not an
independent Fiat–Shamir theorem. The inherited conditional A1 loss is m*delta/p^d,
with all original final obligations discharged. No extra error term or retry is
introduced. Range discipline, integer certificates, PCS, composition, ZK and Q12
remain independent obligations. Finite tests support implementation parity only.
