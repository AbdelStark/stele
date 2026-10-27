# OM31 modulus candidate for RFC-0003 A1

Question Q9: can `QM31[v]/(v²-u)` provide the missing octic field definition?
The security property at stake is that the challenge domain is a field of order `p⁸`.
Kill criterion: `u` is a square in QM31, or the tower/basis is ambiguous.
This is a research proposal, not accepted protocol behavior or a profile decision.

## Method and argument

For an odd finite field of order `q`, its nonzero multiplicative group is cyclic
([Handbook of Applied Cryptography, Fact 2.213](https://cacr.uwaterloo.ca/hac/about/chap2.pdf)).
Thus `a` is nonsquare exactly when `a^((q-1)/2) = -1`.
For a quadratic extension, `N(a) = a^(q+1)`, so
`N(a)^((q-1)/2) = a^((q²-1)/2)`: the quadratic character is preserved by the norm.
These identities give the following argument for the candidate, independently of a prover.

1. `p = 2³¹-1` is prime and `p mod 4 = 3`; hence `i²+1` is irreducible over M31.
2. In CM31, `N(2+i) = (2+i)(2-i) = 5`.
   Exact modular exponentiation gives `5^((p-1)/2) = -1 mod p`.
   Therefore `2+i` is nonsquare and the specified QM31 tower is a field.
3. `N_QM31/CM31(u) = -u² = -(2+i)`.
   Since `-1 = i²` in CM31, multiplication by `-1` preserves quadratic character.
   This norm is nonsquare, hence `u` is nonsquare in QM31 and `v²-u` is irreducible.

Run `python3 research/r-octic/check_modulus.py` from the repository root.
The script uses trial division for primality and independent schoolbook polynomial
arithmetic. It checks the three nonsquare certificates, plus a square comparison.
For QM31 it uses the equivalent power basis with polynomial `u⁴-4u²+5`, not Karatsuba
or the proposed production tower implementation. All assertions pass.

## Recommendation and limits

Review RFC-0003 A1 and accept the explicit modulus/basis before E1-02 implementation.
The algebra above establishes the candidate's irreducibility; the script corroborates
the identities with exact arithmetic. It is not a formal proof assistant certificate.
No benchmark, field implementation parity, treaty parameter choice, transcript
change, or end-to-end soundness claim follows from this result. The existing
R-OCTIC comparison of profile choices remains open.
