# RMSNorm biased output sum (Q26 / Q31)

Revealing research under Draft RFC-0004 A3 for RFC-0022 §§2.1,2.3,5's
bias role. This consumes U=t+h; selected branches, division equality, strict
remainder, signed output and complete normalization remain required.

Question before implementation: can the full16384-row product source and a
wide scalar rounding bias feed one faithful byte-addition proof without a
larger lookup domain? Costs are c_a/c_sc/c_lu/T_misc. Kill the design if a
supplied bias is mistaken for a configured factor, padded rows acquire the
scalar bias, a split result is granted a whole bound without addition, or
any original source/carry/output claim loses its consumer.

Retain a whole range t<=2^44 with eight byte planes and the independently
expected product root. Range scalar h<=hmax, then reconstruct its external
16-slot root from the actual verified bytes with exact zero extension. Actual
same-exponent authentication must later verify the complete64-slot factor
source and derive h from its slice18:34. The scalar range alone grants no
configured-factor authority.

Use the closed bias certificate with Amax=max(2^44,hmax), count2 and right
bound1, giving Zmax=2*Amax. Range the low64 result with cap min(Zmax,2^64-1)
and the optional high part with cap floor(Zmax/2^64). Their independent caps
give digit bounds only. Faithful addition from actual bounded t/h establishes
the whole U bound. Zero-extend the verified parts to a16-plane external U
root, shared with the future qd+r consumer.

Partition C1..C16 into four families of four N-element planes. Use a whole
Boolean range for each family with a nonzero static cap; other families are
public zero. Real caps come from the closed certificate, and padded row caps
are zero. Each family has at most65536 byte words. Both carry endpoints and
every unused plane remain zero; the prover cannot choose active families.

Let P=2^c pad the closed column count to8 or16. One degree-one A3 over PN
entries proves t_k+masked_h_k+C_k=U_k+256*C_(k+1). The bias view multiplies
each actual scalar byte by the known real-row mask before broadcasting it.
Thus padded t/U/carry rows stay zero even for nonzero h. This public mask
derives only from the expected shape; no supplied selector is accepted.
All five original views have independent consumers at emitted points.
Every external/auxiliary root and verified range state precedes parent
weights, rounds and finals. Output bytes beyond P remain exact public zeros
established by range caps/widths and explicit zero extension.

At maximum metadata, hmax=2^89, Zmax=2^90, K12/P16. C1..C11 are Boolean,
C0/C12 and all higher carries zero. Column sides are at most511, with twice
that below p. The high result range needs at most four byte planes; each
range stays within131072 bytes and lookup dimension18. The external U root
has262144 canonical-u32 slots at N16384. This is not packed model storage.

Namespace: identity<2^44, base=2^63+2^18*identity. Range ids are
4096*identity+1..8 for product, bias, low, optional high and four carry
families. Inactive roles retain reserved ids. Product source is external;
other sources use base+1..7. Parent A3 id is16384*identity+512, with five
derived view ids base+16..20. Three distinct external ids stay outside the
whole parent span. All descendant A3 ids precede the parent invocation.

Before implementation, let bh/bl/bu be byte-width exponents for bias and
low/high result ranges, H indicate an active high range, and g count active
Boolean carry families. Set X=3+bh+bl+H*bu, with a=log2N. Total A3 numerator
is (20+9H+9g)*a+7X+18g+2c; each nonlookup label has
(9+4H+4g)*a+3X+8g+c draws. Lookup dimensions are a+4, bh+1, a+bl+1,
optional a+bu+1 and g instances of a+3. Keep each separate identity
((2^m+255)/|K|)^r and reduction r*(F(m)+F(8)+3m)/|K|,
F(m)=3m(m-1)/2+2m. At full a14/c4, bh4/bl3/bu2, H1/g3 and X12,
A3=930 and each nonlookup label has414 draws. Runtime receipts must agree.

Tests first:10000 NumPy byte additions and exact wide sums, ragged nonzero-bias
rows, zero bias, field aliases, fresh false sums/carries, valid halves beyond
Zmax, original-final substitutions, endpoints and padding. Cover both fields,
both repetition counts and width transitions. Compose actual product and
verified factor sources. A complete full-row maximum proof is required before
publication. Native/model/private inference, fidelity and original task/control
criteria stay open. No performance number or production cut is claimed.

The seed2719 corpus passed10000 cases and6767440 byte-column cells. Its
frozen SHA-256 is
`647ceb1175f24fb6d2ebb0b895f602a950c231919c4b3f03f80761b6f03975e3`.
The corpus includes all75 metadata shift maxima from16 through90, the full
row geometry and namespace limit, exact wide sums and independent NumPy
byte addition. All adversarial controls, padding/boundary checks and actual
product/factor composition passed. The16-proof matrix and full16384-row
maximum are running. Repository gates are queued; CI integration remains
pending. Continue Q26/Q31; this evidence does not graduate the consumer.
