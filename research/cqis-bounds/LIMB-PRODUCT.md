# Consumed limb sum of products — Q26 / Q31

Status: research for Draft RFC-0004 A3, RFC-0008 A2 and RFC-0012 A8, using
Accepted RFC-0006 A1/A3 and RFC-0021 range_8. E5-03 remains blocked with its
original criteria. Full reveals are not a private PCS/ZK or production cut.

Question: can the unsigned limb sum-of-products relation consume the actual
input/output/carry sources with work linear in their digit payloads, rather than
trusting plaintext multiplication or materializing a quadratic digit-pair table?
The properties are integer faithfulness of every column, row pairing, virtual
evaluation consumption and exact output/carry binding. Symbolic costs are
c_a/c_sc/c_lu/T_misc; no measured constant or inference weight-pass change.

Kill criterion, stated before implementation: stop if a false product, legal-range
wrong carry, wrong source/row pairing or unconsumed virtual value can pass; if
the polynomial degree or complete challenge accounting is unsupported; or if
the prototype needs an N*P^2 replicated grid. No verifier multiplication oracle,
range scan, challenge retry, inverse of a random expression or new production cut.

Candidate: use the existing exact limb input consumer on N=2^a rows per side,
P=2^h original digit planes, and separate actual capped scalar consumers on output
digits and carries. Expected limbs.Spec supplies all bounds. With K result
columns, pad output/carry arrays to S=nextpow2(K+1); force C0=CK=0 and excess
positions to zero through their actual caps. The caller independently supplies
input and output roots. A carry root and all completed range states are fixed
before one fresh transcript challenge rho.

Let A_r(X)=sum_i A[r,i]X^i and B_r similarly. Check
sum_r A_r(rho)B_r(rho)=sum_k(Z_k+radix*C_{k+1}-C_k)rho^k with a degree2 A1
sumcheck over rows. Consume each virtual final at row point t with a degree2
digit sumcheck for sum_i rho^i*FoldRows(A_i,t), and similarly B. Its public power
final is evaluated exactly; its source final at digit point u maps to the actual
original point u+[side]+t. Both sides retain the same row point. These steps
cost O(NP+S) arithmetic, plus all existing ranges, roots and original consumers.

Conditional on actual input/output/carry ranges, every real column has both
sides strictly below p/2 by the static certificate. High source planes vanish;
the residual polynomial has degree at most K-1. A false integer column therefore
survives rho with probability at most (K-1)/|Kfield|. Add three A1 losses
(2a+4h)/|Kfield| separately, retaining every nested range/lookup term. There are
1+a+2h additional Sumcheck draws, no new label. Hash binding, FS/H and joint
private composition remain separate. Even K=1 retains its rho draw and zero loss.

Never fix rho to the radix: an interior carry change contributes
delta*X^(j-1)*(X-radix), so that choice would hide it. The honest producer should
consume supplied result/carry witnesses and perform only the random-point proof
arithmetic, not recompute the original integer multiplication as a verifier check.
