# Configured RMSNorm output (Q26 / Q31)

Revealing Draft RFC-0004 A3 research for RFC-0022 §2.3. Question: can the
complete same-exponent factor consumer select the required rounding branch
and bind actual X/H/J/Y through the product, rounding and signed-output
consumers? Costs are c_a/c_sc/c_lu/T_misc. Kill the design if a supplied
selector can choose a branch, a valid substituted child breaks a shared
root, unused qd/r escape their zero requirement, or any original consumer
is omitted at a zero factor. No new Accepted cut or protocol is proposed.

Retain four complete children in order: configured output factors, signed
output (including canonical product sign and actual signed X/H/Y), product
xy*J=t, then the selected left or division consumer. Derive the branch only
after the complete factor proof verifies. Its actual64 slots supply branch
flags and exact byte slices B[2:18], h[18:34], L[34:42]. No supplied selector
or child receipt authorizes verification. Expected proof keys depend on
the verified branch, so an alternate branch proof cannot be ignored.

Fifteen external roots are N,a,A,D,factors,X,H,xy,s,Y,q,J,t,qd,r in that
order. Each reused role has one id and root. The left branch checks the
actual t/q roots with the actual L slice, and binds qd/r to canonical
zero vectors of16N byte slots. The right branch checks q/B/qd and t/h/U
through complete division, including 0<=r<B. Its auxiliary U root is a
required32-byte proof field and is consumed by the division child. Neither
branch introduces a free scalar factor. X and Y remain actual signed16
sources; q=abs(Y), product sign and rounded-zero rules remain mandatory.

Namespace before implementation: identity<2^28, base=2^63+2^34*identity.
Factor child16*identity+1 reserves[base+2^30,base+2^31). Signed-output child
4096*identity+1 reserves[base+2^22,base+2^23). Division4096*identity+2
reserves[base+2^23,base+3*2^22). Product65536*identity+1 reserves
[base+2^18,base+2^19); left65536*identity+2 reserves
[base+2^19,base+3*2^18). Internal B/h/L/U ids are base+1..4. All fifteen
distinct external ids stay outside the whole parent span. There is no
parent A3 id because exact root joins add no new algebraic challenge.

Final transcript context binds the complete expected function and role ids,
all fifteen expected roots, the verified branch, right-branch U root if
present and all four verified child states. This wrapper draws no challenge.
Add the four complete accounts, retaining each lookup identity separately.
In particular preserve the factor child's selection reduction6/|K|,
product identity(k-1)/|K| and product reduction4b/|K| in addition to its
A3 numerator199+9b+18g. Signed output adds177a+183 and product adds39a+85
to the A3 numerator; add the selected left/division account without changing
its ranges or repetitions. Every lookup reduction remains unsquared.
Binding, FS/H, private composition and model ownership remain additional.

Tests first:10000 independent NumPy output/factor/source joins, all33 exponent
positions, e=-1/0/1 and static extremes. Require both fields/repetitions,
ragged rows, signed endpoints, negative products rounding to zero and zero
inputs. Substitute valid factors, signs, products, q and selected branches;
mutate every external root, both unused roots and the right total root.
The e=-16 full-row case necessarily has zero output; require a separate
full-row nonzero left case and a full-row right case before publication.

Continue Q26/Q31. This wrapper does not yet join N/a/A/D to the normalized
interval, N to the statistic of the same X, or J to configured rsqrt(M).
Complete normalization, native/model/private inference, fidelity and original
task criteria remain open. No benchmark or additional weight pass is claimed.
