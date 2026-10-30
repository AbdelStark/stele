# Consumed strict RMSNorm remainder — Q26 / Q31

Status: revealing research under Draft RFC-0004 A3, for RFC-0021 §2.3 and
RFC-0022 §2.3 strict0<=R<D. It does not establish the configured origin of D,
the sum A=MD+R, mantissa interval/product, reciprocal or output by itself.

Question before implementation: can actual byte-range consumers and fixed
carry relations prove R<D against independent full16-slot D/R roots, including
strictness at zero/equality and field aliases? Security property: no whole-field
comparison or supplied dynamic cap may replace the integer relation. Cost
terms: c_a/c_sc/c_lu/T_misc for three scalar ranges and fixed16-column A3s.
Kill criterion: D=0, R>=D, a non-Boolean carry, terminal wrap, high-slot source
substitution or altered original final survives its actual consumer.

Derive Dmax from complete expected norm Spec(d,F,G,E,en,ed), retaining every
original domain. Fully verify three scalar wide ranges: D<=Dmax and R,G<=Dmax-1,
where G is the nonnegative gap. Reconstruct independent D/R roots with exact
zero extension to16 canonical-u32 byte slots. Each range has its own complete
lookup, source/cap/carry/terminal and original/public consumers. These are
revealing research roots, not packed/private tensor cuts.

Carry words are c1..c16; c0 is fixed1. Bind all16 canonical field words before
parent challenges. First consume c_j(c_j-1)=0 for every j, then c16=0, then
all16 columns R_j+G_j+c_j=D_j+256*c_(j+1), taking the fixed c0=1. All emitted
claims consume the actual ranged bytes or actual carry/shift views at the same
points. Static nonnegative side bounds are511, with2*511<p; integer faithfulness
therefore follows after the actual byte/bit proofs. Multiplying the column
identities by256^j and summing gives R+G+1=D and thus0<=R<D and D>0. Neither
the producer's gap arithmetic nor a plaintext whole comparison grants acceptance.

Width matters: Dmax may be an exact power of256 while Dmax-1 has fewer bytes.
Derive each range width independently; do not share or truncate one representation.
Every external high slot remains bound and all parent columns retain16 entries.

Namespace: identity<2^50, base=2^63+4096*identity. Three internal range sources
base+1,+2,+3 and carry root base+4. Range ids64*identity+1..3 occupy disjoint
spans starting base+64,+128,+192. Parent A3 ids256*identity+128..130 are
disjoint from child invocations below offset16. External D/R ids are distinct
u64>=2 outside the full parent span. Prefix stele/research/q26/norm-remainder/v1
plus NUL, version/field/repetitions, three ids and complete norm bytes bind two
external roots, three internal source roots, carry root and three verified
range states before parent A3s. No supplied Dmax/gap cap or challenge authority.

Account before implementation: if divisor width=2^bD and remainder/gap
width=2^bR, inherited ranges contribute7bD+14bR A3 numerator. CarryBoolean
dimension4 degree2 adds12; terminal dimension0 adds0; columns dimension4
degree1 add8, total7bD+14bR+20. Three separate lookup dimensions bD+1,bR+1,
bR+1 retain each[(2^m+255)/|K|]^r and r[F(m)+F(8)+3m]/|K|. Parent draws8
ZeroWeight and8 Sumcheck; complete nonlookup totals3bD+6bR+8 of each.
Binding/FS, same-root configured D and MD/A composition, reciprocal/output and
whole-model/private proof obligations remain additional.

Tests first:10000 independent NumPy byte additions and object-integer gap
identities, including carry chains and unequal range widths. Complete proofs
cover both fields/repetitions, D=1/R=0, endpoints, maximum124-bit D and width
transitions. Check exact accounts/draws and all actual final claims. Genuine
range proofs for R=D, D=0 and a field-alias remainder must fail parent columns;
non-Boolean carries and nonzero terminal must fail their respective consumers.
Composition-preserving altered source finals, stale range words, full-root high
padding, malformed shapes/fields/metadata and supplied caps must reject. Compose
actual paired A/D, bounded M/MD and sum proofs with the same R/D roots.

Recommendation: continue Q26/Q31 with actual normalized-interval composition,
complete rsqrt lookup and wide output branches. Original task status/criteria,
native controls, physical/private/model ownership and fidelity remain open.

## Reproduction and evidence

Run `uv run --locked --script research/cqis-bounds/check_norm_remainder.py`.
Tests first failed with the missing module. Seed2702 passed10000 independent
NumPy object-integer gap identities and int64 byte-column additions, with
canonical source reconstruction and complete metadata-domain checks. Frozen
corpus SHA-256:
`198097e6694b80c34214660bcde4f0d29607dabc3842c980610eb151155df1d2`.

All20 complete proofs passed across both fields/repetitions, including D=1,
R=0, maximum R=D-1 and an actual124-bit divisor. Twelve proofs exercise
unequal divisor/remainder range widths at Dmax=2^32 or2^64. Every proof checks
exact losses, challenge draws and all seven original final claims. Frozen states:
`a949dd85b7745908ed56a42a83f0a48e3e7a2da887a3f3757f0a2795d0c1ea51`.

Genuine range proofs for R=D, D=0, R>D and R=p,D=1 all reject
StrictColumns:RoundSumMismatch; the latter aliases in a whole M31 equation.
Non-Boolean carry and terminal1 reject their named consumers. Altered R/G final
claims preserve the last composition but fail StrictColumns:ClaimMismatch.
Stale gap/source words, high external slots, malformed fields/lengths and
supplied caps also reject. No verifier or expected-reason repair was needed.
Actual paired A=65536,D=3, bounded M=21845,MD=65535 and A=MD+R proofs
compose with the same R=1,D=3 roots and the strict proof. Valid changed R or D
proofs fail the pinned source roots. Required local gates remain pending; no
measured performance, native control credit or independent audit is claimed.
