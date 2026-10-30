# Consumed RMSNorm scaled numerator — Q26 / Q31

Status: revealing research under Draft RFC-0004 A3. RFC-0021 §2.3 and
RFC-0022 §2.3 require A=N*4^-min(a,0). This consumes that closed scaled role
with its actual exponent relation; it does not prove the normalized interval,
divisor, mantissa/remainder, rsqrt, outputs, or physical/model/private ownership.

Question before implementation: can the independently bound full numerator
root and actual negative factor bytes feed the existing closed scaled product
without dropping high zero padding or reintroducing independent factor facts?
Cost terms: c_a/c_sc/c_lu/T_misc for source views, complete exponent and product
consumers. Kill criterion: any numerator slot, zero-product factor substitution,
whole-field alias or high output byte escapes its actual source/relation check.

Expected metadata is the complete norm Spec(d,F,G,E,en,ed), all original domains.
External roots are full numerator bytes, offset=a+23, and scaled output bytes.
The numerator uses exactly the8 or16 canonical-u32 slots emitted by its closed
numerator role, including zero padding. The output uses the16 or32 slots from
the closed scaled role, retaining up to153 bound bits. No int32 or whole-field
lift substitutes for these representations.

First fully verify the exponent child against the independently expected offset
root and the root of its actual16 factor bytes. That child proves both powers
and all padding, including its one-hot range/sum and public/original consumers.
The exponent factor root is an internal revealing root, not a production cut.
Then read the actual product source's left bytes and rebuild the full external
numerator root with exact zero extension, retaining all high slots. If product
planes exceed external slots, every excess left byte must be zero. Require the
right bytes to equal the already verified first eight factor bytes with exact
zero extension. Full product verification follows against this actual source
and the independently expected output root.

The scaled role's left bound is exactly Nmax, unlike the broader numerator
role's statistic bound. Its existing whole-input range therefore supplies the
needed N bound without a redundant range child. Canonical field checks alone
do not establish it; the complete limb input range/packing remains mandatory.
Actual product columns, carries and zero boundaries then establish integer A.
This role admits N=0 as a bounded input; positive N and its preceding statistic
association require the separate numerator consumer and matching external root.

Namespace: identity<2^44, base=2^63+2^18*identity. Factor root base+1, derived
product source base+2. Exponent child id64*identity+1 occupies base+4096..8191;
scaled product child id64*identity+2 occupies base+8192..12287. Descendant
root/invocation spans are disjoint. External numerator/offset/output ids are
distinct u64>=2 outside the whole parent span. Prefix
stele/research/q26/norm-scaled/v1 plus NUL, version/field/repetitions, four u64
ids and complete norm function bytes seed the final transcript with five roots
and two verified child states. There is no parent random challenge.

Account before implementation: exponent A3 numerator102, selection A1 loss6;
product planes B=2^b and output slots2^g contribute A3 9b+18g+31. Total A3
is133+9b+18g. Four separate lookup dimensions7,b+2,g+3,g+3 retain identity
[(2^m+255)/|K|]^r and reduction r[F(m)+F(8)+3m]/|K|. Product identity C-1
and product A1 reduction4b remain separate from the exponent selection6,
unsquared and unrepeated with r. Full nonlookup ZeroWeight draws53+4b+8g;
Sumcheck60+6b+8g, including product rho and both plane A1s. FS/H, binding and
remaining normalization composition are additional; no profile is admitted.

Tests first:10000 independent NumPy object-integer products and byte convolutions;
all fields/repetitions with zero, endpoint exponents and maximum parameters.
Check exact accounts/draws and every original/public product claim. Change N
roots/high slots, valid exponent proofs under a different expected offset, actual
factor bytes, and independently valid product proofs with another factor at N=0.
An A+p output with valid ranges must fail the actual product identity. Compose
an actual numerator output root; substitution must reject. Retain every output
and carry consumer and reject malformed fields, roots, lengths and metadata.

Recommendation: continue Q26/Q31 with the configured divisor's actual byte
relation, mantissa/strict remainder, complete rsqrt membership and output
branches, always sharing the verified exponent/source roots. This relation
alone does not establish the unique normalization exponent or complete RMSNorm.
