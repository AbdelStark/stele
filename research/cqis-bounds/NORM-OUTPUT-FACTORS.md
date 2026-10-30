# Consumed RMSNorm output factors — Q26 / Q31

Status: revealing research under Draft RFC-0004 A3. RFC-0021 §2.3 and
RFC-0022 §2.3 use e=F+G+21+a-E, with range-16..90. The int32 Requant API
and its nonnegative shift cap62 cannot replace these wide output semantics.

Question before implementation: can the same actual exponent used for paired
A,D bind the output branch and every rounding/left-shift factor byte, without
a supplied shift or unconsumed source? Cost terms: c_a/c_sc/c_lu/T_misc for
one complete paired-divisor child and one fixed public-grid A3. Kill criterion:
another exponent, inactive factor, high padding byte, whole-field alias or
altered public final survives its actual consumer.

Expected metadata is the complete closed norm Spec(d,F,G,E,en,ed). Fully
verify one norm_divisor child, preserving its N,offset=a+23,A,D roots. Reuse
its same actual64-word exponent indicator; never accept a separate indicator.
This wrapper can supply the paired A/D proof once in a future whole-norm
composer while also exposing configured output factors. It does not establish
the normalized interval, reciprocal membership or final signed outputs.

The new independently expected output root has64 canonical-u32 byte slots:
slot0 is[e<0], slot1 is[e>=0], slots2..17 encode B=2^max(e,0), slots18..33
encode h=2^(e-1) for e>0 else0, slots34..41 encode L=2^max(-e,0), and
slots42..63 are zero. Thus B<=2^90,h<=2^89,L<=2^16 from static parameters.
Every factor remains bound even when its branch is inactive. No whole factor
field equality or caller-provided shift/cap grants acceptance.

Generate all64 slot by64 indicator-index grid cells from expected metadata.
For valid i<33 take a=i-23 and the exact64-slot record; all other indices
are zero. Parent dimension12 degree2 A3 proves indicator[i]*(word[j]-grid[j,i])
is zero everywhere. Exactly one valid indicator is already proved by the child;
equality to public bytes therefore supplies every flag/byte bound and every
zero slot. All three actual original/public MLE claims remain consumed at
their emitted points. Plane coordinates lead the six index coordinates.

Namespace: identity<2^32, base=2^63+2^30*identity. Divisor child id64*identity+1
occupies base+2^24..base+2^25-1. Parent views base+8,+9,+10 are outside that
span; parent A3 id2^26*identity+2^25 is disjoint from all child invocations.
External N/offset/A/D/factor ids are distinct u64>=2 outside the full parent
span. Prefix stele/research/q26/norm-output-factors/v1 plus NUL, version/field/
repetitions, six ids and complete norm bytes seed the parent with five expected
roots and the fully verified divisor state before weights/rounds/final.

Account before implementation: added A3 loss36,12 ZeroWeight and12 Sumcheck
draws. Total A3 numerator199+9b+18g, inherited selection A1 loss6, product
identity C-1 and product A1 loss4b remain separate. Four lookup dimensions
7,b+2,g+3,g+3 keep their independent identities/reductions and repetitions.
Full nonlookup draws75+4b+8g ZeroWeight and82+6b+8g Sumcheck include the
inherited product rho/A1s. Binding/FS and remaining normalized interval,
reciprocal/output/native/model/private composition remain additional.

Tests first:10000 independent integer factor/branch cases across all33 a
and complete metadata domains. Public grids agree with independent equality
bases at10000 points per field, including Boolean/zero/one/minus-one cases.
Complete field/repetition proofs cover negative/zero/positive e, e=-16 and90,
actual90-bit shift, zero numerator and exact accounts/draws. Controls alter
each factor/flag/padding region, use a genuine one-cell-corrupted public grid,
preserve final composition while changing originals, substitute valid same-
result exponent proofs and form B+p as valid bytes. Supplied metadata/table,
malformed fields/roots/lengths and namespace boundaries must reject.

Recommendation: continue Q26/Q31 with actual signed X/H magnitudes, xy and
xy*J products, then both wide output branches using these same factor roots.
Original task, native control, stacking, physical/model/private and fidelity
requirements remain open. No Accepted role or production cut is added.

## Reproduction and evidence

Run `uv run --locked --script research/cqis-bounds/check_norm_output_factors.py`.
Tests first failed with the missing module. Seed2710 passed10000 independent
NumPy integer products for factors/branches, all33 a values, full grid padding
and metadata boundaries. Separate endpoint checks cover e=-16 and90. Frozen
corpus SHA-256:
`e2e63680d4653ee01222e07b0eda9dc0409527e0475271116bf13643e1b2f1df`.

All source/flag/factor/high-padding/alias controls passed. Fresh false records
and B+p represented as bytes fail Factors:RoundSumMismatch. A genuine A3
against a one-cell-corrupted public grid satisfies every Boolean relation but
fails Factors:ClaimMismatch at the actual public consumer. Altered original/
public finals preserving the composition reject there too. A valid different
negative exponent retains identical N,A,D at N=0 but fails the pinned offset
root. No verifier or expected-reason repair was needed. All20 complete proofs
passed across both fields/repetitions, with exact accounts/draws, e=-16/-1/0/1/90
and the91-bit B=2^90 endpoint. Frozen matrix SHA-256:
`0966edb60acb2c5743604516c813110b0deb0fabe8ee191fd8772ec8cc603a6a`.
Required local repository gates passed. Both public matrices completed all
10000 points with exact independent equality-basis agreement. Frozen hashes:

- QM31: `4747b394c7d37c037eb11a1aea196d6ae6ee9461538daf6ae340e38db725fd65`.
- OM31: `5b5ea9a6ee1ada254cf6240b8384f99c93f5bbf49876ef2f84a5c68834150bf8`.

No benchmark, native control credit or independent audit is claimed.
