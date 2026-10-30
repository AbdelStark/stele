# Consumed RMSNorm numerator — Q26 / Q31

Status: revealing research under Draft RFC-0004 A3. RFC-0021 §2.3
defines U=d*2^(2F), N=ed*S+en*U; RFC-0022 §§2.1,2.3,5 supply static bounds.
Original tasks remain blocked/open. No complete norm proof, native/private
source consumer, production cut or independent audit is claimed.

Question: can the actual eight-slot statistic root feed the closed numerator
role while enforcing its whole bound and all configuration-derived factors?
Cost terms: c_a/c_sc/c_lu/T_misc, including every inherited consumer. Kill
criterion: a high source byte disappears, digit caps replace S<=d*2^30,
public U/ed/en can change, an inactive factor escapes consumption, or a
whole-word M31 alias passes. A receipt must not imply complete RMSNorm.

Expected metadata is the complete closed norm Spec(d,F,G,E,en,ed), with all
RFC-0021 parameter domains including d<=16384. This scalar adapter does not
consume the full row; its upstream statistic must separately establish that
association. Derive Smax=d*2^30 and U from expected parameters. The numerator
role has count2, left bound max(Smax,U), right bound max(ed,en), radix8.
No supplied cap, factor, operator or observed maximum is trusted.

The external S root has exactly8 canonical-u32 byte slots, as emitted by the
statistic consumer. Its actual scalar wide-range child uses B_s=4 or8 bytes.
Reconstruct the full8 source from those actual words and exact zero extension,
and require its root to equal the independently expected S root. Then fully
verify S<=Smax against the derived bounded-source root. This preserves high
padding even when the range child uses only four words; no prefix-only root
comparison or alternate packed representation is allowed.

Derive one complete limb-source vector from the verified S bytes and public
constants. Plane j has cells (S_j,U_j,ed_j,en_j), in the existing two-row,
left/right operand order, with exact zero extension to the product layout.
Require exact equality to the product child's source, then fully verify that
sum-of-products child against this derived root and the independently expected
numerator root. There is one product proof, no per-element loop. Verification
does not recompute N as a wide integer. N>0 and N<=ed*Smax+en*U follow after
actual source/range/product acceptance, not from independent result digit caps.

Product whole input ranges, output/carry ranges, zero boundary carries,
polynomial identity and all three A1 consumers remain. Static side bounds are
below p/2 before integer lifting. The output has C result columns and 2^g
canonical-u32 slots, including enforced high zeros; g is3 or4. The full norm
domain can require U with75 bits and numerator bounds with107 bits. No int32
Requant or whole-field lift is a substitute for these bytes.

Namespace: identity<2^44, base=2^63+2^18*identity. Bounded S root base+1;
derived product source base+2. Wide-range child id4096*identity+1 has its span
at base+64; product child id64*identity+1 has its span at base+4096. All
descendants stay within the parent span. External S/numerator ids are distinct
u64>=2 outside it. Prefix stele/research/q26/norm-numerator/v1 plus NUL,
then version/field/repetitions, three u64 identity/source/output ids, and the
complete RFC-0021 norm function bytes. Parent final seed binds external S/N,
bounded S and derived product-source roots, then both verified child states.
No parent challenge or new public-MLE kind is introduced.

Account before implementation: write B_s=2^b_s, product planes B=2^b, and
output slots2^g. Statistic range A3 adds7b_s; product input range/packing
adds22+9b; output/carry ranges18g+20. Total A3 numerator7b_s+9b+18g+42.
Four lookup dimensions are b_s+1,b+3,g+3,g+3; each separately contributes
[(2^m+255)/|K|]^r and r[F(m)+F(8)+3m]/|K|, F(m)=3m(m-1)/2+2m.
Product identity adds(C-1)/|K|; product A1s add(2+4b)/|K|. Neither loss is
squared or repeated with r. Full ZeroWeight count3b_s+4b+8g+18; Sumcheck
count3b_s+6b+8g+20, including product rho/A1s and excluding lookup schedules.
Exact source joins add no algebraic loss conditional on binding. FS/H and
private/model composition remain additional; no production profile is admitted.

Tests first:10000 independent Python/NumPy object-integer numerators and exact
byte views, maximum parameters, full field/repetition matrix and zero S. Prove
genuine changed left/right public operands, including changed ed when S=0;
all must reject their actual source join. Smax+1 with a wrapped slack makes
all range columns hold except terminal carry while the larger product whole
bound permits it; the actual S range must reject. A false N+p with valid output
ranges must fail the product relation. Retain all eight external S slots and
all high output digits. Test root, field, shape, metadata and namespace errors,
and compose an actual statistic root into this consumer with matching metadata.

Recommendation: continue Q26/Q31 with normalization exponent,
scaled numerator/divisor, mantissa and strict remainder, actual rsqrt membership,
final products/branches and model-owned routing. This proves only the numerator
role after an independently bound statistic, not the remaining norm obligations.

## Actual source and integer consumers

The full S root is checked against exact zero extension of the range child's
actual words, then that range verifies all byte, cap and carry claims. The
numerator source is derived only afterward, from those verified words and
expected U/ed/en. Product input whole ranges, source packing, result/carry ranges,
polynomial identity and both original power/source consumers remain. A valid
proof with changed ed at S=0 still fails the exact source join, even though
the numeric result is unchanged. No supplied factor or source map is authority.

The generic product's left bound can exceed Smax because U may be much larger.
It therefore cannot replace the separate statistic range. Only after that range
and faithful integer multiplication are established does the closed N bound
follow. The same order preserves noncircular bounds and the strictly positive
epsilon contribution. Eight-slot external S roots and padded product output
roots retain their exact original lengths; no high byte is silently discarded.

## Reproduction and evidence

Run `uv run --locked --script research/cqis-bounds/check_norm_numerator.py`.
Tests first failed with the missing implementation module. Seed2685 covers10000
Python/NumPy object-integer numerators and independent NumPy int64 byte
convolutions,367840 exact source cells and varied supported metadata. Maximum
dimension/fraction/epsilon parameters retain the75-bit unit and107-bit numerator
bound. Frozen corpus SHA-256:
`944f39a2b0338a1dacbc36be6899cdb4c9a21330c2d25cb1e4eaed8b6ca6e9e8`.

All16 main proofs passed across both fields and repetitions, zero S, the32-bit
statistic boundary and maximum-width public factors. All four extra minimum
C=4 proofs passed with nonzero S, completing that column boundary in both fields
and repetition counts. Exact losses, actual draws and original/public claim
counts are checked in every proof. Frozen main/minimum proof-state checksums:
`3511814162bdb6666fa55e566e676766ee3c49ee2f0cac24563ca99e6f2479cd` and
`fafef6442b62e766a8928a470266126b1a557d1d1251ebb37f6f419216c93c33`.

Every changed operand role rejects Product:SourceJoin, including independently
verified alternative product proofs. A changed S with an updated external root
but stale range proof rejects Statistic:SourceCopy:ClaimMismatch; this observed
original-claim rejection corrected the initial test's predicted round error.
The verifier was unchanged. Smax+1 with wrapped slack satisfies all range
columns but its terminal carry rejects Statistic:TerminalCarry:FinalEvaluationMismatch,
even while a complete product proof fits its broader domain. A false N+p in
valid output ranges collides at fixed rho=256 but fails the actual transcript's
Product:Product:RoundSumMismatch. High S slots, strict fields, metadata and roots
also reject. Actual signed-statistic-to-numerator composition passes and rejects
a valid numerator proof with a substituted statistic. Local gates are pending.

Source views cost O(B), plus all inherited range/product/hash consumers in the
named cost terms. No measured constant, benchmark, weight-pass change, native
control credit or independent audit is claimed. Revealing byte roots do not
establish physical/model ownership or private inference.
