# Complete configured row capacity (Q26 / Q31)

Draft RFC-0004 A3/A6/A8 research. Before code: can the existing complete
attained-maximum, dynamic-scale and row-code consumers cover 16384 entries
without enlarging any range lookup domain or changing an existing proof?
Costs are c_a/c_sc/c_lu/T_misc. Kill the change if a nested byte domain exceeds
131072, any original consumer disappears, a legacy transcript changes, or a
newly admitted false source, scale, rounding or padding value is accepted.

The signed-source consumer already admits 16384 entries. The range consumer
already admits at most 65536 whole values and 131072 value bytes, with at most
262144 lookup entries and dimension 18. Preserve those limits. Raise the
attained-magnitude count guard from 2048 to 16384. Raise both row-code column
guards from 4096 to 65536. Dynamic scale inherits the magnitude count guard;
static row codes retain the signed-source count guard. Reject count 16385
before reading malformed witness or proof data.

For wide int16 and gated int32 sources, byte width B is two or four. The
existing dynamic division has four column planes; static division has two
or four. At N=16384, the largest range is the 65536 two-byte carry values,
exactly 131072 value bytes. No extra grouping, challenge, transcript label,
wire version or witness-dependent shape is introduced. Source, magnitude,
gap and indicator ranges remain complete. Dynamic maximum selection spans
the entire row and includes its one-hot attainment proof. Static scale must
remain the configured constant; overflow rejects without clipping.

All existing formulas remain functions of a=log2(N), b=log2(B), c=log2(column
planes), and br=log2(remainder byte width). Dynamic row range/A3 numerator is
171a+87b+12c+25, with separate selection numerator a; static is
121a+26b+7br+12c+25. Preserve every independent lookup identity and unsquared
reduction. Dynamic nonlookup draws are 73a+36b+5c+11 ZeroWeight and
74a+36b+5c+11 Sumcheck. Static draws per label are
51a+10b+3br+5c+11. No fixed small-row error estimate may be substituted at
larger shapes. Full proofs must match exact accounts and all original ids.

Tests first: admitted/rejected dimensions, every nested range geometry, both
source kinds, both policies, static scale endpoints, ragged padding and the
maximum namespace. Independent whole-row rounding must match witnesses at
1025, 2049, 8193, 16383 and 16384 entries, including extrema, negative zero
outputs and the all-zero dynamic row. Existing 10000-case corpora, all source
controls and both-field/repetition matrices must keep their frozen hashes.
Require complete 16384-entry proofs for wide/gated dynamic/static conversion,
with actual root mutations and receipt checks. Queue them after existing
range-capacity validation and the regression suite, once each.

This is a capacity prerequisite. Attention still needs authenticated head
assembly followed by one conversion over the complete output row. Converting
each head independently is not that operation. Global exact offset ownership,
shared probability/key/mask/value provenance, model/cache/decode ownership,
native/private PCS/ZK/FS, GPU parity, fidelity and independent audit remain
required. No production coverage, benchmark, new cut or weight pass is
claimed. Draft status and original task acceptance criteria stay unchanged.

All 40 geometry/witness cases passed across both source kinds and policies,
including static scale endpoints and 16384 entries. Both challenge fields
derive every nested range within the unchanged byte and lookup limits.
Independent rounding and 1548288 carry-column cells matched; two full-size
dynamic zero rows and over-capacity rejection also passed. Frozen SHA-256:
`9e7621992ac1de560d6a5e2d7477ec0b23ec8c1666f4c50aee279a39bdb907dc`.
All sixteen complete proof cases passed across both fields, repetitions,
source kinds and conversion policies. Their final-state digest is
`49bfeb69d3c8312dd2f4b3e11ccb740906bb31d9f84eec1eccdd759103dcae82`.
The attained-magnitude, dynamic-scale, row-code and static-row-code suites
retained their frozen hashes; gated-source composition also passed.
Four full-size proofs and repository gates remain in their original queues.

CI now requires the shape/proof checks and all four full-size modes. The
normalization parent was merged without changing the conversion arithmetic.
All inherited research jobs and native steps remain mandatory.
