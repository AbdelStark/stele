# Consumed RMSNorm decomposition — Q26 / Q31

Status: revealing research under Draft RFC-0004 A3, using RFC-0021 §2.3
and the closed normal_sum role in RFC-0022 §2.3. This establishes A=MD+R
with actual expected source roots. It does not prove R<D, the normalized
interval, reciprocal lookup, outputs or complete physical/model/private inference.

Question before implementation: can the existing count2 sum-of-products
consumer bind MD,R and A to their full external representations, with both
right factors exactly1, while preserving every range/original/public consumer?
Cost terms: c_a/c_sc/c_lu/T_misc for O(B) source/zero-extension views and the
complete inherited product. Kill criterion: source substitution, a nonunit
factor, ignored high source/result byte or whole-field sum alias survives.

Expected metadata is the complete norm Spec(d,F,G,E,en,ed), retaining its
original domains. External MD uses the8/16/32 byte slots of normal_product;
R uses16 byte slots; A uses the16/32 slots of scaled. All slots are canonical
u32 field encodings of bytes, not physical packed/private tensor commitments.

The normal_sum source has count2, left capMDmax and right cap1. Each plane
has ordered MD,R,one,one entries; right entries are1 only in plane0 and0
otherwise. Reconstruct the full external MD and R roots from actual left
planes, requiring zero in any plane beyond each external width and preserving
every high external slot by exact zero extension. Compare the complete source
to the derived constant-right view. No inactive or supplied right factor is
accepted. Reconstruct full external A from actual sum output slots, again with
checked excess zero planes and exact zero extension, then run the complete LP
verifier with those actual internal source/output roots. Never compare prefixes.

All source whole bounds, packing, output/carry ranges, zero carry endpoints,
fresh product polynomial and row/two-plane A1s remain. Successful integer
sum acceptance supplies A=MD+R. Both left operands have the generic MDmax
bound; the16-slot R representation does not establish R<D. An actual strict
remainder consumer and upstream same-root MD/A/D composition remain required.
Producer helpers do not grant acceptance or recompute the sum in verify.

Namespace before implementation: identity<2^44, base=2^63+2^18*identity.
Internal source/output ids base+1,+2; LP child id64*identity+1 spans base+4096.
External MD/R/A ids are distinct u64>=2 outside the full parent span. Complete
norm function bytes, version/field/repetitions and four ids seed prefix
stele/research/q26/norm-sum/v1 plus NUL. Final parent state binds five roots
and one verified child state; it draws no challenges.

Account before implementation: let planes=2^b, output slots=2^g, result
columns=C. The count2 LP adds A3 numerator9b+18g+42. Its three lookup
dimensions are b+3,g+3,g+3, each retaining identity[(2^m+255)/|K|]^r and
reduction r[F(m)+F(8)+3m]/|K|. Product identity C-1 and A1 reduction2+4b
are separate and not repeated with r. Nonlookup ZeroWeight draws18+4b+8g,
Sumcheck20+6b+8g, including rho and all three A1s. No parent loss or lookup
is added. Binding/FS, strict remainder and whole-model composition remain extra.

Tests first:10000 independent NumPy object-integer sums and int64 byte
convolutions. Complete proofs in both fields/repetitions cover all supported
plane/output widths, zero, boundaries and actual wide sums. Exact account/draw
assertions and original/public consumers stay. Genuine different-MD/R sums
under pinned roots, dropped/nonunit right factors, high zero-extension slots,
valid-range A+p aliases, metadata/namespace/malformed fields and lengths must
reject for their stated consumer. Compose actual upstream MD and paired A
roots; show equality accepts R=D in isolation so it cannot claim strictness.

Recommendation: continue Q26/Q31 with strict0<=R<D and same-root composition,
then the complete reciprocal lookup and output branches. Original task status,
acceptance criteria and native/private/model obligations remain open.

## Reproduction and evidence

Run `uv run --locked --script research/cqis-bounds/check_norm_sum.py`.
Tests first failed with the missing module. Seed2698 passed10000 independent
NumPy object-integer sums and int64 byte convolutions over727680 source cells.
Frozen corpus SHA-256:
`366f19a64949544aa45574cc47b53dc3807e4b74bb0bafe072650fb069d9389f`.

All source/unit/high-slot/field-alias controls and actual upstream composition
passed. A genuine dropped-unit sum-of-products proof fails Sum:SourceJoin.
Valid-range A=p collides with a zero sum at fixed rho256 but fails the actual
Sum:Product:RoundSumMismatch. One malformed-length test initially expected
SourceShape; the verifier already rejected as Scaled:OpeningShape. Correcting
only that expectation made the complete controls pass; no verifier change.
Actual paired A=65536,D=3 and M=21845,MD=65535 proofs compose with R=1.
A valid MD=65534,R=2 sum keeps A but fails the pinned upstream product root.
An isolated R=D equality intentionally accepts, leaving strictness explicit.

Eight additional width-boundary proofs passed, including an external16-slot A
with32 internal output slots, an external32-slot MD with16 source planes and
16-slot R with32 source planes. Each high-slot or excess-plane tamper rejects
at its actual root/padding consumer. Exact accounts/draws pass. Frozen states:
`ec01b18abd84f118573b253429bd305b1e6eb25b002abaae9b4a1b8537dbdce8`.
All16 main proofs passed in both fields/repetitions, including actual140-bit
results with nonzero byte17 and exact accounts/draws. Together the24 proofs
cover ten distinct source/internal/external width combinations. Frozen main
proof-state SHA-256:
`02600f4248ded8d34287268e07594b5cce8c4058b7c9a8eb6a926fdba771c456`.
All required local gates passed.
No measured performance, native control credit or independent audit is claimed.
