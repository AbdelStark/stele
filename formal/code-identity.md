# Candidate code identity, registry and common encoder API (Q23)

Status: Draft, RFC-0010 A1. This closes candidate identity/parameter-selection
semantics, not PCS proximity, profile admission or the production implementation.
The research entrypoint selects an actual map from its checked identity; it never
accepts a raw graph, caller-supplied bound or alternative implementation.

## 1. Closed identities and field binding

There are exactly two supported identity formats:

- Circle: RFC-0010 A2's 21 bytes, `stele/circle-m31/v1 || u8(m) || u8(b)`,
  b in {1,2}, m+b<=30. This identifies the exact non-systematic base map.
- Expander: the 55-byte v2 manifest in [seeded-setup.md](seeded-setup.md),
  including the checked exponent and every seed byte. The v2 algorithm fixes
  degrees, block domains, base, rejection caps and ordering. It uniquely
  determines a map or `SamplingExhausted`; it is not merely an unspecified seed.

Unknown formats, suffixes, malformed lengths, old versions and unsupported sizes
reject as `InvalidCodeId`. A raw expander descriptor is not a code identity.
No registry text, `proven` flag, family nickname or seed without its format may
replace these bytes. No implicit padding, rate change or fallback is permitted.

The identity specifies an M31-linear map independently of the element field.
Surrounding commitment/plan/passport statements must also bind the field encoding;
this interface takes the explicit field degree 1,4 or 8 and rejects others as
`FieldMismatch`. Field degree is not inferred from untrusted row data. Native
consumers must use the validated M31/QM31/OM31 implementations in the RFC-0003 basis.

Equal parameters do not imply equal maps: different expander seeds have the same
lengths/bounds and generally encode differently. Conversely, the base-only expander
and Circle(6,1) encode the same map under distinct identities. Do not normalize
identities by semantic equivalence or bind only the returned parameter dictionary.
Future containers must frame and authenticate the complete code ID plus field;
this research does not supply the surrounding commitment/plan/passport binding.

## 2. Derived parameters and evidence

Identity resolution performs only bounded integer arithmetic, without graph or
FFT allocation. All 59 circle sizes and 13 expander sizes are supported in each
of the three fields. Derive, never accept as overrides:

| Property | Circle | Expander v2 |
|---|---|---|
| message/codeword length | k=2^m, N=2^(m+b) | k=4^J, N=2k |
| distance lower bound | N if k=1, otherwise N-k | 64 if J=3, otherwise floor(k/25)+1 |
| setup error | 0 | 0 if J=3, otherwise 200431782/2^160 |
| sparse edges | 0 | E(J) from the fixed v2 geometry |
| raw sparse-setup bytes | 0 | 43+8*E(J) |

These are symbol-distance lower bounds, not proximity radii, observed minima or
query counts. The expander distance bound has the exact ideal-oracle premises of
the all-seed proof; the circle bound is deterministic. Zero raw sparse-setup bytes
for Circle does not mean zero twiddle, transform or allocation work.

Evidence IDs in the research catalog map to these precise sources:

- `rfc-0010-a2/root-bound-v1`: Accepted A2 and [circle-code.md](circle-code.md).
- `rfc-0010-a1/finite-v2`: Draft A1 and [expander-sampling.md](expander-sampling.md)
  with the v2 schedule in [recursive-code.md](recursive-code.md).
- `rfc-0012-a7/2^256-all-seeds-v2`: Draft A7 and [seeded-setup.md](seeded-setup.md).

The v2 evidence is a candidate, not an Accepted parameter set. On acceptance,
these names must identify immutable versioned hypotheses/results; a change to
those semantics requires a new evidence ID and explicit registry review.

## 3. Registry authority

`research/code-provenance/codes.toml` is a checked export of a fixed two-entry
catalog, not a source of caller-selectable protocol parameters. Its root version
is the catalog format version 1. Entries are ordered Circle then expander, with
exact fields/values produced by `identity.catalog()`. The checker accepts TOML
whitespace, comments and key order, but rejects duplicate/missing/unknown keys,
missing/extra/reordered entries, changed IDs/evidence/bounds/ranges, wrong types,
malformed UTF-8/TOML and files over 4096 bytes. Boolean true is not integer one.
The parsed document is never returned as trusted parameter authority.

Here `proven` means a complete supported PCS parameter set, including applicable
proximity and exceptional-combination bounds, query selection and full accounting.
Both entries are false. Separate distance evidence does not make that flag true.
Flipping a flag or theorem string rejects as `InvalidRegistry`; it cannot enable
a profile. There is no successful PCS-parameter/admission operation in this study.
The native registry must derive approved values from its authenticated fixed
configuration and reject unavailable parameter sets as `UnsupportedParameters`.
Q12 and the actual PCS consumers remain required before such a set can be admitted.

## 4. Native API proposal and research behavior

RFC-0010 A4 and [native-code.md](native-code.md) fix the implemented encoder
surface independently: EncoderInfo contains lengths/counts only. The broader
parameter/registry discussion here remains Draft A1 and cannot extend that API.

Replace §3's underspecified general API with a sealed `Code` trait and a closed
factory resolving only these two checked identities. Callers must not implement
the trusted trait, inject a raw graph, or construct an instance with unchecked
fields. Its operations are `code_id`, `parameters`, `encode(row)` and
`eval_row(row,columns)`. `parameters` returns the derived encoder information above;
it is not `ProximityParams`. The future PCS parameter resolver must check code,
field, profile, evidence and authenticated configuration separately and fail closed
when any required evidence is unavailable. Returning a distance tuple cannot
satisfy that resolver's obligations. No successful PCS result is defined here.

For native typed fields, validate characteristic/representation and whole row
length before setup or transform work. Check all requested columns before any
output. Preserve column order and duplicates. An empty query validates the same
identity, field and row, then returns empty without generating setup or encoding.
Nonempty queries may encode the complete row; no sublinear-query promise is made.
Invalid rows reject as `RowShape`, invalid columns as `Column`, and any sampler
exhaustion rejects the entire operation without partial results or fallback.

The Python oracle represents a row as a list/tuple of field-element tuples,
with exactly 1/4/8 canonical integer limbs; booleans and noncanonical limbs reject.
It regenerates the sparse setup on each nonempty expander encoding and calls the
existing checked recursive encoder; Circle uses the existing component transforms.
Returned metadata is a descriptive snapshot and is never accepted as an encoding
input. The APIs accept neither raw matrices nor caller-supplied `proven` metadata.

The [bounded v2 execution proposal](bounded-encoder.md) supplies a graph-free
candidate traversal and explicit requested-payload formulas. Native delivery still
requires actual allocation, complete memory/cost evidence and approved consumers.

Native capacity calculations must use checked shifts/products/sums before allocation
and must use fallible reservation for every live buffer, mapping failure to
`Capacity`. Account for N field elements, nested row storage, base transforms, scratch and
construction overlap. Charge E graph records and generated raw bytes when those
are materialized; the bounded traversal instead charges per-row generation state. Smaller
address spaces may reject a supported mathematical size as `Capacity`; never
truncate it or change the code. The Python study does not establish that native
allocation contract or a production peak-memory bound; Python resource exceptions
are not successful verification. These remain implementation/review obligations.

## 5. Evidence and cost

Run `uv run --locked --script research/code-provenance/check_identity.py`.
Thirty selected map/field cases check complete codewords and ordered duplicate
queries. Expander outputs use the independent dense/base oracle; Circle dispatch
uses its existing transform and retains A2's independent evidence. All 72 sizes
resolve in all three fields without setup/FFT calls. Every catalog field is
mutated individually, and invalid requests/empty queries are checked before setup
or FFT entry. Same-parameter/different-seed maps remain distinguishable.
These tests earn no production NC-0600..0605 or source-authentication credit.

Descriptor resolution and catalog checking are bounded preparation work under
T_misc. Actual encoding still includes its existing transforms, full regeneration,
raw validation/copies and sparse arithmetic in c_c. The common interface does not
amortize setup, reduce peak memory, prove a new benchmark constant or add a weight
pass. Production APIs, registry admission, proximity and complete memory/operation
ledgers remain E4-01/E4-03/E4-05/E12-04 obligations; A1 stays Draft.
