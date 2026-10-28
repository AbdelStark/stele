# Native deterministic encoder contract (RFC-0010 A4)

Status: Accepted via RFC-0010 A4. This contract authorizes the deterministic
encoder implementation; delivery still requires the gates below. It supplies no PCS parameters, setup-distance certificate, proximity
acceptance, commitment authentication or profile admission. E4-08 is implementation
work; completing it does not complete E4-01, A1, A3, A7 or Q12.

## 1. Public API and authority

The new public surface in stele-code is the following, using the existing Error
and Field/M31 types. Names below are fixed; private module names are illustrative.

```rust
pub struct Encoder { /* private, checked identity */ }
pub struct EncoderInfo {
    pub message_len: u64,
    pub codeword_len: u64,
    pub sparse_edges: u64,
    pub row_count: u64,
}
pub trait CodeField: Field + private::SealedField {
    const DEGREE: u8;
    fn mul_base(self, coefficient: M31) -> Self;
}
pub trait Code: private::SealedCode {
    fn code_id(&self) -> &[u8];
    fn info(&self) -> EncoderInfo;
    fn encode<K: CodeField>(&self, row: &[K]) -> Result<Vec<K>, Error>;
    fn eval_row<K: CodeField>(&self, row: &[K], columns: &[usize])
        -> Result<Vec<K>, Error>;
}
impl Encoder {
    pub fn from_code_id(bytes: &[u8]) -> Result<Self, Error>;
}
```

Only Encoder implements Code. Only M31, QM31 and OM31 implement CodeField, with
DEGREE 1/4/8 and canonical limb size 4*DEGREE. mul_base multiplies every base limb
by the supplied coefficient, exactly DEGREE M31 multiplications. External code
cannot implement either sealed trait or construct unchecked Encoder fields.
CM31 and KoalaBear are not accepted by the new interface. Existing Circle APIs,
including their generic field checks and errors, remain compatible.

The factory accepts precisely A2's 21-byte Circle ID or A4's 55-byte v2 manifest.
It copies the complete identity into private fixed-size storage without hashing,
FFT or graph allocation. Circle dimensions are exactly A2's m,b; expander J is
3..15 and all 32 seed bytes are retained, including at J=3. No normalization of
semantically equivalent IDs, implicit padding, alternate degree/base or fallback
is permitted. Old versions, raw setup bytes, unknown formats, suffixes, truncated
IDs and invalid dimensions reject InvalidCodeId. Direct Circle::new retains its
existing InvalidSize behavior. The new factory never accepts raw graphs or metadata.

info derives mathematical lengths and counts from that stored identity in checked
u64 arithmetic. Circle uses k=2^m, N=2^(m+b), sparse_edges=row_count=0. Expander
uses n=4^J, N=2n and E(J),R(J) from bounded-encoder.md. It does not allocate or
convert mathematical metadata to an address-sized count. Returned fields are
non-authoritative snapshots: no operation takes an EncoderInfo back as input.
Distance, gap, setup loss, query count, proven flag and profile are absent.

There is no runtime TOML parser, registry override, parameter-admission callback
or trusted external Code implementation in A4. A1 retains the complete registry
and PCS parameter obligations; its research codes.toml remains research-only,
with both proven flags false. Future commitment/plan/passport consumers must bind
the complete ID and explicit field selected by their authenticated statement.
A Rust field type selects arithmetic; it is not evidence of that public binding.

## 2. Exact map and deterministic expansion

A4 makes the map/coordinate definition in recursive-code.md §1 and the raw
structural representation in §2 normative for this encoder, using the v2 degree
schedule and A2 base. The raw structural representation is a reference format,
not a native constructor input. materialize/check_setup remain reference utilities;
A4 does not require a native raw-setup parser or full graph materialization. The map is E_3=Circle(6,1); for J>=4,
`E_J(x)=x || z || z*B_J`, where `z=E_(J-1)(x*A_J)`. Base coefficients embed in K.
The base is non-systematic; outer maps retain their literal systematic prefix.

The manifest, exact 74-byte hash input, row/stream/counter coordinates, masking,
duplicate rejection, sorting, coefficient order and 256-word caps in
seeded-setup.md §1 are normative. Neither the all-seed probability analysis nor
PCS admission in its later sections is accepted by A4. BLAKE3 is deterministic
setup expansion, never an alternate source of Fiat-Shamir challenges.

Use the existing pinned BLAKE3 1.8.7 dependency with default features disabled,
directly in stele-code. This is the already-used external hash primitive, not a
new workspace-crate dependency, proof system or reference-prover import. RFC-0020's
internal dependency edges remain unchanged. Cargo bans/lockfile and no_std checks
must pass when the actual dependency is added.

Use bounded-encoder.md §§1–2 for exact traversal, requested buffer formulas and
capacity handling. The setup materializer's byte order and the encoder's execution
order can differ as specified there: all block identities and successful codewords
are identical. Generate every required stream, even for all-zero input. Zero-valued
coefficients remain edges. Any exhausted stream aborts the whole operation with
SamplingExhausted; no output or alternate seed/code is returned.

## 3. Validation, resources and errors

Add InvalidCodeId and SamplingExhausted to the existing Error enum. Preserve
InvalidSize, RowShape, Column, FieldMismatch and Capacity for existing APIs.
For a new encode call, the sealed type fixes the field, row.len() must equal the
stored message length, and supported target layout and checked capacity arithmetic
must pass before allocation/generation. A malformed row length is RowShape.
No noncanonical limb normalization occurs; typed field constructors already enforce
canonical values. Unknown byte fields are rejected by their actual decoders.

For eval_row, validate the row then every supplied column before work; out-of-range
columns are Column. Preserve query order and duplicates. An empty request returns
an empty vector with no FFT, setup generation or output/scratch reservation. For
nonempty requests, check requested result/borrowed-column bytes and combined owned
payload, reserve the selected result fallibly, encode the full word, and select
those coordinates. The encoded word and selected vector coexist. No sublinear
query promise is made. No partial result is returned on allocation or sampler error.

Every length/product/sum/conversion used for allocation or indexing is checked;
capacity arithmetic uses the actual native target. Treat requested vector bytes
over isize::MAX, overflow, incompatible type layout or reservation failure as
Capacity. Empty queries need no hypothetical full-encode reservation. Use fallible
reservation for all vectors; preserve borrowed input and release partial owned
buffers on failure. No data-dependent skipping, panicking allocation shortcut or
caller-supplied memory/field limit may change the selected map.

Operation counters remain checked u64, independent of usize. Native layouts must
be checked for the three sealed field types. Requested payload formulas do not
bound allocator rounding, vector capacities, stack/hash state or process RSS;
these need actual delivery evidence. A supported mathematical size may fail
Capacity on a particular machine; that does not permit another encoding.

## 4. Acceptance, delivery and remaining obligations

A4 acceptance requires the deterministic contract, explicit authority/error/resource
boundaries and required skill reviews. The existing independent dense/base map,
sampler framing/KAT, common identity and bounded traversal studies support it.
They do not complete native implementation or benchmarks. E4-08 delivery requires:

1. Native no_std implementation, sealed-field/code compile-fail tests, checked
   factory/metadata and unchanged existing Circle behavior. No raw graph, registry
   metadata or external implementation may be injected into this encoder.
2. Exact Rust/Python full words and ordered query values over all three fields;
   at least 1000 seeded small cases per field including J=3/4/5, full-extension
   limbs, linearity, zero inputs, zero coefficients and scalar/boundary values.
   Use existing independent dense/base evidence as well as materialized-map parity.
3. Invalid ID/version/size/shape/column/field/capacity tests; no generation for
   invalid/empty requests; deterministic framed block KATs; outer/inner/late stream
   exhaustion with input preserved. Add native reference digests to the real gate.
   Test-only sampler fault injection must not provide a production bypass or
   cause a successful output to be accepted as a distance/PCS certificate.
4. Full clean-source ledgers through n=2^20 on M31/QM31/OM31, recording actual
   generation, validation, initialization, copies, base and sparse work. Include
   requested/actual capacities, borrowed inputs, base/query overlap, stack/hash
   overhead and process peaks. Measure every claimed size/field; no extrapolated
   peak or time. Independently check all supported size arithmetic without huge
   allocations. Sparse work is d*E(J) adds/multiplies; base/hash work is additional.
5. All required repository gates and existing Circle regressions. GPU parity is
   required if GPU code changes; CPU-only work makes no GPU performance claim.

These are delivery gates, not requirements to write core code before its governing
RFC is accepted. E4-01 retains every original acceptance criterion and its A1 block,
and now depends on E4-08. E4-03/A3, E12-04 and Q12 still require real consumers,
registry authority, arbitrary/batched openings, setup/proximity composition and
full profile accounting. Encoder tests earn no NC-0600..0605 credit.
No new binding, challenge, loss line, committed tensor or matmul pass is added.
A4 changes no measured c_c/T_misc constant; actual native ledgers must charge
complete costs before any performance claim or task-completion decision.
