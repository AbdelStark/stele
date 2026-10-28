# Canonical component-table identity candidate (Q25)

Research for Draft RFC-0004 A2 and the pending RFC-0008 §4/RFC-0011 table
contract. This supplies component descriptors and data bytes. It does not
complete composition identities, CQIS configuration bytes, passport commitments,
lookup reductions or native verifier admission. No Accepted encoding is replaced.

## 1. Closed descriptors

Let H be ordinary unkeyed BLAKE3's first 32 bytes, as in RFC-0012 A1. For the
closed ASCII names below, definition_version is exactly 1. All lengths count
bytes. Encode the descriptor, without terminator or alignment, as

    ASCII("stele/v0.1/table/identity") || u16le(name_length) || name
    || u32le(definition_version) || u16le(parameter_length) || parameter_bytes.

TableId=H(descriptor). This is an identity hash, not a Fiat–Shamir challenge.
The framing is injective before hashing: fixed lengths delimit the name,
version and parameters, and trailing data rejects. Unknown names, versions,
non-ASCII/aliased names, lengths and parameters reject. The parser caps total
descriptor length at 128, name length at 32 and parameter length at 64 before
reading variable fields; current schemas are much smaller.

| Exact name | Parameter bytes, in order | Valid rows in increasing input order |
|---|---|---|
| `exp_q/hi` | u8 B,F,E,k | (h,H[h]), h=0..2^(B-k) |
| `exp_q/lo` | u8 B,F,E,k | (l,L[l]), l=0..2^k-1 |
| `exp_q/direct` | u8 B,F,E | (t,D(t)), t=-2^B..0 |
| `exp_q/correction` | u8 B,F,E,k | (t,D(t)-P_k(t)), t=-2^B..0 |
| `silu_q`, `sigmoid_q` | u8 F,E | (t,Y(t)), t=-32768..32767 |
| `gelu_q`, `gelu_tanh_q` | u8 F,E | (t,Y(t)), same full signed domain |
| `softcap_q` | u8 F,E; u16le cap_m; u8 cap_f | (t,Y(t)), same full signed domain |
| `rsqrt_q` | empty | (M,J(M)), M=16384..65535 |
| `range_8`, `range_12`, `range_16` | empty | one column v=0..2^b-1 |

The [exp](cqis-exp.md), [wide exp](cqis-wide-exp.md),
[activation](cqis-activations.md), [GeLU](cqis-gelu.md) and
[RMSNorm](cqis-rmsnorm.md) candidate definitions determine every entry and
parameter bound. In particular cap_m/2^cap_f must be reduced, direct/correction
require B<=15, and hi/lo/correction bind the split k. D does not depend on k,
so its descriptor has no split. The rsqrt table fixes K=2^21 and its rounding
in version 1; dimension, epsilon and input/gain/output scales belong to the
separate RMSNorm operation, not this fixed mantissa table. They still need
canonical operation/configuration identity bytes before norm admission.

`exp_q` alone is not a component table name: a large product is a composition
of hi/lo memberships and integer relations. This candidate rejects it rather
than materializing a table exceeding 2^16 rows. Direct and product functions
cannot share an identity. RoPE remains a public tensor with its own pending
variant/parameter contract, not an implicitly registered lookup here.

## 2. Integer data, padding and field interpretation

Derive N, padded size L=2^ceil(log2 N), and column count c from the descriptor.
N<=L<=65536 and c is one for range tables, two otherwise. The candidate data is

    ASCII("stele/v0.1/table/data") || TableId[32] || u32le(N) || u32le(L)
    || u8(c) || row-major i32le entries for all L rows and c columns.

Each i32 is a signed two's-complement integer. Inputs precede outputs. Valid
rows follow the order above; rows N..L-1 contain c zero integers. The decoder
checks the expected identity and descriptor-derived sizes, then exact byte
length, before allocating parsed rows. Neither claimed dimensions nor a matching
self-supplied digest determine allocation or semantic acceptance. It rejects
nonzero padding, reordered rows, any wrong value and trailing/truncated bytes.
Generation rejects the entire table on overflow or unresolved precision.
A valid descriptor alone therefore does not admit its table configuration.

For lookup/MLE use, lift each integer v to the unique canonical M31 encoding
of v mod p, then into QM31/OM31 as a base-field constant. Integer artifact bytes
are distinct from field-element bytes: e.g. -1 is i32 0xffffffff here, whereas
its canonical field limb is p-1. A positive integer v+p substituted for a
negative v is rejected even if its field lift agrees. All valid component
coordinates have magnitude <=65535, below p/2; this bound does not certify
the larger exp input decomposition or RMSNorm arithmetic.

The candidate padded column MLE uses MSB-first row index order. Its definition
is sum over Boolean row indices of the padded entry times the equality basis.
The public valid-row selector is one precisely on indices below N. Padding
must be excluded by the lookup/plan consumer; zero padding alone proves no
membership exclusion. This prototype checks bytes and rows, not native MLE
evaluation parity or the lookup selector relation.

## 3. Binding, reproduction and delivery limits

TableId hashes the definition, not caller-provided rows. A research data digest
H(data) is useful reproducibility evidence but is not a passport code commitment
or proof that an untrusted table follows the definition. Admission regenerates
every row from that definition. A future passport must authenticate the exact
descriptor set, function compositions and expected code/Merkle roots derived
from these validated tables (or a sound proof of that derivation). Merely
publishing a matching TableId beside an arbitrary root is insufficient.

Run `uv run --locked --script research/cqis-tables/check_identity.py`.
The [artifact](../research/cqis-tables/table-identity-candidates.json) records
all 13 descriptor frames/ids and nine complete data shapes/digests. Independent
byte assembly checks framing and signed row layout. Every truncation, appended
byte, unknown schema, invalid cap/split, giant claimed length, modified id,
entry, field alias, order and padding is tested. A valid but overflowing SiLU
configuration fails data generation. Numerical correctness remains covered by
the separate exact-oracle studies; this is not an independent numerical oracle.

No challenge, ledger line, private commitment or weight pass is introduced.
Generation, definition validation and storage require O(Lc) entries and belong
in T_misc; eventual public MLE/membership work remains in c_lu. No measured
constant or benchmark result is claimed. Complete A2, RFC-0008/0011 framing,
composition/configuration binding, native table/identity controls and Rust/NumPy
parity remain before production delivery. Q12 and the full privacy goal remain.
