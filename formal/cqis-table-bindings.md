# Canonical table matrices and root binding (Q25)

This is executable evidence for Draft RFC-0011 A2 / RFC-0021, not a new PCS,
passport or lookup verifier. It reuses the exact code-identity and Merkle
research implementations governed by Accepted RFC-0010 A2/A4 and RFC-0012 A3.

For descriptor-derived rows T of shape L by c, the source matrix is c by L:
row j contains canonical M31 lifts of T[i,j], including every padded zero.
Encode each complete row with the verifier-owned code identity whose message
length is exactly L. Coded column i serializes the c canonical M31 limbs in
tuple-column order. The Merkle context fixes kind 0, a distinct plan-owned u64
tree id, the full codeword length and width 4c. No tuple column is omitted.

The expected record is derived from configuration, never from supplied roots:
its function-manifest hash and sorted component set are regenerated; each entry
binds TableId, the canonical integer-data digest, field tag, complete code id,
tree id and computed root. Record verification compares all expected bytes.
All code lengths and tree-id uniqueness checks precede encoding. The arithmetic
helper accepting explicit rows is used to construct attacks; it is not an
admission path. The expected-root path regenerates and validates every row.

Two attacks distinguish the required bindings:

1. Alter one correction output and encode the resulting table honestly. A
   Merkle opening under its new root verifies. Replacing only the expected
   record's root with that root rejects: membership proves nothing about the
   intended numerical definition.
2. Replace an integer input -128 by -128+p, still within signed i32. Its M31
   lift, entire codeword and root are unchanged. Canonical integer-data
   validation rejects the alias; substituting its data digest in the record
   rejects too. Field encoding alone cannot establish canonical integer bytes.

The [executable](../research/cqis-tables/check_table_bindings.py) independently
parses each record and checks real Merkle openings at the first, middle and last
coded columns. Cases cover corrected exp plus range with both Circle and v2
expander identities, product exp including a two-row high component, and all
49,152 rsqrt rows padded to 65,536 and encoded to 131,072 columns. The
[artifact](../research/cqis-tables/table-binding-candidates.json) records exact
bytes, roots and contexts. Empty closure and order independence are checked.

Mutations cover manifest/id/data/field/code-length/tree/root bytes, omitted or
extra components, invalid/duplicate/context-colliding tree ids, incompatible
message dimensions, tuple-column order, truncation and trailing bytes. Invalid
configuration tests replace the encoder with a failure sentinel to establish
that validation precedes encoding. This is ordinary research testing, with no
native catalog credit or synthetic proof-acceptance claim.

The complete outer cqis_id/passport codec, actual operation/source binding,
wrapper PCS and profile admission remain unchanged obligations. Generation,
encoding and hashing contribute to T_misc/commitment work; no benchmark number,
soundness loss, weight pass or committed intermediate is introduced.
