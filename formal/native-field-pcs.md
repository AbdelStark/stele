# Conditional native Circle field openings

Status: Draft proposal for RFC-0010 A9. This contract closes a general field
functional against the unique near-message interpretation of a certified
Circle commitment. A separate adapter closes every original claim returned
by native RFC-0006 A1. It does not admit an inference proof or either profile.

Every verifier error aborts the enclosing proof attempt and returns no usable
accounting result or certificate handle. A partially advanced transcript cannot
be retried or rolled back. The caller discards that attempt after failure.

## 1. Expected source and exact parameters

The source owner supplies the complete expected context. The proof cannot
replace its root, code, dimensions or field. Version 1 supports only the
Accepted Circle encoder and canonical M31 message elements, embedded in
the selected K=QM31 or OM31. For R=2^ell and C=2^m, the message order is
`M[row*C+column]`. Native point coordinate zero controls the highest index
bit. The certificate's row distribution is the same as the low-bit notation
in tensor-opening.md after permuting independent coordinates.

Canonical source bytes, concatenated without padding, are:

| Field | Bytes |
|---|---|
| purpose | ASCII `stele/v0.1/field-source` |
| version | u8(1) |
| challenge degree | u8(4) or u8(8), equal to the selected K |
| tensor/tree identity | u64le(id) |
| row exponent | u8(ell), 0 <= ell <= 30 |
| code identity | exact 21-byte Circle ID from RFC-0010 A2 |
| logical rows, columns | u64le(R), u64le(C) |
| layout | u8(0), canonical row-major field elements |
| policy | u8(1), the exact finite query policy below |
| expected root | 32 bytes |

Logical and padded dimensions coincide in this version. Other layouts or
logical extents reject as UnsupportedSource; no implicit padding, packing
or signed-integer interpretation is introduced. Let N=2^(m+b). The Merkle
descriptor is exactly `{kind: Columns, id, count: N, width: 4R}`. Every
payload is R canonical u32le M31 elements in row order. Reject limbs >=p.
The code ID determines m,b and must pass the existing Circle factory.

Derive D=N for C=1 and D=N-C otherwise; e=floor((D-1)/3). Policy 1 selects
the least positive q_c,q_o satisfying, respectively,

```
2^130 * (N-e-1)^q_c <= N^q_c
2^130 * (N-D+e)^q_o <= N^q_o.
```

Use immutable u16 tables indexed by validated m,b. The independent Python
checker must verify both inequalities and their failure at q-1 for all
59 Circle IDs. No TOML flag, proof-supplied q, floating point or native big
integer dependency selects parameters. These counts establish query terms
only; they do not pass a complete profile budget.

The fixed table entries are:

| b | Quantity | Entries by m |
|---|---|---|
| 1 | q_c | m=0:130; 1..2:314; 3..4:434; 5..6:478; 7..8:491; 9..12:494; 13..29:495 |
| 1 | q_o | m=0:1; 1:130; 2..3:192; 4..5:214; 6..7:221; 8..9:222; 10..29:223 |
| 2 | q_c | m=0:130; 1..28:314 |
| 2 | q_o | m=0..6:[65,92,110,119,125,128,129]; 7..28:130 |

## 2. Column sampling

For each requested index, set T=floor(p/N)*N=p-(N-1). Make at most 64 calls
to the dedicated registered PCS column challenge label. Each successful
`Transcript::challenge` returns a full K value. Read its first canonical
M31 limb x; accept x mod N only when x<T. Invalid N outside powers of two in [2,2^30] returns InvalidColumnDomain
before a challenge. Outer exhaustion returns ColumnSamplingExhausted; inner
SamplingExhausted propagates unchanged. Every rejected attempt has already
advanced the transcript using all K limbs. Discard the other limbs for index
selection; never recycle them. An inner sampling error or 64 failed outer
attempts aborts the whole operation. No rollback, fallback or hidden retry.

Each index has exactly T/N accepted preimages. In the ideal interactive
model the completed draws are independent and uniform with replacement.
Outer exhaustion is below 2^-64 per requested index. With the Accepted RFC-0012 A1
inner-decoder bound, PCS-only abort probability is at most
`q_total*2^-64 + (ell_total+64*q_total)*2^-1703`.
This is an availability bound, not false-acceptance loss. The complete adapter
also counts every RFC-0006 A1 and other non-PCS draw. Every attempted
draw, XOF evaluation, state update and abandoned attempt still counts in
the actual FS/H resource model. Unused K limbs do not enlarge the column
sample space beyond N.

## 3. Standalone registration certificate

Construct a fresh Transcript from the nonempty public bytes
`ASCII(stele/v0.1/pcs-certificate/public) || source_bytes`.
This binds purpose, expected root/context and policy before row randomness.
Draw ell K values using challenge(CertificateWeight). Construct a
using the native MSB-first eq table. For R=1 use a=(1) with no row draw.

The prover sends t in K^C. Absorb its complete canonical bytes using
absorb(CertificateRow) before drawing q_c column indices under CertificateColumn. Send one
response per draw, in draw order, even when indices repeat. A response is
exactly `4R` payload bytes followed by `log2(N)` 32-byte siblings in
bottom-up order. No response contains a proof-supplied index.

Invoke the single-path Merkle verifier for each draw, preserving duplicates.
Authenticate each response at its derived index, decode every field limb,
and check `Enc(t)[c]=sum_i a_i*column[i]`. Check all q_c responses. Then
absorb the entire response block using absorb(CertificateColumns).

The certificate wire is `u8(1) || t_bytes || response_block` with lengths
derived from the expected context. Reject truncation, trailing bytes,
noncanonical K limbs, path/column errors or a failed equation. The complete
proof is parsed with checked size arithmetic before allocation or execution.

After successful full verification, compute its certificate ID as

```
H(ASCII(stele/v0.1/pcs-certificate/id)
  || u64le(len(source_bytes)) || source_bytes
  || u64le(len(certificate_bytes)) || certificate_bytes).
```

This is a domain-separated hash binding, never a challenge. It needs the
explicit RFC-0012 API and H accounting. The completed-proof ID cannot occur
in this certificate's own public input or challenges: that would be circular.

Only full verification constructs an opaque VerifiedCertificate<K>. Its
private identity includes exact source/context, policy, K and certificate ID.
Imported bytes always reparse and reverify. There is no unchecked constructor,
deserialization, from_digest or boolean receipt path. This explicitly permits
collision-accounted digest identity for A8's exact-certificate cache key.
The handle alone does not accept a functional claim or inference statement.

## 4. General functional opening

The verifier owns opening id, the verified certificate and complete expected
`a in K^R, b in K^C, v in K`. Validate their lengths and field before use.
Absorb `u64le(opening_id) || source_bytes || certificate_id || a_bytes ||
b_bytes || v_bytes` using absorb(Opening). All lengths are fixed
by that context; proof metadata cannot override them.

The prover sends u in K^C. Absorb the complete u using absorb(OpeningRow),
check dot(u,b)=v, then derive q_o fresh indices under OpeningColumn. Responses have the same
fixed format as certificate responses and retain duplicates. Authenticate
each response, canonically decode it and check each equation
`Enc(u)[c]=sum_i a_i*column[i]`. Absorb the entire response block using
absorb(OpeningColumns) before any continuation challenge.

Opening wire is `u8(1) || u_bytes || response_block`; reject any short,
extra or malformed data. The initial implementation uses full individual
paths and every draw response. It performs no proof-selected deduplication. The sorted unique-index Merkle
batch API cannot consume this ordered repeated-query schedule.
Multiple openings are separate executions with separate query terms. The
general batched/grouped optimization in A3 retains its own implementation
obligations; no multi-claim error is silently charged as one opening.

Point openings derive a,b using the existing eq-table implementation.
The point has exactly ell+m coordinates, split at ell. Zero coefficients
do not exempt a source or a column equation. Actual fused u=B ownership
remains RFC-0010 A6/RFC-0007 A1 work; this contract supplies no fused receipt.

## 5. Closed RFC-0006 A1 consumer

Place the field-source adapter in stele-reductions. It receives the
verifier-owned RFC-0006 A1 instance and expected ordered certified sources, plus
the A1 proof and one opening proof per original input. Its verifier API
receives no original source tables or authentication callback.

The source roster must exactly equal Instance.inputs, including order and
count, with distinct tensor IDs and matching ell+m=Instance.num_vars.
Preflight the complete source/opening roster, all wire lengths and the A1
instance/proof shape before any absorb, sharing A1 validation with its verifier.
Before calling sumcheck::verify, absorb the complete ordered bundle:
`u64le(instance_id) || u32le(source_count) || (source_bytes || certificate_id)*`
using absorb(FieldSources). The source bytes have fixed context lengths.
An empty input roster requires an empty source/opening list.

Call the actual RFC-0006 A1 verifier. For every returned claim, use its returned
point and value and the matching expected source. Derive row/column weights
and run the actual PCS opening verifier in original input order. Use the
tensor ID as the opening id within this instance's already-bound segment.
Consume unused inputs and zero-factor originals as well. No ignored proof,
extra claim, synthetic receipt or caller-supplied replacement point survives.
Return only the complete conditional algebraic/PCS accounting result.

This requires explicit stele-pcs dependencies on field/poly, and
stele-reductions dependencies on field/hash/sumcheck. Add them through
RFC-0020, with the exact policy tests. GKR gains neither a PCS dependency
nor an authentication callback. The full verifier's dependency contract
remains a separate integration requirement.

## 6. Accounting, resources and acceptance tests

Certificate terms are `2*ell*(e+1)/|K|` and `((N-e-1)/N)^q_c`.
Each opening contributes `((N-D+e)/N)^q_o`. Keep A8's global collision and
late-preimage terms, all applicable certificate-attempt/lifetime terms and
A1's SC record. Certificate reuse retains its lifetime loss.
The resulting records remain conditional: Q12, privacy, source ownership
and the complete profile sum are unresolved. No proven flag changes.

Check every size conversion, shift, product and sum before allocation;
use fallible allocation and return Capacity without partial success.
Charge source RC storage, encoded RN elements, all Merkle nodes, K-valued
row and encoding buffers, complete proof bytes, coefficients and overlap.
Certification performs a registration pass; ordinary functional row
preparation costs O(RC), scalar checking O(C), and column equations O(qR),
in addition to encoding and authentication. No full-opening performance or
one-weight-pass result follows from these formulas.

Required tests cover both fields, every parameter entry, MSB point parity,
threshold boundaries, forced sampler exhaustion, duplicate queries, changed
response order, noncanonical fields, stale queries and response absorption
before a real continuation. A source/certificate substitution must fail at
its actual consumer. Alter an unused A1 final so the reduction itself still
passes; its terminal opening must reject. Run complete native and independent
Python verification on the same canonical bytes, plus malformed-proof fuzzing.
Native controls and registry labels must land with the implementing change.

## 7. Exact registry additions

All labels below have prefix `stele/v0.1/pcs/`. Absorb entries carry no
randomness line. The row challenge owns the tensor term; column challenges
own the relevant query term, including every rejected outer attempt in the
resource counts. None of these entries supplies a complete FS/H bound.

| Typed label | Suffix | Kind / accounting |
|---|---|---|
| CertificateWeight | certificate-weight | challenge / PCS tensor |
| CertificateRow | certificate-row | absorb |
| CertificateColumn | certificate-column | challenge / PCS query |
| CertificateColumns | certificate-columns | absorb |
| Opening | opening | absorb |
| OpeningRow | opening-row | absorb |
| OpeningColumn | opening-column | challenge / PCS query |
| OpeningColumns | opening-columns | absorb |
| FieldSources | sources | absorb |

Add closed typed choices and PCS tensor/query loss categories to the fixed
registry through RFC-0012. The index sampler accepts only CertificateColumn
or OpeningColumn; arbitrary challenge labels and external generators are
not its API. Pure candidate decoding supports forced threshold/exhaustion
tests without a production randomness-injection path.

## 8. Errors and proposed native controls

Use FunctionalShape for wrong coefficient or standalone point lengths,
UnsupportedSource for rejected context/code/layout/policy values,
ProofShape for wire length/version errors, NoncanonicalField for invalid
limbs, ValueMismatch for the scalar functional, ColumnMismatch for a failed
encoded-column equation, CertificateContext for a mismatched verified handle,
and SourceRoster for the A1 ordered-source contract. Preserve Merkle errors,
Capacity and transcript sampling errors as their stated causes. Structural
length checks precede transcript changes. Authenticate a response before its
field decoding and column equation. All failures obey the abort rule above.

Reserve these controls as todo at acceptance; the implementing change must
supply their actual binaries. Proposed additions are NC-0606 (certificate/context substitution),
NC-0607 (canonical field interpretation at an authenticated leaf), NC-0608
(certificate identity/reuse) and NC-0609 (complete A1 original-source roster).
NC-0600 checks encoded-column consistency; NC-0601 and NC-0803 exercise actual
query scheduling. NC-0602 retains its existing path controls. These proposed
IDs confer no coverage before their real binaries run. Packing, blinding
and fused NC-0603..0605 remain unfulfilled by this field-only contract.

## 9. Conditional records and lifetime ownership

Successful certificate verification constructs an immutable CertificateRecord
inside the opaque handle: full source context, certificate ID, ell,N,D,e,q_c,
field degree and Certificate operation kind, all verifier-derived. A successful
opening returns OpeningRecord with its expected opening ID, q_o, Opening kind
and a reference to that original CertificateRecord. The closed adapter returns
the actual ScRecord and ordered opening records with certificate references.
These are conditional proof obligations, not evaluated probabilities, boolean
receipts, admission decisions or profile totals. Reuse never erases a certificate
loss or represents it as a new zero-loss certificate.

Root/context identifies A8's first frozen oracle. Root/context/certificate ID
identifies certificate replay. A new certificate for that same root cannot
re-freeze it. The external composition layer owns deterministic registration,
fresh-certificate-attempt and hash-query caps fixed before execution, including
failed and abandoned attempts. Local work counts cannot establish adversarial
query caps. No full composition or budget validator is supplied by this primitive.

A separate non-authorizing usage record counts ordinary hash evaluations, XOF
requests and output bytes, transcript state updates, inner candidate words
consumed and outer column attempts. Count discarded attempts too. Transcript
keeps checked counters and exposes immutable snapshots, including A1 draws.
Merkle verification and certificate-ID hashing report their work explicitly.
Failure returns no proof record or handle, but its local usage remains observable;
these observations authorize no continuation of the failed attempt. Counter
overflow aborts before unrecorded work. Local evaluations are not distinct
adversarial random-oracle queries.

Resource reports include full encoder scratch/twiddles, encoded words, selected
outputs, transposed columns, leaf-reference arrays and Merkle nodes. Calling
Circle::eval_row still performs complete encoding; no sublinear cost is inferred.
