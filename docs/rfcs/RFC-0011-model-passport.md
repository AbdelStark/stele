# RFC-0011 — Model passport and checkpoint binding

Status: Accepted · Version: 0.1.0 · Depends: RFC-0004, RFC-0010

## 1. Contents (`passport.json` + binary artefacts), `passport_root = H(all fields)`
1. `cqis_id`, model configuration (shapes, formats, table ids, scale exponents), `plan.json` digest.
2. Weight commitments: per type `τ` the Merkle root, layout, code parameters, element format; scale tensors in plaintext.
3. Table commitments (every registered table as an interleaved-code matrix) for wrapper-mode openings.
4. **Proximity certificate** (optional, treaty: required): a transcript proving each committed matrix is within the
   proven proximity radius of an interleaved codeword, with randomness derived from the roots (one-time, RFC-0010 §5).
5. **Checkpoint binding proof**: a proof that the committed plaintext (packed int8 weights + scales, canonical
   serialisation `cqis-weights-v1`) hashes to `digest_cqis`, and that `digest_cqis` was produced from the published
   checkpoint `digest_hf` (SHA-256 of the safetensors) by the public quantiser `quantiser_id`. v0.1: the quantiser step is
   reproducible, not proven (anyone with the HF checkpoint can recompute `digest_cqis`); the hash binding of the commitment
   to `digest_cqis` is proven in the wrapper (SHA-256 or Blake3 in-circuit, one-time, RFC-0016 §6).
6. **Fidelity report** (RFC-0004 §8) with item-level hashes so it can be re-run.
7. Registration metadata: registrant identity, timestamp, signature(s); optional registry transaction reference.

## 2. Lifecycle
`quantise → commit → certify → bind → evaluate → publish`. Any change to weights or CQIS version is a new passport.
Proofs reference `passport_root` in their public input; verifiers cache passports.

## 3. Cost (one-time, per model)
Encode + Merkle 4·10¹¹ elements with circle RS: ≈ 2^39 · 39 butterflies ≈ 10 GPU-minutes; hashing ≈ 1 GPU-minute;
proximity certificate ≈ one weight pass; checkpoint binding ≈ hashing 400 GB in-circuit ≈ 10³–10⁴ GPU-s (Blake3) or
10× more (SHA-256). Negligible against the model's lifetime.

## 4. Confidentiality
The passport reveals shapes and scales only. Treaty registrations may encrypt scales to the verifier set; the ZK
argument (RFC-0013) keeps weight values hidden through all openings.

## 5. Hooks for traffic binding (out of scope, interface only)
`io_digest` may be replaced by `(input_commitment, output_commitment)` with openings held by a certifier; the proof
statement is unchanged. A `session_id` field allows multi-turn chaining (RFC-0017 §9).

## 6. Negative controls
NC-0700 passport root mismatch; NC-0701 table commitment swapped; NC-0702 certificate for a different root; NC-0703 scale
tensor altered after registration.

## 7. Amendment log

### A1 — Confidentiality across a fixed passport's lifetime

Status: Draft. Question Q29. Companions RFC-0013 A1 and RFC-0010 A7.
Evidence: [mask lifetime and fixed-oracle analysis](../../formal/commitment-privacy.md).
Motivation: a mask row committed in a passport is fixed with its root. Fresh
proof challenges cannot refresh it, and raw coordinate disclosures accumulate.

Proposed addition to §§2,4:

> Specify the complete confidentiality lifetime of each committed weight oracle,
> including its certificate and every later opening. Any query-bounded masking
> argument must count the cumulative disclosures to that same oracle. Fresh
> session identifiers, seeds or challenges do not change its committed mask.
> A mask refresh must bind the unchanged source to the resulting commitment and
> justify certificate reuse or replacement. Its source reads, registration work,
> storage and per-proof costs require explicit accounting. Alternatively specify
> a protocol hiding the queried payload itself. Neither path is selected here.

The original checkpoint/source binding, public statement, privacy goal and
one-weight-pass requirement remain. No new root, seed API, certificate format,
loss or profile is admitted. Costs and possible protocol losses depend on the
complete replacement; no measured constant changes. Affected tasks: E4-05,
E4-06, E10 passport/inference and E12 privacy/certificate consumers.

### A2 — Canonical function manifest and table commitment binding

Status: Draft. Companion RFC-0021/RFC-0004 A4 and RFC-0008 A4. Review: pending.
Motivation: a table id names a definition, while an arbitrary supplied root can
commit to different data. The function set also omits operation/source mapping.

Addition to §1 items 1,3: the passport authenticates the exact RFC-0021 function
manifest, and each operation in its canonical model/plan identifies its expected
FunctionId/RepresentationId and source/scale/gain tensors. The verifier derives
the exact manifest and component closure from that authenticated configuration.
Recompute component data from the complete definition; an id beside an unchecked
root, or a supplied data digest, is not definition binding. Store the manifest
as its exact binary bytes, not a reserialized JSON object. The full cqis_id and
passport_root encodings must include these typed fields under their complete
canonical outer contracts; this extension alone does not supply those contracts.

For each component, form the public M31 message matrix with c rows and L columns:
matrix[j,i]=canonical_lift(T[i,j]), with all prescribed padding already present.
There is no packing, transposition choice, extra mask or omitted tuple column.
Use the exact verifier-owned Accepted RFC-0010 A2/A4 code identity; its message
length must equal L. Encode each row in M31. A coded column contains c canonical
u32 M31 limbs in tuple-column order, so its byte width is 4c. Authenticate those
columns using RFC-0012 A3 kind 0, the plan's distinct u64 tree id, codeword length
and width 4c. Tree ids must be unique across the plan's roles and are not truncated
TableIds. Recompute the expected root from this exact source/code/layout before
admitting the table binding, or use a separately Accepted proof of that derivation.
An inclusion proof alone does not establish contents or encoding.

The canonical table-binding record is

    ASCII("stele/v0.1/passport/tables") || H(function_manifest)[32] || u32(count)
    || entries in raw TableId order, each:
       TableId[32] || H(canonical_table_data)[32] || u8(field=1 for M31)
       || u16(code_id_length) || complete_code_id || u64(tree_id) || root[32].

Lengths are unsigned little-endian, with no padding, aliases or trailing bytes.
The current closed code factory accepts only its exact 21/55-byte identities.
Count, component set, code ids, tree ids, source dimensions and roots are checked
against the verifier-owned configuration and complete regeneration, before use.
No record may choose its own trusted code, field, source, shape or expected root.
The table-binding record and manifest are mandatory typed inputs to the complete
passport/CQIS binding; hashing them beside an opaque unvalidated config is not
admission. Changing any selected field requires a new passport.

Wrapper MLE openings must use those same matrices/roots and the full Accepted
PCS/recursion schedule; this record does not certify a code's profile parameters,
proximity, private weights, or ZK. A1 confidentiality requirements remain open.
NC-0701 retains the actual swapped-root consumer; NC-0412/0413/0414 cover the
configured function/representation/data edges when implemented. All controls
remain real-consumer obligations, with no primitive/research catalog credit.
One-time table generation/encoding/hash work is explicit T_misc/commitment work;
no measured constant, additional inference weight pass or intermediate cut.
E10 retains its complete outer bytes, registration, checkpoint, profile, fidelity
and proof gates; none is waived by this deterministic table subrecord.
