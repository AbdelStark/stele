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

Status: Accepted. Companion RFC-0021/RFC-0004 A4 and RFC-0008 A4. Review: [coordinated skill sign-off](../../agents/reviews/cqis-functions-contract-accepted.md).
Motivation: a table id names a definition, while an arbitrary supplied root can
commit to different data. The function set also omits operation/source mapping.
Executable evidence: [canonical table matrices and roots](../../formal/cqis-table-bindings.md).

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
E12-05 retains its complete outer bytes, registration, checkpoint, profile, fidelity
and proof gates; none is waived by this deterministic table subrecord.

### A3 — Typed checkpoint source identity for indexed shards

Status: Draft. Question Q26. Evidence: [indexed source study](../../research/cqis-checkpoint/SHARDS.md).
Motivation: §1 item 5 names SHA-256 of safetensors without distinguishing one
file from a checkpoint consisting of an index and several files. A digest of
framed file hashes is not SHA-256 of any single safetensors file.

Proposed addition to §1 item 5, pending the complete outer contract/consumers:

> Source identity is typed. Single-file sources retain the original file's exact
> SHA-256. Indexed sources authenticate the complete original index and exact set
> of original shard files through a versioned canonical manifest, preserving each
> file's name, length and SHA-256. Record its distinct bundle digest and source
> kind; never relabel this value as a single-file digest_hf. Check exact tensor
> locations, absence of duplicate/unindexed tensors, complete container coverage
> and the declared physical payload total before source conversion. Source and
> preparation identities bind explicit selection/ignored policy and complete
> offline conversion metadata under the final quantiser/passport encoding.
>
> Expected source/configuration authority comes from the authenticated statement
> and passport, not the supplied files. Reproducible conversion does not replace
> the required commitment-to-artifact hash binding, wrapper, privacy or fidelity.

The study fixes executable candidate manifest/tag bytes, file/index validation
and partition-invariant numerical output. Acceptance still requires canonical
outer passport/quantiser fields, source/role/tie semantics, native streaming and
resource admission, and actual wrong-source/index/shard/selection consumer controls.
RFC-0004 A3/static certificates, Q12/Q29, all original tasks and existing controls
remain required. No challenge, production loss, new commitment or profile is
introduced; source/hash preparation is T_misc, without a measured constant or
inference weight-pass change. E5-03, E10 and E12-05 are affected but not completed.

### A4 — Complete physical Artifact and Preparation binding

Status: Draft. Question Q26; task E5-03b. Companion RFC-0025 §2.7 and its
[encoding appendix §3](full-model-encoding.md). This proposes the complete
`cqis-weights-v1` frame for the mandatory GPT-2/Llama physical roles: explicitly
selected int4/int8 matrices, int16 gain/bias vectors, original matrix scales and
the prescribed GPT-2 token/head tie. It broadens §1 item 5's packed-int8
description; it is not enabled by the current Accepted contract.

The passport must authenticate the exact Preparation/quantiser_id, Model and
Scales used to derive every physical record, alongside the complete typed source
identity from A3 and digest_cqis. Preparation binds the canonical source map and
all physical configurations; the Artifact embeds its quantiser_id. Record and
payload lengths, order, coordinates, packed tails and every scale byte derive
from that same expected configuration. A syntactically valid changed payload
changes digest_cqis without changing the conversion algorithm identity.

Streaming structural validation checks all bytes and exact exhaustion. It does
not establish minimal quantiser scales, source conversion, alias equality or
publisher authority. Preserve §1 item 5's reproducible original-source conversion
requirement and its separate proven commitment-to-Artifact hash binding. The
actual wrapper must bind the same physical codes, scales, packing, role/layout
and complete Artifact bytes; a hash beside an unchecked commitment is insufficient.

The full passport/public-input codecs, actual hash/source consumers, H/query
accounting and negative controls remain acceptance/delivery work. A2's complete
table commitment binding, A1/Q29 confidentiality, private PCS/ZK, fidelity,
certificates, registration and encrypted-to-verifiers scales remain required.
Preparation/Artifact scans are one-time T_misc/hash work; this proposal adds no
online inference weight pass, cut, challenge, profile or measured constant.

Draft continuation of A3/A4. The RFC-0025 [source appendix](full-model-source.md)
fixes canonical Source and Assets frames. Source includes exact file names,
lengths and SHA-256 values, including the original index name and bytes.
Its typed identity remains the actual single-file SHA-256 for kind 0 and a
distinct H(Source) bundle identity for kind 1. Authenticate the complete Source
as well as that derived identity: a kind-0 filename is not in the file digest.
Assets binds the exact config, tokenizer and optional generation files under
a separate assets_id. The passport must authenticate these alongside A4's
Preparation, Model, Scales and Artifact, without treating supplied hashes as
their own authority. Actual config/text adapters must consume the same original
bytes and check all used parameters. Exact hashes alone cannot prove that join.

Before returning source slices, check every actual file, complete container and
index coverage, selected/alias/ignored union, raw dtype/shape and permitted alias
bytes. Retain immutable backing bytes through conversion; hashing a file before
reading an unchecked mutable replacement does not suffice. Native resource
admission, reproducible conversion, commitment/hash consumers and all existing
privacy/profile/fidelity/accounting/control requirements remain unchanged.

The RFC-0025 [conversion appendix](full-model-conversion.md) connects those
immutable source slices to minimal matrix scales, exact vector rounding and the
complete streamed Artifact. Its success result requires full emission, and
failed output must be discarded. Independently authenticate the original
Source/Assets and Preparation before treating regenerated bytes as the expected
artifact. Reading back stored bytes and proving the committed-plaintext hash
relation remain separate obligations; a numerical conversion result does not
discharge them. Complete semantic adapters, native consumers, outer passport,
H/query accounting and every existing privacy/profile/fidelity requirement
remain necessary for acceptance and delivery.

The [source-architecture appendix](full-model-source-architecture.md) further
specifies SourceConfig/source_config_id. Authenticate the explicit source
layout and this complete record alongside its same Model, Map and Assets.
Original config bytes must supply the exact declared architecture, epsilon,
rotation and source-role mapping; a matching dimensional summary is insufficient.
Closed absence rules belong to the versioned adapter, not host-library defaults
selected during execution. Configuration metadata never authorizes remote code,
casts or an unchecked inference backend. Tokenizer/generation consumers, original
checkpoint authority and the commitment/hash/private-proof obligations remain.

### A5 — Passport template and per-request statement references

Status: Draft. Question Q26; task E5-03b. Motivation: a persistent passport's
plan digest and a request-specific proof-plan digest have different lifetimes.
Companions: RFC-0005 A4 and [RFC-0025 public input](full-model-public-input.md).

Proposed clarification of §1 item 1 and §2: the passport binds the exact complete
model-wide plan template. A request instantiates it with independently expected
request fields; the resulting instance's hash is the public-input plan_id.
Neither a new request nor a different permitted sequence length issues a new
passport. Physical/source/layout changes still require a new passport. The same
complete authenticated passport and CQIS records govern every instance.

Proposed clarification of §5's optional I/O commitments: the public frame carries
distinct input/output tree-id and root references. The full plan must prescribe
their exact token sources, lengths, layout/code/context, private opening and mask
lifecycle, including the zero-generated-token case. The envelope cannot supply
or skip those contracts. Original traffic/chaining, complete outer passport,
source/hash proof, fidelity, registration and Q29 requirements remain unchanged.
No challenge, commitment construction, profile, cost constant or online weight
pass changes. Preparation/identity checks contribute T_misc; complete H/query
accounting and actual passport/source controls remain required. Affected tasks:
E5-03b, E6, E8, E12-05, E13-05 and E14.

### A6 — Acyclic passport subject, evidence and signatures

Status: Draft. Question Q26; task E5-03b. Motivation: §1's H(all fields) needs
exact framing and an acyclic construction when certificates, signatures and
registry references are themselves fields of the passport.

Proposed replacement for the outer encoding in §§1,2: use the complete
[RFC-0025 composition frame](full-model-passport-composition.md). Its model
subject binds exact numerical/source/Artifact, plan and commitment/table roles.
Evidence binds that subject; registration binds the subject, evidence and exact
key roster. Every registered key signs the defined 120-byte message over those
three identities. The final passport includes all signature references and has
its own root. Signatures and evidence do not attest to that later final root.
Actual proof and signature verification remain mandatory at their consumers.

Each referenced artifact must match its complete bytes and pass its typed
semantic/authority checks. This framing admits no opaque configuration, arbitrary
signature suite, self-authorized registrant, private commitment or security
profile. All complete child codecs and approved authority/suite contracts remain
prerequisites. Treaty still requires valid proximity evidence; checkpoint binding,
fidelity and registration remain mandatory, with Q12/Q29 and private PCS/ZK intact.

A registry receipt created after publication refers to the final passport from
outside it. An optional in-passport registry reference can identify only an
already fixed independent record. Do not mutate a passport to include a receipt
whose transaction depends on that passport's root. Existing traffic/chaining
and lifetime/privacy requirements remain unchanged.

This fixes deterministic preimages and adds their reference/composition hash
work to the pending complete H/query schedule. It adds no Fiat-Shamir challenge,
profile, intermediate cut, measured constant or online weight pass. Preparation,
signature and evidence validation remain explicit T_misc/registration work.
Affected tasks: E5-03b, E6, E8, E12-05/06 and E14. NC-0700..0703 and all original
source/hash/private-proof controls must run against their real consumers.
