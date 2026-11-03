# RFC-0025 passport composition and identity order

Status: Accepted. Part of [RFC-0025](RFC-0025-full-model-cqis.md), Q26/E5-03b.
This fixes outer composition, referenced artifact roles and attestation preimages.
Complete child schemas, approved signature suites/authority policy, private
commitment/proof consumers and profile admission remain mandatory before a
passport can be accepted. A parsed reference is never an authenticated child.

## 1. Content references and model subject

H is ordinary unkeyed BLAKE3-256. Integers are fixed-width unsigned little-endian;
B(x)=u32(len(x))||x. A nonempty immutable artifact has
Ref(x)=u64(len(x))||H(x)[32]. Length is in 1..2^64-1; no zero-length or all-zero
digest sentinel denotes absence. A reference check requires the complete exact
bytes, then the artifact's actual semantic validator. A hash-only match cannot
replace the latter. Referenced data may be stored separately and, where required,
encrypted to authorized verifiers; this frame does not publish private payloads
or define an encryption format. The authorized plaintext must match the reference.

The eleven subject references, in exact order, are Model, Scales, Registry,
Bounds, Preparation, Source, Assets, SourceConfig, PlanTemplate, WeightBindings,
TableBindings. Each has its own required closed schema and actual consumer.
There is no caller-selected role list, omitted role, count or extension slot.
The first eight use the existing RFC-0025 appendices; TableBindings retains
RFC-0011 A2's complete regenerated table/code/root relation. The full plan and
private weight-binding schemas remain prerequisites, not opaque trusted blobs.

    Subject = ASCII("stele/v0.1/passport/subject") || cqis_id[32]
       || typed_source_identity[33] || Ref(Artifact) || Ref[11]

Artifact is the exact complete cqis-weights-v1 bytes. Its reference supplies
digest_cqis and exact length. quantiser_id, assets_id and source_config_id are
the Preparation, Assets and SourceConfig reference digests, respectively.
cqis_id is rederived from the complete Model/Scales/Registry/Bounds identity.
Its four inner hashes must equal the first four reference digests. For indexed
source kind 1, the typed source digest equals H(Source); kind 0 retains the
original safetensors SHA-256 and still binds the complete Source reference.
Recompute these relations from complete original artifacts, not supplied hashes.

Subject includes complete commitment/layout/code and table-binding references,
but no evidence, signature, registration, final passport_root or request fields.
PlanTemplate is model-wide and must omit Subject's hash and all later identities.
subject_id=H(Subject) is the subject of registration evidence. Certificate and
checkpoint-binding consumers must prove their actual relations for this same
subject and all original committed sources, not merely repeat subject_id.

## 2. Evidence and registration

Let OptRef be u8(0) alone for absence, or u8(1)||Ref for presence. Other tags and
inactive bytes reject. The complete evidence package is

    Evidence = ASCII("stele/v0.1/passport/evidence") || subject_id[32]
       || OptRef(proximity_certificate) || Ref(checkpoint_binding_proof)
       || Ref(fidelity_report),
    evidence_id = H(Evidence).

Only the proximity certificate has a presence choice. Its absence is forbidden
by actual treaty admission; presence alone never proves proximity or privacy.
Checkpoint binding and fidelity remain mandatory in both profiles. Each artifact
must bind the same subject under its complete child contract. Referencing a
report cannot establish named-model fidelity, and referencing a proof cannot
establish source/hash binding or profile/security admission.

Registration binds an externally expected registrant identity and key set:

    Registration = ASCII("stele/v0.1/passport/registration")
       || subject_id[32] || evidence_id[32] || registrant_id[32]
       || u64(timestamp) || OptRef(prior_registry_record)
       || u16(key_count) || Ref(key_descriptor)[key_count].

timestamp is unsigned POSIX seconds. key_count lies in 1..65535. Key descriptors
are sorted strictly by their H(descriptor) bytes; duplicate digests reject.
The descriptor's digest is its key_id. Each complete descriptor must specify its
approved signature suite, public key, parameters and authority mapping under a
closed accepted registration contract. No suite, arbitrary key or authorization
policy is supplied by this outer frame. The verifier independently checks the
expected registrant/key set, suite, signatures, authority and timestamp policy.
This study does not choose or implement those missing registration contracts.

A prior_registry_record can identify only an already fixed record independent
of this passport's final root. A later transaction publishing passport_root is
an external anchoring receipt. It cannot be inserted into the passport whose
root that transaction contains. Such receipts retain their separate authority
and chaining checks; they do not mutate an issued passport.

## 3. Signing and final root

Set registration_id=H(Registration). Every listed key signs the exact message

    ASCII("stele/v0.1/passport/sign") || subject_id[32]
       || evidence_id[32] || registration_id[32].

The message includes the complete key roster through Registration. It includes
no signature bytes or final passport_root. Verification uses every listed key
and its approved complete descriptor; an independently expected authority policy
still determines whether that roster is permitted. The outer codec performs no
signature or authority verification and must not expose an admission handle.

    Signatures = u16(key_count)
       || (key_id[32] || Ref(signature_bytes)) for each registered key,
    Passport = ASCII("stele/v0.1/passport")
       || B(Subject) || B(Evidence) || B(Registration) || B(Signatures),
    passport_root = H(Passport).

Signature order and count equal Registration exactly. Every signature artifact
is nonempty and must verify over the same message; unknown/extra/missing signers
reject. Changing a signature changes passport_root without changing the message
it signs. Changing Subject, Evidence or Registration changes the signing message
and final root. Thus construction is acyclic: subject, evidence, registration,
signatures, final passport. No child may refer to its own or a later identity.

The [public-input envelope](full-model-public-input.md) binds this final root.
Checking it requires the complete expected passport, referenced data and actual
child verification. A matching caller-supplied root, self-signed key, successful
parse or reference comparison establishes no inference or registration authority.

## 4. Bounds, validation and evidence scope

The outer frame has an 8 MiB cap. It contains metadata references only, with
no attachment payloads. Subject is 572 bytes; Evidence is 141+40c bytes and
Registration is 139+40t+40k bytes, where c/t are the two presence bits and k is
key_count. Signatures is 2+72k bytes. The complete frame is 889+40(c+t)+112k
bytes, at most 7340889 bytes. The signing message is exactly 120 bytes.
Its exact length derives from the fixed subject roles,
two optional references and the bounded key/signature count; the child sections
must exhaust their exact lengths. Check all counts, tags and remaining byte
counts before materializing entries. Ref lengths never allocate child buffers;
each actual child validator enforces its independently derived domain/resource
limits. Native fallible streaming/allocation remains required.

The numerical/source composition helper regenerates SourceConfig, conversion,
stored Artifact, complete numerical identity and the first eight subject
references from the same original files and Model. It accepts only reference
metadata for the remaining three roles and grants no plan/weight/table admission.
Outer framing tests likewise use evidence/key/signature references, without
claiming certificate, fidelity, signature, private PCS/ZK or native verification.

Every actual consumer must reject single-value changes to source/artifact,
numeric/configuration, plan/commitment/table, evidence subject, registrant/key,
message, signature or final-root bindings. NC-0700..0703 and all original
source/PCS/wrapper controls remain mandatory; research tests earn no NC credit.
Complete typed child contracts and actual authentication remain prerequisites
of native passport admission at the owners in RFC-0025 §7.1.
Q12/Q29, private tokens/weights, named GPT-2/Llama/W8 and profile goals remain.

This adds explicit deterministic hash preimages, without a Fiat-Shamir challenge,
extra intermediate commitment or online weight pass. All reference/subject/
evidence/registration/final-root and signature-suite hash uses must enter the
complete H/query and registration accounting before native admission. Honest
metadata hash counts do not establish an adversarial or quantum security bound.
Preparation, byte hashing, signature and evidence verification contribute
T_misc and registration work; no measured constant changes.
