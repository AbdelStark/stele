# RFC-0025 canonical public input

Status: Draft. Part of [RFC-0025](RFC-0025-full-model-cqis.md), Q26/E5-03b.
This specifies the complete public-input envelope and its required joins.
It does not supply the complete passport, proof-plan, private commitment or
ledger codecs, or admit any profile. Those require their own complete Accepted
consumer contracts and native validation before proof construction/admission;
RFC-0025 §7.1 fixes the numerical-specification and native-delivery boundary.

## 1. Independently expected statement

The verifier receives an externally expected statement. A proof may repeat it
but cannot select its passport, policy, profile, I/O authority or plan. The
authenticated passport supplies complete Model/Scales/Registry/Bounds and the
remaining source, commitment, certificate, fidelity and registration records.
Validate those records under their governing contracts and rederive cqis_id.
Checking equality to a caller-supplied digest alone does not authenticate them.

Use the exact [request and TokenIO contract](full-model-request.md). In addition
to q and maximum_new=a from RequestBoundary, expose generated length g and stop
reason as public metadata. Require 0<=g<=a, reason in {0,1}, g=a when reason=0,
and g>0 when reason=1. Actual token membership still determines whether this
reason is true. The full proof establishes every required stop/source relation;
these structural conditions cannot do so without the tokens or their proof.

The actual causal length is N=q+g, including a final EOS; 1<=N<=n. Its padded
position count is 2^ceil(log2 N). Decode rows have previous positions q-1 through
N-2 and selected-token positions q through N-1. At g=0 there are no decode rows,
but all prompt rows are evaluated and sampled seed binding remains mandatory.
Context n remains the static bound capacity; N never tightens a bound certificate.

This makes actual sequence length and stop reason explicit public outputs.
It adds no token values to the public input. Length-hiding is separate RFC-0017
work and cannot silently replace these fields or request-dependent selectors.
Neither token mode asserts text encoding or traffic provenance.

## 2. Exact frame

Use unsigned fixed-width little-endian integers and B(x)=u32(len(x))||x, with
byte lengths and no alignment padding. H is ordinary unkeyed BLAKE3-256.

    PublicInput = ASCII("stele/v0.1/public-input") || u8(profile)
       || cqis_id[32] || passport_root[32] || plan_id[32] || ledger_id[32]
       || u32(g) || u8(reason) || B(policy) || u8(io_mode) || IOPayload

profile is exactly 0:standard or 1:treaty. A tag does not establish security
admission. The expected profile and complete recomputed budget must pass before
transcript construction; no unknown tag, fallback or downgrade is defined.
The plan selects its permitted challenge field under the governing profile
contract. This frame neither selects a new field policy nor resolves Q12/Q29.

cqis_id is the [complete numerical identity](full-model-encoding.md#6-registry-and-numerical-identity).
passport_root binds the complete canonical passport, including its model-wide
canonical plan template. plan_id is H of the complete canonical plan instance
derived from that template, Model, this RequestBoundary, g, reason, I/O mode and
approved profile configuration. The passport's template digest is distinct from
this request-specific instance digest; a request does not issue a new passport.
ledger_id is H of the instance's
complete canonical recomputed ledger. Neither digest authorizes an opaque plan
or an unvalidated ledger. Their complete codecs and consumer schedules remain
mandatory. The plan does not contain its own hash, passport_root, I/O roots or
ledger_id; the ledger must not contain its own digest or the final PublicInput.
This avoids a content-identity cycle. Source roles/layouts are plan data; their
actual roots are checked against the passport and public I/O references.

policy is exactly B(Decoding)||B(RequestBoundary) from the independently checked
Model and request. It is stored in full, including every EOS id and the sampled
seed commitment. No supplied policy hash or alternate decoding copy is accepted.

For io_mode=0, IOPayload is exactly io_digest[32]. It equals H(TokenIO), whose
q,g,reason and original token values must match this statement and every
embedding/decoding/prompt consumer. TokenIO may remain a private preimage.

For io_mode=1, IOPayload is exactly

    u64(input_tree_id) || input_root[32]
       || u64(output_tree_id) || output_root[32].

These reference two distinct plan-owned token sources: the q original prompt
tokens and the g generated tokens, respectively. The full inference sequence is
their ordered concatenation. They are references, not a new commitment scheme.
The complete plan fixes each source's logical length, token-byte/field mapping,
layout, code, Merkle context, padding, private opening and mask lifecycle. Those
schemas must be complete and admitted before this mode can verify a proof.
Do not infer them from roots or the integer tree ids. Tree ids must be distinct
from each other and all other plan roles; complete context equality is required.
For g=0 the plan must still define its canonical empty-output source and proof
relation. Omitting the output reference or treating an all-zero root as absent
is forbidden; no empty-source construction is chosen by this envelope.

All four identity digests and all I/O roots are exactly 32 bytes. All-zero bytes
are ordinary values, never optional-field sentinels. There are no unused I/O
bytes, other modes, extensions, aliases, optional suffixes or session-id defaults.
RFC-0011 traffic interfaces and E13-05 chaining must bind this same statement
under their separate complete contracts.

## 3. Parsing and geometry

Derive the expected policy bytes and length from Model/RequestBoundary before
reading its supplied u32 length. The header through that length is 161 bytes.
Total lengths are 194+len(policy) for digest mode and 242+len(policy) for
commitment mode. The closed Decoding frame is at most 345 bytes using Model's
128/192-byte Function/Representation caps. RequestBoundary is at most 4194381
bytes; policy is therefore at most 4194734 bytes and PublicInput at most
4194976 bytes. An 8 MiB envelope cap covers the complete domain.

Check byte type/capacity, fixed prefix/header, the independently derived policy
length and exact policy bytes before accessing IOPayload. Then check its tag,
exact remaining size, profile/count/reason domains and all root/reference fields.
Reject booleans as integer host parameters, unknown tags, duplicate tree ids,
truncation and suffixes. Supplied lengths never select allocation or source
geometry. Checked native arithmetic and fallible allocation remain required.
Decoding and re-encoding recover the original bytes exactly.

## 4. Admission and consumers

Before constructing a transcript, the real verifier must:

1. Match the externally expected complete statement, including profile and I/O
   authority. Structurally valid alternate statements still reject.
2. Validate the complete passport and original source/registration authority;
   rederive the same numerical identity from complete Model/Scales/Registry/Bounds.
3. Derive the complete request-specific plan and ledger, check both identities,
   all private source/layout/certificate joins and the selected profile budget.
4. Use that same plan, public input and owned sources throughout the actual
   reductions. Bind public g/reason to original TokenIO or committed token sources,
   including all stop-membership checks and complete final-token evaluation.
5. Pass these exact full bytes once to RFC-0012 A1's existing public-input
   constructor absorb. No field is reserialized or omitted by a backend.

The research codec tests framing, structural geometry, numerical identity and
plaintext digest preimages. It returns no authenticated passport, source handle,
profile admission or inference-verification result. Committed-mode fixtures are
reference bytes only, without any private commitment/opening/proof evidence.

No challenge, new hash function, extra transcript absorb, intermediate cut or
online weight pass is introduced. Existing plan/ledger/TokenIO/numerical identity
hash uses require their complete H/query accounting at their actual consumers;
this envelope supplies no budget credit. Parsing/hashing contributes T_misc,
and source/proof checks retain T_witness/c_a/c_lu/PCS costs. No measured constant
changes. Controls must cover every identity/profile/policy/geometry/I/O field at
the real E6/E8/E12-05/E14 consumers, alongside NC-0001/0004/0005/0107/0108,
NC-0700..0703, NC-0804/0805 and NC-1201/1203. Research mutations earn no NC credit.

The [passport composition appendix](full-model-passport-composition.md) defines
the referenced final passport_root and separates it from the earlier subject_id
used by its evidence and signing message. The public input always carries the
final root; a subject or signing preimage hash cannot substitute for it.
