# RFC-0012 — Transcript, Fiat–Shamir, soundness accounting

Status: Accepted · Version: 0.1.0

## 1. Transcript
Duplex sponge over Blake3 (`stele-hash::Transcript`): state = 32-byte chaining value; `absorb(label, bytes)` hashes
`(state ∥ label_len ∥ label ∥ len ∥ bytes)`; `challenge(label) → K` draws 16 bytes, rejection-samples each M31 limb
into `[0,p)`. Labels are ASCII constants registered in `labels.rs` (unique, versioned). Order of absorption is the
proof order (RFC-0016 §2). The first absorb is `("stele/v0.1/public", π)` with the full public input `π` (RFC-0001 §3)
including `cqis_id`, `passport_root`, `profile`, and the accounting hash (§5).

## 2. Rules
- Every prover message (round polynomial, claimed value, commitment root, opened leaf) is absorbed before any challenge that may depend on it.
- Claimed final values of sumchecks are absorbed explicitly (weak-FS guard).
- Column indices for PCS openings are drawn *after* `u` (or its commitment) is absorbed.
- Per-instance challenges are never shared across independent instances except through explicit batching (γ drawn from the transcript).
- Grinding: optional proof-of-work nonce absorbed before the PCS query challenges; counted in the ledger.

## 3. Hash choices
Blake3-256 for transcript and Merkle; leaves prefixed `0x00`, internal nodes `0x01`, roots-of-roots `0x02`. Poseidon2-M31
appears only in the recursion wrapper's own transcript. Treaty: 256-bit everywhere; standard may truncate Merkle to 192 bits.

## 4. Error ledger (generated per proof config by `stele-verifier::accounting`)
| Line | Term | Formula |
|---|---|---|
| SC | each sumcheck instance | `m·δ/|K|` |
| RLC | each batching of `t` claims | `t/|K|` |
| LU | each LogUp instance | `(N+|T|)/|K|` (standard) or squared (treaty) |
| PCS | each opening | `ε_gap + (1−δ)^q + ε_Merkle` (RFC-0010 §6) |
| MASK | ZK masks (RFC-0013) | `≤ 1/|K|` per masked instance |
| FS | Fiat–Shamir | `(Q_hash + grind) · ε_round-max` style bound in ROM with `Q ≤ 2^{80|100}` |
| H | collisions | `Q²/2²⁵⁶` |
Total = sum; the verifier rejects any proof whose config yields total above the profile bound (RFC-0002 §8).

## 5. Illustrative budget (405B, n = 4608, treaty)
Sumcheck rounds ≈ 10⁵ instances × ≤ 40 rounds × δ ≤ 4 ⇒ 1.6·10⁷/2¹²⁴ ≈ 2⁻¹⁰⁰ ✗ — **too large for 2⁻¹²⁸**. Mitigation:
(a) batch instances so the count is ≈ 10² stacked instances (the design does this: all per-layer instances are stacked),
giving ≈ 10²·40·4/2¹²⁴ ≈ 2⁻¹¹⁰; (b) treaty profile draws each sumcheck challenge from `OM31` (2²⁴⁸) — the prover's cost
difference is small because round polynomials are few — or doubles the sumcheck (R-OCTIC). Lookups: `N ≈ 2³⁷ ⇒ 2⁻⁸⁷`
single, `2⁻¹⁷⁴` double. PCS: proven gaps with `q` ≈ 300 (rate 1/4). The ledger must show ≤ 2⁻¹²⁸ or the config is invalid.
**Decision D10:** treaty profile uses `OM31` challenges for *all* sumchecks (round polynomials in OM31, witness folds in
QM31 are *not* allowed — folds must be in the challenge field), accepting ≈ 2× extension cost on the K-arithmetic share
(≈ 30% of prover time) — or the alternative of splitting each phase into two independent transcripts; to be fixed by bench (task E12-03).

## 6. Negative controls
NC-0800 challenge drawn before a message is absorbed; NC-0801 label collision; NC-0802 final value not absorbed;
NC-0803 query indices from stale state; NC-0804 ledger total tampered; NC-0805 profile downgrade in public input.

## 7. Amendment log

### A1 — Canonical transcript bytes and unbiased extension challenges

Status: Accepted. Research question Q11. Review: [A1 skill passes](../../agents/reviews/transcript-a1.md). Byte oracle and checks:
[transcript study](../../research/transcript/REPORT.md).

Motivation: §1 does not specify length widths, initial state, squeeze domain,
rejection handling, state updates after challenges, or OM31's eight limbs. Two
implementations can follow the sketch and disagree. This amendment resolves that
byte-contract blocker; implementation and protocol controls remain incomplete.

Exact replacement for §1:

> The transcript is a domain-separated Blake3 hash chain with extendable-output
> challenge requests, not an invocation of an unspecified sponge API. Let H(x)
> be the first 32 bytes of ordinary, unkeyed BLAKE3 output and XOF(x) its ordinary
> extendable output. Keyed mode and derive-key mode are not used. Before the first
> public-input absorb, S = H(ASCII("stele/v0.1/transcript/init")). Define
>
> `frame(S, tag, label, payload) = S || u8(tag) || u32le(len(label)) || label || u64le(len(payload)) || payload`.
>
> S is exactly 32 bytes. Lengths count bytes, are unsigned fixed-width
> little-endian integers, and must fit without truncation. Labels are registered
> ASCII byte strings of length 1..255. Tags are 0 = absorb, 1 = challenge request,
> 2 = challenge state update. No alignment padding, terminator or implicit
> text encoding is present. Frame concatenation is unambiguous because every
> variable-size field has its own length and state/tag widths are fixed.
>
> Construction performs exactly one tag-0 absorb of the nonempty canonical
> public-input encoding under `stele/v0.1/public`. Its complete semantic encoding
> is governed by RFC-0001/RFC-0016; accepting arbitrary bytes in the primitive
> does not verify that encoding. The proof verifier must derive/check the public
> input and profile before constructing its transcript. The public-input label
> cannot be used again through the public absorb API. Every subsequent absorb
> sets S = H(frame(S, 0, label, bytes)) with a registered absorb label.
>
> A transcript has one fixed extension degree d, either 4 for QM31 or 8 for
> OM31, selected by the caller from the verified profile. Arbitrary Field
> implementations are not challenge targets. Each challenge request uses a
> registered challenge label. Let X = the first 256 bytes of
> XOF(frame(S, 1, label, u8(d))). Read X in consecutive four-byte little-endian
> words w, replacing each by c = w AND 0x7fffffff. Reject c = p = 2^31-1;
> accept c < p as the next coefficient. Stop after d accepted coefficients.
> Encode them as canonical u32le limbs in the RFC-0003 A1 basis order.
>
> At most 64 candidate words may be examined per request. If fewer than d
> coefficients are accepted, return SamplingExhausted, leave S unchanged and
> abort the proof attempt. Do not reduce p to zero, reuse coefficients, switch
> field, accept a short result, or retry with another domain or seed. If n words
> were consumed successfully and C is the canonical challenge encoding, set
> S = H(frame(S, 2, label, u8(d) || u32le(n) || C)) before returning C. Consecutive
> challenges therefore use different state even when their labels repeat.
> Input-validation errors also leave S unchanged and return no challenge.
>
> Production transcript construction cannot import an arbitrary state or an
> external byte generator. Forced-rejection vectors exercise the pure coefficient
> decoder in tests; there is no injected-randomness or check-disabling API.
> Neither the primitive nor a transcript digest proves that a protocol followed
> its required message schedule. Each prover/verifier must follow the same
> Accepted schedule, with each required message absorbed before its challenge.

Addition to §2 (initial registry and owners):

| Kind | Label bytes | Consumer / accounting |
|---|---|---|
| Constructor absorb | `stele/v0.1/public` | full public input; no random challenge |
| Absorb | `stele/v0.1/sumcheck/instance` | instance description supplied by sumcheck; no random challenge |
| Absorb | `stele/v0.1/sumcheck/round` | round polynomial; no random challenge |
| Absorb | `stele/v0.1/sumcheck/final` | final claims; no random challenge |
| Challenge | `stele/v0.1/sumcheck/challenge` | one round challenge; SC, plus existing FS/H |

Labels must be unique across both kinds and exposed as closed typed choices, not
arbitrary caller strings. Repeated calls using one registered label are allowed;
that is distinct from registering two meanings with the same bytes. Protocol
owners must specify canonical message encoding and instance context before using
these labels. Future labels require an RFC-governed schedule, a registry entry,
and an accounting mapping; a free-form label escape hatch is forbidden.
The primitive supports both fields; this amendment does not decide R-OCTIC's
profile comparison, remove profile checks, or authorize QM31 in a treaty stage
whose Accepted schedule requires OM31.

Soundness: under ideal independent XOF words, masking gives exactly two u32
preimages per 31-bit candidate. Conditional on acceptance, every M31 coefficient
has probability 1/p. Rejection decisions depend only on whether a word is in the
two rejected preimages, so conditioning on obtaining d limbs within 64 words
preserves independence and uniformity of the accepted vector. No statistical
sampling loss is added to SC/RLC/LU/MASK; use exact field sizes p^4 or p^8.
This is an elementary counting argument, checked exhaustively for reduced-width
analogues and boundary vectors; an empirical histogram is not its proof.

Exhaustion for d <= 8 requires at least 57 rejected words among 64. A union bound
over subsets gives probability at most 2^64 * (2^-31)^57 = 2^-1703 in the ideal
model. This is completeness/availability loss, not probability of accepting a
false statement. Abort is mandatory even on that event. No new soundness error
line or discount for failed attempts is introduced. FS/H must count all adversary
queries and grinding, including failed attempts, initialization, absorbs,
challenge XOF evaluations and state updates under their respective oracle model.

Cryptographic status: these byte rules and the counting lemma do not prove the
Fiat-Shamir transformation of Stele's IOP. BLAKE3 is specified by the
[official specification](https://github.com/BLAKE3-team/BLAKE3-specs).
RFC-0002 assumptions A1/A2 remain assumptions, not proven hash properties. The
existing FS formula is still a placeholder needing a concrete theorem and query
convention before any profile can be certified. Q12 tracks that obligation,
including reconciliation of the stated Q caps with the H budget. No treaty or
standard soundness-budget claim follows from this amendment.

Costs: initialization adds one fixed hash, each absorb hashes the framed payload,
and each challenge computes a request XOF and one fixed-size state-update hash,
examining at most 64 words. Storage is constant apart from the caller's message.
This contributes to T_misc; no measured constant or cost-model fit changes.
Prover and verifier use identical byte rules and coefficient decoding.

Controls and task dependency: retain E2-01's complete NC-0800..0802 acceptance.
Primitive tests must check byte framing, registry uniqueness, forced rejection,
field/basis selection, state updates, and sensitivity to reordered/omitted
messages. Such tests alone earn no protocol NC catalog credit. NC-0800/0802 must
exercise real prover/verifier schedules, including a downstream challenge after
final claims. NC-0801 is a configuration-validation control: accept the honest registry,
replace exactly one registered label with another, and require DuplicateLabel
from the actual core registry validator. It is not a proof-witness control and
cannot be represented by a toy proof verifier. Workflow 08 records this narrow
exception. The same validation must guard the production registry; a test-only
validator or a bypass in transcript construction is forbidden.

The accepted DAG adds E2-00 for the primitive, KATs, registry/sampling checks,
NC-0801 configuration validation and actual primitive/accounting gate wiring. E3-01 depends on E2-00 instead of E2-01.
E2-01 retains every original acceptance criterion and additionally depends on
E2-00 and E3-01, so real protocol controls can exist before it is completed. The
remaining gates must continue rejecting unvalidated changes to other protocol
crates; changing a scaffold hash to bless implementation is not gate wiring.
This refines the DAG without deleting or crediting any security obligation.
Affected tasks: E2-00 (new), E2-01, E3-01, E8-04, E8-05 and E12-09.

Completed same-author skill reviews (not independent audit): soundness-auditor,
rfc-author, pcs-engineer (stele-hash owner), sumcheck-prover-engineer (schedule
consumer), recorded in the linked review.

### A2 — Fixed wrapper Poseidon2-M31 permutation

Status: Accepted. Questions Q13/Q14. Review: [skill passes](../../agents/reviews/poseidon2-a2.md). Evidence: [parameter study](../../research/poseidon2/REPORT.md).

Motivation: §3 does not identify the permutation required by E2-03. Width, rounds,
linear layers and constants must be fixed before interoperable code can exist.
This amendment supplies that primitive contract. It does not define a hash mode.

Addition to §3:

> E2-03 implements the fixed permutation `poseidon2_m31_16` over sixteen canonical
> M31 elements. It is available only with the `wrapper` feature, has no custom
> constants or round-count API, and is not used by native transcripts or Merkle
> commitments. The reference is Plonky3 `p3-mersenne-31=0.8.0`, published from
> commit `a21e3ed42905040ad49c519e402f018381c12d0c`, function
> `default_mersenne31_poseidon2_16`. The exact 142 constants are the `initial`,
> `internal`, and `final` arrays in the first record of the committed
> [reference vectors](../../research/poseidon2/reference.jsonl). These integers,
> not a dependency's changing defaults or an unspecified random seed, are normative.
>
> All operations are in F_p, p = 2^31-1; state positions are numbered 0..15.
> Apply the external linear layer once before the rounds. Then apply four full
> rounds, fourteen partial rounds, and four full rounds. A full round first adds
> its sixteen constants, raises every element to the fifth power, then applies
> the external linear layer. A partial round adds its constant only to position
> 0, raises only that position to the fifth power, then applies the internal layer.
>
> External layer: split the state into four consecutive length-four column vectors.
> Multiply each by M4 = [[2,3,1,1], [1,2,3,1], [1,1,2,3], [3,1,1,2]]. For each
> position j within a block, add the sum of position j across all four transformed
> blocks to that position in every block. Sums use the transformed values before
> any of these final additions.
>
> Internal layer: for the state after its S-box, compute s = sum(x_i); output
> y_i = s + d_i*x_i, where d = [-2,1,2,4,8,16,32,64,128,256,1024,4096,8192,
> 16384,32768,65536]. Both the sum and each product use the original layer input.
>
> The API operates on field arrays, without byte reduction, padding, squeezing,
> challenge sampling, or a claimed digest size. Canonical fixture bytes use
> RFC-0003's u32 little-endian element encoding in state order. E14-01 must first
> resolve Q14 with an Accepted wrapper mode and separate accounting before using
> this permutation for any hash, commitment or transcript. Native verification
> continues to use BLAKE3 under A1. Completing E2-03 does not complete E14-01.

Soundness: no new random challenge, claim edge or ledger term is introduced by
an unused permutation primitive. The fifth power and both linear layers are
invertible over M31, checked by exact arithmetic; invertibility is not collision
resistance. The [Poseidon2 paper](https://eprint.iacr.org/2023/323) and the pinned
upstream parameters are cryptographic design evidence, not an unconditional
security theorem. No standard/treaty bound is certified here. Q12 and Q14 remain
open; in particular, a string of eight M31 elements has fewer than 248 bits of
range, so calling its encoding 256 bits does not yield a 128-bit birthday bound.

Costs: eight full rounds each use sixteen fifth powers and an external layer;
fourteen partial rounds each use one fifth power and an internal layer; one
initial external layer. Thus 142 fifth powers, nine external and fourteen internal
layers per permutation. This contributes to wrapper T_misc when consumed; no
native term, weight-pass count, measured constant or benchmark result changes.

Validation: E2-03 retains KATs versus an executed reference and adds exact fixture
parity with the integer oracle, canonical boundary inputs, and disabled-by-default
wrapper API coverage. Research mutation checks receive no protocol control id.
NC-1203 and all E14-01 obligations remain incomplete. No catalog status changes.
Affected tasks: E2-03, E14-01; no dependency or original acceptance is removed.

### A3 — Canonical byte-column Merkle trees and roots of roots

Status: Accepted. Question Q16. Review: [skill passes](../../agents/reviews/merkle-a3.md). Candidate checks: [Merkle study](../../research/merkle/REPORT.md).

Motivation: §3 fixes hash domains but not leaf bytes, shape, padding, index binding
or batch verification. E2-02 cannot choose those silently. This amendment defines
an authentication primitive; it does not implement a PCS or select its queries.

Exact replacement for the Merkle part of §3 (the transcript and wrapper rules
remain in force). In particular, 0x02 tags child-root leaves; the explicit rules
below govern every internal node, including a root-of-roots tree root:

> **Statement and context.** A tree authenticates an ordered list of fixed-width
> byte payloads. Its verifier-owned descriptor is `(kind, id, n, w)`: kind 0 for
> byte columns, kind 2 for roots of roots; unsigned tree id `id < 2^64`; real leaf
> count `1 <= n <= 2^63`; payload width `1 <= w < 2^64` bytes. Kind 2 requires
> w = 32 and each payload is one child root, ordered by the plan's shard index.
> Other kinds, empty trees and zero-width payloads are invalid. The verifier
> derives/checks the descriptor, expected root and requested indices from its
> authenticated plan/commitments, never from unauthenticated opening metadata.
> Tree ids distinguish roles within that plan. The descriptor is not a complete
> plan encoding and does not validate a passport, profile, code or field format.
>
> Byte columns contain exactly one column in row order. PCS consumers must encode
> and validate their field elements canonically under RFC-0003 and enforce their
> own row count, packing and code parameters. The hash primitive treats payloads
> as bytes, not field values. A short column changes w, not the authentication rule.
> DPA/mixed-field encoding and recursion consumers require their own contracts.
>
> **Hash inputs.** Let H be ordinary unkeyed BLAKE3's first 32 output bytes. All
> roots and siblings are exactly 32 bytes, in both profiles; optional standard
> truncation is not implemented by this contract. Define the fixed-length header
> `D = ASCII("stele/v0.1/merkle") || u8(kind) || u64le(id) || u64le(n) || u64le(w)`.
> Let h = ceil(log2(n)), including h = 0 for n = 1, and P = 2^h. Positions are
> zero-based, left to right. Level 0 contains P leaves; level h contains the root.
> The leaf digest at position i < P is
> `H(u8(kind) || D || u64le(i) || u8(present) || payload)`.
> For i < n, present = 1 and payload has exactly w bytes. For n <= i < P,
> present = 0 and payload is empty. These are tree padding, not additional tensor
> rows or zero-valued real leaves; they cannot be requested as openings.
> The digest of internal node j at level l, 1 <= l <= h, is
> `H(0x01 || D || u32le(l) || u64le(j) || left_digest || right_digest)`.
> No terminators, alignment, implicit padding, field reduction, keyed hashing,
> variable digest lengths or alternate empty-tree rule are permitted. For n = 1
> the leaf digest itself is the root. Kind-2 trees use the same construction;
> their child roots are hashed as 0x02 leaves, never inserted as untyped nodes.
> The root binds this ordered logical partition; it is not invariant under changing
> its descriptor/list and need not equal a flat-tree root. Q17 must resolve E4-07
> shard/digest semantics before distributed implementation.
>
> **Opening and verification.** An opening consists of the w-byte payload and
> exactly h sibling digests in bottom-up order. Its index is a separate
> verifier-owned argument. Reject i >= n, wrong payload length, wrong path
> length or any non-32-byte digest before authentication. Starting from the real
> leaf digest at i, at step d = 0..h-1 let k = i >> d. If k is even, the current
> value is the left child; otherwise it is the right child. Hash the ordered
> children at level d+1, position k >> 1. Accept only equality with the expected
> root after all h steps; root mismatch is RootMismatch, never a partial success.
> No supplied direction bits, ignored trailing siblings or unchecked path suffixes.
> Implementations check all size/index arithmetic and conversions without truncation.
>
> Batched verification receives one descriptor/root, a nonempty strictly
> increasing list of distinct requested real indices, and exactly one opening
> per index in that order. Reject a count mismatch, duplicate or unsorted request,
> invalid index, malformed opening or any failed authentication. Acceptance is
> atomic: all requested openings pass. The baseline sends full paths; no shared
> sibling compression or implicit duplicate elimination is specified. This API
> does not sample indices, prove they came from a transcript, or choose a PCS
> query count. A consumer must specify that schedule before use (NC-0601/0803).
> A root-of-roots opening authenticates a child root only; its column opening
> must separately verify against that exact child root and the child's descriptor.
> Membership alone does not establish encoding/proximity, canonical contents of
> unopened subtrees, shard ownership, field faithfulness, inference or privacy.
>
> **Prover/verifier costs.** Honest construction hashes n*w payload bytes, P leaf
> frames (including P-n empty padding payloads), and P-1 fixed-size internal
> frames. A baseline stored tree needs 32*(2*P-1) digest bytes, plus caller-owned
> payloads. An opening carries w+32*h bytes. A q-opening batch uses q leaf hashes
> and q*h internal hashes and carries q*(w+32*h) bytes, excluding outer framing.
> Root-of-roots substitutes w = 32. These hashes contribute to commitment c_c
> (T_cuts; passport weight encoding is one-time), and authentication to verifier
> work/T_misc as applicable. No weight-pass count, measured constant or fit moves.
>
> **Soundness.** Under collision resistance of H, two different accepted payloads
> at the same descriptor/index/root imply a collision: compare their paths from
> the equal root down to the first different child input, or to different leaf
> frames if all siblings agree. Fixed widths, role tags, indices and descriptor
> bytes make those distinct input strings. This is an elementary binding reduction,
> not a theorem that BLAKE3 is collision resistant. Unqueried leaves/codewords are
> not certified by an inclusion proof. Ordinary leaf/internal domain separation
> follows the established rationale in RFC 9162 §2.1.1, but Stele's headers,
> padding and root-of-roots bytes are defined here; it is not that RFC's tree format.
> There is no challenge or algebraic loss. Existing PCS ε_Merkle/H must account
> for all relevant hash queries without treating repeated use as free or silently
> double-counting the same event. No concrete profile budget follows: Q12 still
> blocks certification, and 256-bit outputs alone do not settle its query model.
> No conjectural coding gap or PCS proximity claim is introduced for either profile.

Controls and acceptance: retain NC-0602, exercised against actual construction
and authentication for both kinds: after an honest baseline, replace exactly one
payload byte or one sibling digest and require RootMismatch. Include a wrong-leaf
variant, index/descriptor sensitivity, equal payloads at distinct positions,
singleton trees, non-power-of-two counts, padding rejection, exact path lengths,
and batch completeness/order tests. Research checks earn no catalog credit.
E2-02 remains incomplete until production implementation, both-kind NC-0602,
byte-vector parity and actual Merkle gate wiring pass. PCS consumers retain
NC-0600/0601/0603..0605 and distributed consumers retain their own obligations.

Affected tasks: E2-02, E4-03, E4-07, E8-04/E8-05 and the E10 GPU commitment work.
No original acceptance criterion is removed. Q16 resolves only this byte contract;
Q12, query sampling, field/code validation and distributed scheduling remain open
in their owning tasks. No change to RFC-0010's algebraic opening relation.

Completed same-author skill passes (not independent audit): soundness-auditor,
rfc-author, pcs-engineer (stele-hash owner), distributed-systems-engineer.

### A4 — Batching labels and per-invocation RLC records

Status: Accepted. Question Q18. Review: [skill passes](../../agents/reviews/batching-a2.md).
Motivation: bind the RFC-0006 A2 ordered batch before its coefficient and all
final values before continuation. Add these closed labels to A1's registry:

| Kind | Label bytes | Consumer / accounting |
|---|---|---|
| Absorb | `stele/v0.1/sumcheck/batch` | Batch; complete A2 descriptor, no challenge |
| Absorb | `stele/v0.1/sumcheck/batch-final` | BatchFinal; complete A2 final values, no challenge |
| Challenge | `stele/v0.1/sumcheck/batch-coefficient` | BatchCoefficient; one per A2 batch, RLC |

A1 framing, field selection, rejection sampling and state updates are unchanged.
RFC-0006 A2 supplies exact messages, order, algebraic proof, costs and controls
NC-0202/0206 plus extensions of NC-0205/0802. Its single RLC record has numerator
t; shared rounds supply one SC record with numerator M D, both over p^d. FS/H
remain separate, Q12 open. No label-registration escape hatch, new loss family,
measured constant or weight pass is introduced. E3-02 must implement the registry,
canonical inventory and record/consumer gates atomically; this specification
alone adds no production challenge or coverage. Other consumers keep A1 bytes.

### A5 — Zerocheck weights, skip and final framing

Status: Accepted. Question Q19. Review: [skill passes](../../agents/reviews/zerocheck-a3.md).
Motivation: RFC-0006 A3 changes the relation and
schedule; bind its descriptor, skip polynomial and all original slice claims.
Add these closed labels to A1's registry when implementing the consumer:

| Kind | Label bytes | Consumer / accounting |
|---|---|---|
| Absorb | `stele/v0.1/sumcheck/zero` | Zero; full A3 descriptor |
| Challenge | `stele/v0.1/sumcheck/zero-weight` | ZeroWeight; j challenges, SC phase 0 |
| Absorb | `stele/v0.1/sumcheck/zero-skip` | ZeroSkip; A3 initial polynomial |
| Absorb | `stele/v0.1/sumcheck/zero-final` | ZeroFinal; all A3 slice finals |

Reuse Sumcheck after ZeroSkip (one challenge iff k>0, SC phase 1) and after each
Round (j challenges, SC phase 2). A3 fixes all bytes, ordering, bounds, errors,
costs and NC-0207..0209/0802 obligations. No sampling exclusions, retries or new
loss family are introduced. The three SC numerators are j, δ*(2^k-1), j*δ over
p^d. A1/A4 consumers and their bytes remain unchanged. The production registry,
canonical inventory and actual per-invocation accounting gate change atomically
with the consumer; this amendment alone supplies no production coverage.
No measured constant or weight pass moves. Q12 still blocks profile certification.

### A6 — Stacked statement descriptor

Status: Draft. Question Q20. Companion to RFC-0006 Draft A4.
Motivation: bind the complete verifier-owned stacked relation, consumed claim,
canonical layout/order and resolved coefficient source values before A1 rounds.
Candidate payload and exact schedule: [stacked statement](../../formal/stacked-statement.md).

Proposed registry addition on implementation after acceptance:

| Kind | Label bytes | Consumer / accounting |
|---|---|---|
| Absorb | `stele/v0.1/gkr/stacked` | Stack; full A4 statement, no challenge |

Stack precedes the derived A1 Instance. A1 Round, Sumcheck and Final operations
remain unchanged, with one SC record m*delta/p^d for the complete A*P polynomial.
No extra draw or algebraic loss is proposed; FS/H and Q12 remain separate.
Absorbing source bytes is not authentication against their original commitment,
public input or CQIS identity. Actual source resolution and original consumers
remain mandatory. No private-source, profile or coverage claim follows here.

Before acceptance, complete the source interface, error/control mapping and
required A4 reviews. On implementation, change the closed registry, canonical
inventory and actual accounting/control gates atomically. The current production
registry remains unchanged; this Draft alone grants no label or protocol access.
Cost impact: descriptor/source-byte absorption in T_misc, with no fitted constant
or weight-pass change. Affected tasks: E3-06 and its reduction consumers.


### A7 — Separate setup failure over the complete seed universe

Status: Draft. Questions Q23/Q12. Companion to RFC-0010 A1. Candidate contract and
self-contained conditional argument: [seeded setup](../../formal/seeded-setup.md).
Motivation: a uniformly sampled code theorem does not certify a chosen seed, and
a setup error cannot disappear into the PCS column-query term or hash loss.

Proposed addition to §4, pending the full admission and FS/H composition contract:

> Account separately for the event that an admitted code setup fails its required
> support/distance properties. Add that event's bound to the protocol error
> conditional on good setup; do not assume good setup from parser success or a
> `proven` flag. Its exact distribution, versions, lifetime/query policy, reuse
> and authoritative consumers must be fixed and checked. Missing evidence rejects
> admission rather than assigning a zero loss.
>
> V2 uses the exact manifest/map/block identities in the candidate contract and
> 416-bit finite event bounds. In the ideal random-oracle experiment the probability
> that any successfully regenerated supported code from any of the 2^256 seeds
> fails is at most 200431782/2^160 < 2^-132. This union bounds all seeds together:
> outside that event every seed is good, irrespective of classical or quantum
> selection, queries, outputs or reuse. Bounded-stream exhaustion rejects and is
> coupled to the uncapped ensemble without conditioning away failures.
>
> Reject v1, unknown identities, unsupported seed lengths and arbitrary raw maps.
> The bound has no caller-supplied query/attempt budget. The v1 classical-only
> expression is superseded; its quantum counterexample remains a regression check.
> Concrete BLAKE3 vectors do not prove the oracle assumption. Authenticate the
> actual regenerated source and fixed parameters before applying this setup bound.
>
> Compose with the actual protocol failure event outside bad setup under its
> applicable oracle model. Conditioning on good setup need not preserve fresh
> independent oracle outputs; a simple union decomposition does not supply the
> remaining FS/H proof. Q12's quantum FS/hash and budget obligations remain open.

Soundness impact: proposes a separate setup term, with no production ledger or
loss-family change until admission and composition are complete. No proof challenge,
transcript label or challenge derivation changes. Q12 still blocks certification.
The sampler is deterministic setup expansion, not a second Fiat-Shamir mechanism.

Cost impact: bounded setup hashing/preparation in T_misc/c_c, graph storage and
regeneration copies. Stronger v2 degrees increase exact edge work/storage (9728
versus 7424 edges at n=256); these are operation counts, not benchmarks. No measured coefficient or weight-pass count changes. Affected
tasks: E4-01/E4-03/E4-05, E8-05, E12-04/E12-09. A1 and A7 remain Draft; this
research does not enable a code registry, PCS parameter or treaty profile.

### A8 — Require the characteristic and pole hypotheses of LU accounting

Status: Draft. Question Q31; companion RFC-0008 A2.
Evidence: [LogUp algebra and counterexamples](../../formal/logup-characteristic.md).
Motivation: the N≈2^37 illustrative lookup exceeds char(M31); changing to QM31
or OM31 does not change that characteristic. An identically zero bad-instance
rational function has no small root-bound error to square.

Proposed replacement requirements for the LU row in §4 and its use in §5:

> Derive each LU record from the exact Accepted lookup mode and static public
> shape/selector bounds. Ordinary unit multiplicities require fewer selected
> positions than the characteristic. Missing count/unit, source binding, pole,
> compression or consumer hypotheses mean unsupported configuration, never a
> zero term or admission based on the field extension size alone.
> Include tuple compression, rational-identity, GKR and any batching/unit errors
> under their actual challenge schedule. Square only the independent repeated
> event justified by its theorem; shared or separately bounded errors retain
> separate accounting. Partitioned or weighted-unit modes need their complete
> exact formulas and registered challenges before use.

The bounded-count note gives a conditional power-compression identity bound
min(1,(N+c*|T|-1)/|K|). It is not a complete LU record or new production schema.
No challenge, label, verifier admission or ledger line changes in this Draft.
Q12 and all source/PCS/ZK composition obligations remain. Cost terms include
c_lu/T_misc, multiplicity/table work and memory, with no measured constant.
Affected tasks: E3-07, E8-05, E12-02/E12-03 and every lookup consumer.

A8 candidate continuation: [grouped-unit derivation](../../formal/weighted-logup.md)
proposes r*h additional unit challenges before r weighted multiplicity commitments,
then independent beta/alpha pairs. Its single rational-identity bound is
e=min(1,(h+N+c*|T|-1)/|K|). Under the exact fixed-source, joint-commitment and
independent-unit schedule it proves e^r for those identity events only. Sharing
units does not establish that bound; GKR/PCS/source/FS/privacy failures stay
separate. No production registry or ledger schema changes; complete framing,
sampler/domain composition and actual consumers remain prerequisites.

A8 fraction continuation: [candidate schedule](../../formal/fraction-reduction.md)
names gamma and tau once per tree layer and the A1 rounds they enclose. A depth-m
tree contributes [3m(m-1)/2+2m]/|K| conditional on its original leaf consumers;
the selected-product leaf adds 3m/|K|. Each tree/repetition has its own terms,
added separately from the repeated rational-identity bound. All children precede
tau, and the next layer's P/Q claims precede gamma. These are research-local
Transcript labels and conditional interactive losses, not production registry,
LU admission, private consumers or Q12 composition.

A8 consumer continuation: [complete event inventory](../../formal/lookup-consumers.md)
binds all r multiplicity roots before every beta/alpha, then consumes both trees
and all original claims. With table depth k, the conservative conditional bound
adds r*[F(m)+F(k)+3m]/|K| to e^r, F(n)=3n(n-1)/2+2n, plus actual binding/FS terms.
The study checks actual Transcript draw counts and ordering, not receipt fields
alone. Full revealing Merkle openings do not instantiate private PCS or ZK;
no production labels, ledger schema or profile admission change.

### A9 — Conditional fraction reduction labels and accounting

Status: Accepted. Companion RFC-0008 A3. Review: [skill passes](../../agents/reviews/fraction-a3.md).
Reserve stele/v0.1/lookup/fraction, /layer and /leaf as absorbs, and
stele/v0.1/lookup/gamma and /fold as RLC challenges. A1 framing, capped sampling
and ratcheting are unchanged. Gamma follows descriptor/root/current claims;
Fold follows complete A1 Final and exact Eq consumption. No unit, alpha, beta
or multiplicity label is admitted by A9; A8 remains Draft.
Per tree, Gamma and Fold each contribute m/|K|; scoped A1 SC contributes
3m(m-1)/2 over |K|. The selected-product leaf adds 3m/|K| via existing A1 draws.
Keep tree/phase/level identity even when local SC ids repeat. Native registration
and use must update inventory and actual producer/gate together; codecs alone
add no production label or loss. No complete LU record, profile, privacy, source
authentication or Q12 result follows. No measured constant changes.
Affected tasks: E3-07a, E3-07, E8-05.

### A10: Conditional field PCS schedule and column indices

Status: Draft. Companion RFC-0010 A9. The exact nine registry entries, kind
and PCS tensor/query ownership are specified in
[native-field-pcs.md §7](../../formal/native-field-pcs.md#7-exact-registry-additions).
The A1 hash-chain framing, canonical K sampling and state updates stay intact.

Proposed API addition: a checked column sampler on Transcript accepts only
the closed certificate/opening column kind and N=2^h, 1<=h<=30. Each outer
attempt draws a full K value with its registered label. Read the first
canonical limb x; accept x mod N only for x<floor(p/N)*N. Reject at most
64 candidates, then abort. Discard unused limbs for index selection, keep
every state advance, and propagate inner exhaustion. There is no external
random source, arbitrary label, rollback or failure fallback.

Each successful index is uniform under the independent interactive model.
The total availability bound is
`q_total*2^-64+(ell_total+64*q_total)*2^-1703`; it is not an acceptance loss.
Every attempted field draw and associated hash work remains in FS/H resource
accounting. The PCS query term has N possible coordinates, not |K| outcomes.

After full standalone certificate verification, a dedicated hash helper may
compute its ID from the exact purpose/context/length/proof frame in A9 §3.
Use the full 32-byte ordinary unkeyed BLAKE3 output, with checked u64 byte
lengths. This helper authenticates no proof by itself and is not a challenge.
The completed-proof ID never enters its own certificate transcript. Later
source bundles and opening statements bind that verified ID and full context.

Native labels, sampler, ID helper and actual consumers must land together
with byte parity, threshold/exhaustion and continuation controls. No production
registry or ledger changes occur in this Draft. Existing Q12 FS/H and quantum
obligations remain; neither profile is enabled. Affected tasks are E4-03,
E3-06's terminal source work and E8-05, without completion of their criteria.
