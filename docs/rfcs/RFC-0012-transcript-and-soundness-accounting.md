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
