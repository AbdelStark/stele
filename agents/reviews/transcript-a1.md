# RFC-0012 A1 skill reviews

Reviewer: codex-root, also the author. Separate skill passes below are not an
independent audit or human sign-off. Scope: byte contract and DAG refinement;
no core transcript, protocol verifier, or soundness-budget generator is delivered.

## Soundness-auditor

Fixed-width framing is injective on its input tuple. The short initial domain
cannot equal a frame; request/update tags and the degree byte separate operations
and fields. Masked sampling has two preimages for each accepted candidate and two
rejected raw words. Acceptance patterns reveal only rejections, not which valid
values occurred, so the fixed cap does not bias successful vectors. Exhaustion
requires at least 57 rejections; the stated union bound is valid in the ideal-XOF
model. Actual BLAKE3 pseudorandomness and Fiat-Shamir compilation remain assumptions
and proof obligations, not consequences of these tests. No new error term or
budget discount is justified. Q12 explicitly blocks certification from placeholders.

I tried to break it by duplicating one label and by exhausting the candidate
stream, and the research controls rejected them with DuplicateLabel and
SamplingExhausted. The explicit last-word-success case is accepted. No protocol
NC coverage is claimed by these checks.

Sign-off: approve the specified bytes and sampling argument under the stated
ideal model; do not approve any instantiated standard/treaty security claim.

## RFC-author

The original Accepted text is retained byte-for-byte before the amendment log.
A1 replaces §1 explicitly and adds registry/ownership requirements to §2. It
preserves public-input, profile, absorb-order and final-claim obligations. E2-01
keeps every acceptance line; E2-00 breaks the dependency cycle without pretending
that a byte oracle is a proof verifier. Workflow 08's NC-0801 exception names the
actual configuration boundary and preserves every proof-control requirement.
Sign-off: approve glossary, amendment scope and DAG refinement.

## Implementing skills / owners

pcs-engineer / stele-hash: the contract supports constant-memory, no_std execution
with the existing field basis. Fixed typed labels and extension targets avoid
arbitrary-string/field escape hatches. Hash initialisation, framing, rejection and
state-update vectors are reproducible. The Python oracle uses the official Rust
hash backend; its framing is independent, its cryptographic implementation is not.
Sign-off: approve for E2-00 implementation with actual gate replacement, never
scaffold-hash updates to bless new code.

sumcheck-prover-engineer / stele-sumcheck: no generic byte API can enforce whether a
specific round or final claim was omitted. E3-01 must supply the real consumer and
NC-0800/0802, including a downstream challenge after final claims. Canonical
instance/message encodings must be specified before use. E2-01 cannot be completed
from primitive tests alone. Sign-off: approve the dependency refinement and retain
all original control obligations.

## Workflow 03 checklist

| Check | Disposition |
|---|---|
| Public items / RFC | No core public item added; reference code models RFC-0012 A1. |
| Challenges / absorbs | A1 specifies mandatory public absorb, typed caller absorbs, request and state update. No prover challenge exists yet. |
| Claims / consumers | None implemented. E3-01 must enforce its real schedule. |
| Bindings / controls | Existing NC-0800..0802 retained; NC-0801 boundary clarified. All remain todo. |
| Ledger | SC mapping documented; FS/H unchanged and uncertified. Accounting gate remains guarded scaffold. |
| Certificates | None introduced; this change is not an integer relation. |
| Padding / masks | No tensor padding or ZK masks changed. |
| Determinism | Canonical bytes, fixed basis and fixed decoding order. Failure returns no challenge. |
| Parity | Candidate vectors/checks only. No CPU/CUDA proof parity claim. |
| Cost | T_misc: framed payload hashes, bounded XOF, state update. No measured constant changed. |
| Verifier | Core verifier untouched; no bypass or injected-randomness API added. |
| Glossary | Applicable lint passes; no new exception. |
