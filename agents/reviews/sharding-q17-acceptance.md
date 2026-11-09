# RFC-0010 A13 / RFC-0015 A1 acceptance review (plan-fixed row shards, Q17)

Reviewed: branch `rfc/RFC-0010-sharding-q17`, drafted on `origin/main` 6a93f15 and
rebased onto b9dde05 (RFC-0007 A1, #298).
Companion: RFC-0015 A1 and the Q17 resolution in RFC-0019. These are internal
agent passes, not an external cryptographic audit.

Reviewers:
- **Pass 1, soundness-auditor.** Same-author pass by the drafting agent. It checked
  what the verifier derives against what the prover chooses, every new prover
  byte, Fiat–Shamir rounds, the frozen-oracle lift and proven or conjectural labels.
- **Pass 2, rfc-author, pcs-engineer (stele-pcs owner) and distributed-systems-engineer
  (stele-dist owner).** Same-author pass by the drafting agent. It checked conflicts
  with older Accepted text, the glossary, the control catalog, affected tasks and
  whether E4-07 can be built on stele-pcs and stele-hash as they are.

Both passes are by the author; neither is independent.

- **Pass 3, independent review** of PR #299 at e2b5bfa, by a reviewer outside this
  drafting session. It is recorded under "Independent pass" below.

**Verdict: accept.** No soundness gap remains in the interactive argument. The
amendment adds no challenge, round, label or ledger line. One open obligation is
scoped, not a gap: cuts use s=0 until E11-01 lands an Accepted plan field for s.

## Option chosen and why

Q17 asked how "digest identical for 1 and N shards" can hold when RFC-0012 A3
says a root of roots binds its logical partition. Two readings exist:

- **Option A (chosen).** The logical partition (s) is part of the source context,
  fixed by the plan. Devices own whole shards. The device count appears in no byte,
  so 1 and N devices give the same root, certificate and opening bytes by
  construction. E4-07's "shards" means devices holding the plan's fixed partition.
- **Option B (rejected).** Make the sharded root equal a flat-tree root. A flat
  tree's leaves are whole columns of R elements, so every device would have to
  hash full columns spanning all devices. That is a gather of all encoded
  columns, not a sharded commitment, and it would still need a new rule for who
  hashes what. It buys nothing that s=0 does not already give.

Pass 1 found no soundness reason against A: any admitted s is sound, and the
verifier never reads s from the prover.

## Pass 1 — soundness-auditor

Provenance, field by field:

| Value | Source | Who chooses |
|---|---|---|
| s, S, R_s, shard order | layout byte of the expected source bytes; σ = top s row bits | consuming RFC (plan/passport); verifier |
| child descriptors `{Columns, id, N, 4R_s}`, kind-2 descriptor `{Roots, id, S, 32}` | derived from context | verifier |
| root of roots | expected root field of source bytes | consuming RFC's pre-challenge commitment |
| child roots | certificate wire | prover; checked against the root before the transcript exists |
| segments and paths | responses | prover; each authenticated at the derived index against its child root |
| N, D, e, q_c, q_o | same as s=0 | verifier |
| partial rows per device | not sent | nobody; only the summed t or u is a message |

Findings:

1. **Child roots must be fixed before row randomness.** Draft text absorbed them
   with t under CertificateRow, after CertificateWeight. Given the root they are
   fixed up to an H event, so this was not an attack, but it broke RFC-0012 §2's
   literal rule and made the A8 freeze argument longer. Fixed: item 6 puts them in
   the certificate public input and checks them before the transcript is created.
2. **Opening must not accept proof-supplied child roots.** If an opening carried
   its own child roots, an implementation could check segments against them and
   forget the root check. Fixed: item 8 sends none; the verifier reads them from
   the verified certificate, whose ID absorb(Opening) binds. E4-07 must keep them
   in the certificate record.
3. **Zero-coefficient shards.** A shard whose rows all have a_r=0 still needs its
   segment authenticated, or its child root would be unconstrained at that index.
   Item 7 requires every segment, matching A9's zero-coefficient rule.
4. **A8 lift.** Item 11 extends A8's traversal. A kind-2 internal frame fixes two
   digests and a kind-2 leaf frame fixes one, so each recorded input still adds at
   most two frontier digests and `|F| <= 1+2·Q_pre` holds. Frames of different
   kinds, ids, counts or widths are distinct inputs (A3's header D), so a node
   cannot be parsed in two roles without a collision. S and N are powers of two,
   so neither tree has absent padding leaves. Two equal child roots name the same
   subtree; the frozen W is still a function of the digests, so this is harmless.
   The argument is A8's classical ideal-hash argument, conditional in the same way.
5. **Fiat–Shamir.** No new challenge or round. CertificateWeight is still
   re-rolled only by changing the expected root; child roots add no freedom
   except through an H event. Column rounds are unchanged. No FS term is added and
   A3 item 7's hand derivation (Policy 1 fails both profiles) is unaffected.
6. **Proven versus conjectured.** The PCS terms are A3's proven terms for the same
   N, D, e, q. Nothing conjectural is introduced. Q12 stays open.
7. **Context confusion.** A flat source and a sharded source with the same root
   field differ in the layout byte, so a certificate for one is CertificateContext
   for the other. A kind-0 root and a kind-2 root over the same bytes are different
   hash inputs; equality is a collision.
8. **Capacity.** s is capped at min(ell, 8). Proof bytes grow with S·log2 N per
   response, and q_c reaches 13472 for v2 sources, so an uncapped s could make the
   wire enormous. All wire sizes must be checked before allocation (A9 §6). The cap
   is a cost limit, not a soundness one; raising it needs an amendment.
9. **Determinism.** Partial rows are summed in K, which is exact and order-free.
   Segments are serialized in σ order. No byte depends on device count, rank or
   timing. This is what E4-07's digest test checks.

## Pass 2 — consistency, ownership and tasks

Older Accepted text:

| Text | Conflict | Resolution |
|---|---|---|
| RFC-0010 §9 | row shards, yet "column openings touch only the device owning the column shard" | withdrawn and replaced by A13; every column draw touches every shard |
| RFC-0015 §3 | "each device commits its shard" ties the commitment to device count; "one device per column" | replaced by RFC-0015 A1 |
| RFC-0015 §2 | "the device owning the columns opens them" reads as protocol | clarified as prover storage; weights stay s=0 |
| RFC-0012 A3 | none. Kind 2 is used as specified, ordered by the plan's shard index; the root is rebuilt from the full list (no kind-2 membership openings); the "need not equal a flat-tree root" sentence is what option A relies on | no change; Q17 recorded resolved in RFC-0019 |
| RFC-0012 §2-§3 | none: child roots are bound before any challenge; 0x02 leaf tag unchanged | no change |
| RFC-0010 A9 §1 / native-field-pcs.md §1 | "other layouts reject" | A13 item 1 admits layout bytes 1..min(ell,8); every other value still rejects. s=0 bytes, fixtures and digests are unchanged |

Other checks:
- **Glossary.** Adds shard exponent, child root and root of roots. "Shard" keeps
  its RFC-0015 sense; no forbidden synonym. Glossary lint passes.
- **Controls.** NC-0615..0618 reserved todo under a new binding, "sharded
  commitment", so coverage reports it missing until E4-07 runs them through the
  actual verifiers. (NC-0619..0621 were added after the independent pass; the
  final snapshot is 162 rows, 21/63 bindings, 64/162 controls.)
- **Ledger.** No new line. The H caps must count child-tree hashes. Recorded in
  docs/security/soundness-accounting.md.
- **Cost.** Exact frame and byte counts in docs/cost-model.md; no constant moves.

Tasks:
- **E4-07** stays ready. Its original line is kept verbatim, plus byte parity
  for 1 and N devices at fixed s and NC-0615..0618 (NC-0615..0621 after the
  independent pass).
- **E11-01** gains one line: no cut with s>=1 until an Accepted plan field
  (RFC-0005) derives s from public plan data. Without it, R_stack stays s=0.
- **E11-02** unchanged. Weight sources are passport sources with s=0.
- **E4-03** (done) unaffected: s=0 is byte-for-byte the existing source.

Implementability (stele-pcs and stele-hash owners): stele-hash already builds and
verifies Kind::Roots trees. `Source::from_bytes` re-serializes with layout 0 and
must accept item 1's range. Certificate and opening parsers gain the child-root
block and segmented responses. No new dependency; deny.toml unchanged. The change
fits one E4-07 PR.

Sign-off: soundness-auditor, rfc-author, pcs-engineer and distributed-systems-engineer
(same author) approve A13 and RFC-0015 A1 as Accepted.

## Independent pass

Reviewer outside the drafting session, PR #299 at e2b5bfa. Verdict: fix then
merge. No soundness break: the encoding is unchanged, s comes only from the
expected source bytes, domain separation and transcript order hold, the A8
frontier bound is unchanged and the cost figures are right. Passes 1 and 2
missed S1 and S3; both are fixed. The amendment was renumbered A12 to A13 and the
ADR 070 to 071 after RFC-0007 A1 (#298) took RFC-0010 A12 and ADR-070.

| Finding | Closed by |
|---|---|
| S1. Accepted texts still pinned layout 0: RFC-0010 A3 items 2 and 5, A6, native-field-pcs.md §1 (layout row and rejection sentence), native-lookup.md §1 | A13 item 12 gives exact replacement sentences in the requested wording; a pointer line in native-field-pcs.md §1. Multiplicity sources stay s=0. A6 cut sources may use s>=1 only where the consuming Accepted text fixes s; none does today |
| S2. E4-07's verbatim line contradicts item 4 | Line kept verbatim and annotated in place: "(shards = devices holding the plan's fixed partition; RFC-0010 A13 item 4)" |
| S3. NC-0615..0618 test only kind-2 RootMismatch and ProofShape | New reserved NC-0619 (segment under the wrong child root, RootMismatch), NC-0620 (off-code shard or t/u inconsistent with one shard's segment, ColumnMismatch), NC-0621 (byte change in a zero-coefficient shard's segment, RootMismatch). All at s>=1 through the actual verifiers; added to E4-07. Catalog 162 rows, 64/162 controls, test updated |
| Minor: RFC-0012 A3 "Q17 must resolve" | Annotation pointing to RFC-0010 A13 and RFC-0015 A1 |
| Minor: E11-02 rfc list | RFC-0015 A1 added |
| Minor: device count not dividing S | RFC-0015 A1 says it affects only scheduling, never s or any byte |
| Minor: verifier hash count as cap input | soundness-accounting.md states S·(1+log2 N) per response plus 2S−1 per certificate |

Post-rebase check (same author): #298 introduced RFC-0010 A12 and RFC-0007 A1
item 2, which call the fused-layout split index "s" and fix it at 0. A13 item 1
and the glossary now say the shard exponent is a different quantity. Weight
sources stay s=0 under both meanings, so nothing conflicts. E4-06 and E7-02 keep
#298's blockers.
