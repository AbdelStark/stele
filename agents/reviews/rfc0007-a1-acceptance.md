# RFC-0007 A1 acceptance review (full-row fused weight opening)

Reviewed: branch `rfc/RFC-0007-A1-accept` on `origin/main` 6a93f15. Companion:
RFC-0010 A12. These are internal agent passes, not an external cryptographic audit.

Reviewers:
- **Pass 1, soundness-auditor.** Same-author pass by the drafting agent. It checked
  error terms, theorem citations, proven or conjectural labels, Fiat–Shamir rounds and
  every place a parameter could come from the prover.
- **Pass 2, rfc-author and pcs-engineer (stele-pcs owner).** Same-author pass by the
  drafting agent. It checked consistency with Accepted text, the glossary, tasks,
  controls and implementability against E7-01b1's retained row.

- **Pass 3, independent review** of PR #298 at d9e044d, by a reviewer outside this
  drafting session. It is recorded under "Independent pass" below.

Passes 1 and 2 are by the author; neither is independent. Pass 3 is the independent
sign-off of the soundness-auditor and of the stele-pcs owner.

**Verdict: accept after fixes.** All blocking findings below are closed on this
branch. A1 admits no new protocol: it fixes a layout constant and names an existing
object (the A10 retained row) as the fused opening row. No profile is admitted.

## Gap analysis of the Draft's open items

| Draft item | Closed by | Where |
|---|---|---|
| Injective source map, signed representation, padding | RFC-0010 A6 (one element per value, signed or offset, layout 0, no padding); A7 for cuts | A1 item 1 |
| "Do not assume two int16 per M31" | RFC-0007 A7 | A1 item 1 |
| B is the original signed partial evaluation; opening consumes it or an authenticated reduction | Identity (signed) or a constant shift (offset); no reduction admitted | A1 item 3 |
| Short columns retain u_s and fold to B | Not admitted; RFC-0010 §4's sentence withdrawn (A12) | A1 item 2 |
| Exactly one source weight visit, every source claim consumed | A10 constructor is the only read; one A3 opening per W claim; virtual X and configured phase stay E7-02 | A1 item 4 |
| Packing/decomposition consumer (with RFC-0008 A1) | Moot: no packed source is admitted | A1 item 1 |
| NC-0300..0305/0605, E4-04/E7 criteria unchanged | NC-0305/0605 refined, todo, E4-04; all original criteria kept | A1 items 7, 9 |
| Future challenges/losses accounted | None added; inherited rounds recorded | A1 item 6 |
| Message counts, c_w/c_c/T_misc, memory | Full-u size stated; no constant moves | A1 item 8 |

## Pass 1 — soundness-auditor

Parameter provenance:
- **Verifier-derived.** Row weights a = eq(·, r_j) from the expected stage point;
  column weights eq(s_l‖r_k) from the A1 final point; N, D, e, q_o from the code ID
  and policy (RFC-0010 A3). The split index is the constant s=0.
- **From the expected statement.** A2's ids, dimensions, sources and certificates.
  Root and code identity come from the passport (RFC-0010 A3 item 5); the embedding
  from the plan (RFC-0010 A6, enforced by E8-02).
- **From the proof.** Only round polynomials, finals, u and column responses.
  B never crosses the wire as such; the verifier sees only u.

Findings:
- **P1 (blocking): the Draft's "or an explicitly specified authenticated reduction"
  is open-ended.**
  - Problem: accepted as written, any future reduction from B to the committed row
    could be slotted in without its challenges being accounted.
  - Closed: item 3 admits exactly two relations, identity (signed) and the constant
    2^(w−1) (offset). "No other relation, reduction or copy is admitted."
- **P2: the offset identity needs Σ_j a_j = 1.**
  - Problem: with padded rows that hold message zeros (not offset zeros), the shift
    would be 2^(w−1)·Σ over logical rows only.
  - Closed: A2 and RFC-0010 A6 require full power-of-two extents with no padding, so
    Σ_j eq(j, r_j) = 1 exactly. Item 3 states the dependency. The verifier needs no
    change either way: A4 already opens the raw scalar.
- **P3: does short-column soundness need a u_s-to-B binding?**
  - Analysis: no. The verifier never reads B. The W claim at (s_l, r_k, r_j) is a
    rank-one functional of any registered layout, and A3 item 1 opens arbitrary a, b
    on a certified source. The fold is a prover and pass-count obligation.
  - Still not admitted: s would need a verifier-derived owner (passport or plan) and
    pass-count evidence. Item 2 records both, and leaves the split for an amendment.
- **P4: Fiat–Shamir rounds.**
  - A1 adds no round. Inherited, recorded in item 6:
    - phase sumcheck rounds, error 3/|K| each: Q·3/|K| ≈ 2^-22.4 (treaty, Q=2^100)
      and 2^-42.4 (standard, Q=2^80) in QM31, both failing; ≈ 2^-146.4 and 2^-166.4
      in OM31, both passing;
    - OpeningColumn under Policy 1 fails both profiles (RFC-0010 A3 item 7).
  - Arithmetic: log2(3) = 1.585, |QM31| ≈ 2^124, |OM31| ≈ 2^248.
- **P5: ledger lines.**
  - Per phase: SC `3·(log2 L + log2 d)/|K|` (RFC-0007 A2) and PCS opening
    `((N−D+e)/N)^q_o` (RFC-0012 A15). The weight certificate is charged once over
    its registration lifetime with every opening (RFC-0010 A9 adaptive reuse). Merkle
    under H. All proven, conditional interactive. No new line.
- **P6: width.**
  - The opening proves no width; faithfulness of the integer matmul needs one.
  - Closed by reference: RFC-0010 A6's rule stands. Item 5 states the consequence:
    only offset int8 weights (RFC-0024 §1.1) currently pass E6-02's plan check.
- **P7: two W claims per type.**
  - §5's single claim depends on the stacked requant zerocheck. A plan with two r_j
    for one type would be sound (two openings) but would read W twice.
  - Closed: item 4 states that this breaks INV-7 and that E7-02's existing one-pass
    counter criterion forbids it. No new criterion.
- **P8: NC-0305 with a nonzero factor.**
  - Problem: a first draft of NC-0305 changed one coordinate of B with a nonzero X
    factor. Then the round-one sum no longer equals v and the sumcheck rejects,
    so the control would never reach the opening.
  - Closed: the variant changes two coordinates so that Σ c·B' = v. Every round
    passes and only the column equations reject. This is distinct from NC-0611
    (zero opposite factor).

## Pass 2 — rfc-author and pcs-engineer

- **S1 (blocking): RFC-0010 §4's short-column variant is Accepted text.**
  - Closed: RFC-0010 A12 withdraws it.
- **S2 (blocking): the glossary says u equals B.**
  - Problem: false under the offset embedding.
  - Closed: the entry now names both relations.
- **S3 (blocking): E4-06 is ready but needs short columns and Ligerito.**
  - Problem: neither is admitted (RFC-0010 A3 item 1, A1 item 2), and E4-06
    becomes reachable once E4-04 is done.
  - Closed: E4-06 is blocked, citing both.
- **S4: NC-0305 and NC-0605 sat in "see RFC" range rows with no error.**
  - Closed: split into their own catalog rows with tamper and error. Entry count is
    unchanged.
- **S5: architecture.md still said "R_stack (1 batched functional)".**
  - Closed: now one opening per row-17 claim (RFC-0007 A7).
- **S6: formal/native-matmul.md ends "RFC-0007 A1 remain Draft".**
  - That contract is Accepted and not edited in place. Item 9 states the sentence is
    superseded.
- **S7: RFC-0008 A1.**
  - Its addition governs packed committed sources. RFC-0010 A6 admits none, so it
    has no object here and is not a prerequisite. The PR #296 independent review
    reached the same view. RFC-0008 is not edited; A1 stays Draft for a future format.
- **S8: implementability (stele-pcs owner).**
  - E7-01b1 already ships the retained row with one observed source visit. E4-04's
    remaining work is the fused API surface for weight phases, the read counter and
    the two controls.
  - No new label, error kind, wire field or crate dependency. ColumnMismatch and
    ValueMismatch are A9 errors. The controls forge wires at byte level, because the
    retained-row API rejects a foreign row with RowContext before any transcript work.
- **S9: other text.**
  - RFC-0001 D4 ("raw packed weights") is physical storage; RFC-0014's "short
    columns" refers to Merkle leaves; RFC-0015 §4's fused sharding is unaffected.
    No conflict.
  - RFC-0019 gains a Q28 resolution note; formal/fused-layout.md's status line is
    updated (Draft study, not normative).
- **S10: cost.**
  - No constant moves. Item 8 states the full-u size per weight type.

## Independent pass

Verdict at d9e044d: fix, then merge. No soundness break: u is bound before the column
draws, no opening parameter is prover-chosen, the text matches RFC-0010 A3/A7/A9, the
Fiat–Shamir arithmetic checks out and the NC-0305 forgery argument holds. This pass is
the soundness-auditor and stele-pcs owner sign-off. Each finding was closed on this
branch.

- **S1 (significant): wrong expected scalar under the offset embedding.**
  - Problem: item 3 compared dot(u,b) with the A1 W final, which is the signed value.
    An honest raw offset row would fail with ValueMismatch.
  - Closed: item 3 now compares with RFC-0024 §2.2's v_raw = v_signed + 2^(w−1)·Σa·Σb
    under offset, and with the A1 W final under signed. ADR-070 says the same.
- **S2: "adds one PCS opening term" undercounts.**
  - Problem: an A2 phase opens X and W, and RFC-0024 phases carry m/|K| and advice terms.
  - Closed: item 6 gives the exact unchanged A2 line
    `3·(log2 L + log2 d)/|K| + ((N_X−D_X+e_X)/N_X)^q_o,X + ((N_W−D_W+e_W)/N_W)^q_o,W`
    and keeps RFC-0024's terms unchanged. A1 adds no term.
- **S3: the virtual-X configured phase had no owner text.**
  - Problem: item 4 sent it to E7-02 and item 9 said E7-02 was unchanged, but A2 is
    two-source only, and no Accepted text gives that phase's statement, bytes or labels.
  - Closed: Draft RFC-0007 A8 (Q28) names the obligation. E7-02 is blocked on A8, its
    acceptance lines are verbatim, and its rfc list gains RFC-0007 A1/A2 and RFC-0010 A10.
    RFC-0019 Q28 and the RFC-0000 index record A8.
- **S4: cost figure.**
  - Problem: 4·8·2^21 = 2^26 bytes is 64 MiB in OM31; 32 MiB is QM31.
  - Closed: item 8, ADR-070 and the PR body give both.
- **M5: Accepted text still called A1 Draft.**
  - Closed: item 10 lists every superseded sentence: RFC-0007 A2 and A7, RFC-0010 A3
    item 11, A6 (item 3 and its task line), formal/native-matmul.md's closing sentence,
    and RFC-0010 §10's NC-0605 "fused u ≠ B", which an honest offset row does not violate.
- **M6: NC-0305 had two owners (E4-04 and E7-02).**
  - Closed: E4-04 owns it. E7-02's verbatim line re-runs the control at the composed
    phase and is not a second owner (item 9).
- **M7: the E4-04 title said "takes sumcheck B as u".**
  - Closed: the title now names the retained row and both relations. Acceptance lines
    are verbatim.

## Not reviewed

- Q12's actual Fiat–Shamir theorem.
- Privacy (RFC-0010 A7, RFC-0013 A1).
- Short-column, Ligerito and packed formats (not admitted).
- Native code: none is changed by this PR.
