# RFC-0004 A14 / RFC-0021 A4 acceptance review (wide int24 residual)

Reviewers:
- One independent reviewer agent covered the soundness-auditor, rfc-author and
  cqis-numerics owner roles. It had no part in drafting, and it ran `check_ci.py` and
  `check_cqis_torch.py` itself.
- claude-code, the author, addressed the findings below.

Acceptance follows the repository owner's instruction to resolve fidelity and
blocking amendments autonomously, with Workflow 02 still applying.

**Initial verdict:** accept with changes. All findings below are resolved; the final
verdict is **accept**.

## Verified independently

- **Arithmetic.**
  - S <= 2^59, P < 2^105, A < 2^152, D < 2^137, MD < 2^153, |T| <= 2^52.
  - a in [-23,16] (16 is attained) and e in [-16,97].
  - Left shift <= 2^68, biased < 2^97.
  - The statistic side is 1071628543 < p/2 at d = 8192. d = 8208 is faithful and 8209
    raises FieldBound.
  - Umax <= 2^54. Sign sides are 2^25-1 and 2^24.
- **Schemas.** The roles and scalars of schema 20 match the text, and schema ids 20–22
  are unused elsewhere.
- **Version 1 unchanged.** Version-1 behaviour is byte-identical: fd = 2^18, scalars
  32/33, emax F+G+30, function version 1. The full model-contract output equals the
  pre-change output.
- **Error bound.** RFC-0021 §5's bound is independent of input width:
  - |x_i|/sqrt(q) <= sqrt(d) for any width, since q >= mean(x^2);
  - delta comes from J/M truncation only;
  - the gain stays int16.
- **Identity and aliasing.**
  - The version is in the FunctionId preimage, and decode re-encodes, so `Width` is
    enforced.
  - GPT-2 LayerNorm has no wide form.
  - An int16 R_0 consumed as an int24 source is sound.
- **Reference parity.** The torch executor matches the research reference on 1000
  models, with wide twins built with their own Artifact identity: 181 wide accepted
  against 166 narrow, reason_mismatch 0.

## Findings and resolutions

1. **Blocking: N < 2^105 was false.** d = 8192, F = 30, en = 2^32-1, ed = 2^32-2 gives
   106 bits.
   - The text now reads N < 2^106.
   - The check grid now includes coprime near-maximal ε and odd d, and asserts exactly
     the quoted bounds.
2. **Blocking: a record size of at most 51136 B was false.** The actual maximum is
   51180 B.
   - The text now reads "below 52 KiB". The check asserts it for schemas 20, 21 and 22.
3. **Blocking: cut width conflicted with Accepted int16 statements.** These were
   RFC-0004 §2, RFC-0005 §4, RFC-0007 §3, RFC-0010 §8 and the cost model.
   - Added the Cross-RFC scope in A14 and the companion entries RFC-0005 A6, RFC-0007 A5
     and RFC-0010 A11.
   - Added a cost-model note: int24 cuts are committed one per M31 element, so the cut
     message count doubles and storage is 1.5x.
4. **Blocking (process): status was premature.**
   - Added this record, ADR-061, the RFC-0000 index rows and the catalog reservations
     before publication.
5. **Should-fix: "no control id" did not hold under INV-4.**
   - Reserved NC-0127..0130 (`todo`): mixed versions, a 2^23 wide target, width
     substitution, and the gain source bound through the X roles.
   - Updated the catalog snapshot.
6. **Should-fix: "range-checked exactly once" contradicted the producer and consumer
   checks.**
   - Reworded to: each producer checks its signed target, and every consumer
     re-decomposes the original source as o = x + 2^23 in three unsigned bytes.
7. **Should-fix: "about 4d lookups" undercounted.**
   - Restated as about 12d range_8 memberships plus about 10d limb products per token
     and layer, with the role-by-role count. The conclusion (negligible) holds.
8. **Nits.**
   - "The scalar values 32 and 33". fd_max is now described as a fixed value.
   - The `modal_e505.py` docstring is restored.
   - ADR-061 records the narrowed E5-05a acceptance and the new E5-05c.
   - REPORT.md notes that A14 keeps R_0 int16. The int16 run had no embedding overflow
     with the same f0, so the measured numbers are unaffected.

## Checklist

- **Challenges, absorbs, losses and profiles:** none added.
- **Ledger:** no new term. Added byte digits increase the LogUp instance count N.
- **Cost:** c_lu/c_a and T_cuts messages, all stated. No measured constant or weight
  pass changes.
- **Controls:** NC-0127..0130 are reserved for actual consumers (E5-05c, E7-03, E7-10).
- **Native:** E5-05c owns native support. No native crate changes in this PR.
