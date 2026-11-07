# RFC-0004 A15 / RFC-0005 A7 / RFC-0007 A6 / RFC-0025 A2 review (grouped activation rows)

Reviewers:
- One independent reviewer agent covered the soundness-auditor, rfc-author and
  cqis-numerics/harness owner roles. It had no part in drafting. It ran
  `check_grouped_rows.py`, `check_ci.py` (branch and `origin/main`),
  `check_cqis_torch.py 200` (branch and `origin/main`) and the catalog test itself, and it
  recomputed the bounds with its own script.

Reviewed: `git diff origin/main...task/E5-05d-grouped-rows` at 39e45a4.

**Verdict: accept after fixes.** The semantics are sound and the reference has parity:
grouped conversion, the one-rounding affine on A', the codec and identity, and the slot
schemas. The proof-form records are not sound yet. Schema 23 never binds the fold to its
digits, and for the gated row no field form of that binding can be faithful (B1).
Schema 24/25's recombination role cannot represent signed digit-row accumulators (B2).
Both are local fixes to the records and their consuming relations. Neither changes the
Model bytes, the conversion or the affine semantics. Re-review B1 and B2 before acceptance.

## Verified independently

- **Pass/fail.**
  - `check_grouped_rows.py` passes in 3.7 s. The worst ratio 8*cmax/p is 0.99219, the
    records are 43567 B and 21650 B, and the Llama counts are as quoted.
  - `check_cqis_torch.py 200` passes: reason_mismatch 0, 107 grouped twins accepted,
    300 grouped endpoint checks.
  - `cargo test -p stele-negative-controls --test catalog` passes (146 entries,
    21/61 bindings).
- **Version-1 identity.** Every pre-existing `check_ci.py` check prints byte-identical
  output on the branch and on `origin/main`, compared line by line with `grouped_cases`
  excluded. The ungrouped torch counts differ only because the grouped twins consume
  the shared RNG.
- **Arithmetic I recomputed.**
  - smax is 259 and 8454661, so X is 32893 and 1073741947.
  - The top digit is +-128 for int16 rows, attained at +-32893. It is +-64 for the gated
    row, attained at +-X.
  - 8*16384*128*127 = 2130706432 < p.
  - The gated amax is 16384*1073741947*127 = 2234207883575296 < 2^51.
  - 2*257*32893*127 = 2147189254 < p <= 2*258*32893*127.
  - Cost counts: 43008 base, 51200 extra, 26624 folds, 81920 digit *values*, 1703936
    partials and 208 group scales.
  - Record sizes: the largest grouped affine record over f in {0..44}, fo in {0,30},
    e in {-1099,1024} and bias options is 44460 B, at f=44, e=-1099, fo=0. This is still
    below 45056 B. The largest row record is 21650 B.
- **Codec.** Q/K/V reject mode 2. g = n, g not a power of two and g not dividing n
  reject, so one conversion has one encoding. The Policy frame stays 5 bytes, and the
  version-1 Policy bytes are unchanged. The quoted RFC-0025 and encoding-appendix
  sentences exist verbatim (RFC-0025:84, 92-93, 167-168, 190; full-model-encoding.md:216,
  233-234).
- **Oracles are independent.**
  - `oracle_row`/`oracle_affine` use Fraction rounding.
  - `digits()` is independent of `digit_bounds`, which the check asserts against
    literal constants.
  - The grouped `linear` in `check_model_execution` maps groups with `k*len(s)//n`,
    while `model_execution` uses `k//g`.

## Findings

### Blocking

**B1. The fold and its digits are never bound, and for the gated row no single field
identity can bind them.**
- Where: RFC-0004-cqis.md:2106-2108 (schema 23 roles), 2143-2144 (faithfulness),
  2150 (NC-0134); flow_bounds.py:65.
- **The gap.** Schema 23 appends two independent columns:
  - the fold (1,127,smax), a magnitude q_i*s_k;
  - the offset digits sum_t 256^t*o_t = x'+c, with c = sum_{t<T-1} 128*256^t +
    Btop*256^(T-1).

  No role and no stated consuming relation joins them. Nothing carries the code sign
  into the fold, and nothing joins the fold to the digits. RFC-0022 §2.2 requires these
  joins "by canonical digits with checked zero extension, not a single wide field
  equality", and RFC-0025 §2.8 requires the difference of every M31 identity to lie
  strictly within (-p,p).
- **Why it matters.** For the gated row (int32 product kind):
  - the fold lies in [-X,X] with X = 1073741947 > p/2;
  - in-range digit vectors span [-1082163328, 1082097535];
  - c+X = 2155905275 > p.
- **Counterexample.** Take the honest fold s*q = 8454661*127 = 1073741947, attained at
  |x| = 2^30. The digits (124, 0, 0, -64) all pass the A15 ranges, since the top digit
  -64 lies in [-64,64]. Their field sum equals X mod p, but their integer value is
  X-p = -1073741700.
  - So "digits ↔ folded value" checked as a field equality admits a sign flip of the
    largest down-projection inputs.
  - NC-0134 as reserved, "last digit outside [-Btop,Btop]", does not exercise this alias.
  - Every |fold| >= 1065320319 has an in-range alias.
  - int16 rows are not affected: the span is ±32896 and c+X = 65789.
- **Fix.**
  - Add schema-4-style sign roles that join the offset digits to the magnitude fold in
    byte columns. "Fold sign left": (1,255,256^t) for t<T-1, (1,2Btop,256^(T-1)) and
    (1,X,2). "Fold sign right": (1,c,1) and (1,X,1). Here F_i is the fold role's result.
  - State the consuming relation sum_t 256^t*o_t + 2*b_i*F_i = c + F_i, with b_i the
    code's sign from schema 4.
  - State that F_i, the digits and the fold are joined by canonical digits, never by
    one field equality.
  - Rewrite NC-0134 (or add a control) as "an in-range digit vector equal to the fold
    mod p but not over Z" (the X-p alias).
  - In `check_grouped_rows.py`, instantiate the relation with honest witnesses at ±X,
    and assert that the (124,0,0,-64) alias fails it.

**B2. Schema 24/25's role 1 recombines magnitudes, so mixed-sign C_t are incomplete or
unsound.**
- Where: RFC-0004-cqis.md:2111-2120; arithmetic_bounds.py:227-233.
- **The gap.** Role 1 is (1, inner*qw*b_t, 256^t), one term per digit row. Its left
  bound is cmax_t, not 2*cmax_t, so its operands are nonnegative magnitudes. The scalars
  4*cmax and 2*cmax are schema 1's small signed-dot sides (full-model-bounds.md:137), so
  each C_t is split into a magnitude v_t and a sign. Roles 2-4 then treat the role-1
  result as |A'|. But |A'| != sum_t 256^t*|C_t| whenever the C_t differ in sign.
- **Example.** C = (-5, 1) gives A' = 251, but the magnitude recombination is 261. No
  relation is stated that assigns the per-row signs.
- **Fix.**
  - Recombine offsets: U_t = C_t + cmax_t in [0, 2*cmax_t], with role 1 terms
    (1, 2*cmax_t, 256^t). Then sum_t 256^t*U_t = A' + V, where
    V = sum_t 256^t*cmax_t (V >= amax).
  - Add schema-1-style "recombined sign left/right" roles: (1,2V,1),(1,amax,2) and
    (1,V,1),(1,amax,1). Their relation is sum_t 256^t*U_t + 2*sign(A')*|A'| = V + |A'|.
  - Then apply role 2 = (1,amax,m) to |A'|, and update the scalars (V, and the sign
    sides) and the record-size claim.
  - Add a control for a C_t whose sign is flipped while the recombination role is still
    satisfied by magnitudes. Add a completeness check with mixed-sign C_t.

### Should-fix

**S1. The C_t source form is contradictory.**
- Where: RFC-0004-cqis.md:2134; RFC-0007:193-194; RFC-0005:158-159;
  RFC-0004-cqis.md:2158.
- **The conflict.**
  - "Each C_t is an RFC-0023 four-byte int32 accumulator source". RFC-0023 makes that a
    registered A9 source whose advice is a named auxiliary cut (RFC-0023 §1).
  - Schema 24 instead carries schema 1's small field sign sides (4cmax/2cmax).
  - RFC-0005 A7 says the accumulators "are virtual ... never cuts".
  - The cost line mentions "RFC-0023 advice in c_c where that cut is used", but "residual
    cuts unchanged" omits that the advice cut grows T-fold.
- **Fix.** Pick one form. The schema-1 field sign relation is sufficient, because
  8*cmax < p. If it is used, delete the RFC-0023 sentence in A15 and in RFC-0007 A6. If
  instead RFC-0023 sources and advice are used, state in RFC-0005 A7 and the A15 cost
  section that the advice cut grows by T per output (INV-6, T_cuts).

**S2. The cost section undercounts lookups, and its "upper bound" is not one.**
- Where: RFC-0004-cqis.md:2157-2165; check_grouped_rows.py:193-209.
- **Undercount.** "81,920 digit range memberships" counts digit *values*. The text's own
  range discipline uses one range_8 per low digit and two range_16 per top digit
  (RFC-0004-cqis.md:2129-2131). So memberships are 3 per int16 value and 5 per gated
  value: 3*3*4096 + 5*14336 = 108,544.
- **Missing terms.**
  - Under the RFC-0023 form (S1), each extra accumulator adds 4 range_8 memberships:
    204,800.
  - The head projection under Policy(final) is grouped too. It adds 128,256 accumulators
    per token for Llama-3.1-8B, which is not counted.
- **The bound.** c_a assumes 1.5–3 lookups per N_act element (cost-model.md:18). An added
  item carrying 3-5 lookups therefore does not count as at most one element, so "at most
  2.5 s" is not established.
- **Fix.**
  - State the lookup counts explicitly.
  - Count the head.
  - Either convert to N_act-equivalents at the cost model's lookups per element, or
    replace "upper bound" with an estimate and its assumption.
  - Make `llama_costs` assert the membership count, not the value count.

**S3. The claim that RFC-0024 needs an exact range is misleading.**
- Where: RFC-0007-matmul-cuts-and-weight-phases.md:189-192.
- **The problem.** RFC-0024 applies only to physical, byte-range-verified committed X
  sources with power-of-two d <= 2^15. It explicitly excludes "virtual activation
  source ownership" (RFC-0024 §1). Digit rows are virtual (RFC-0005 A7), so RFC-0024 can
  never apply to them, with or without a 128 digit. The stated fix, o and 2Btop-o in
  range_16, is sound as a range check, but it is not an RFC-0024 accommodation.
- **Fix.** Say that digit-row matmuls use RFC-0007 §5's field matmul over a virtual
  signed X. RFC-0024's centered path is unavailable for grouped inputs, and faithfulness
  rests on 8*d_in*128*q_w < p plus A15's digit consumers. Note that a plan which would
  otherwise use RFC-0024 for that projection loses it.

**S4. The reduction of the X-side claim on the virtual digit tensor is unstated.**
- Where: RFC-0007:183-188; RFC-0004-cqis.md:2138-2144.
- **The gap.** The matmul sumcheck leaves a claim on X̃ at ((r_t, r_i), r_k). The text
  names only the Requant-side zerocheck. It does not say how the digit-tensor claim is
  split into T claims at (r_i, r_k) and consumed by the schema-23 zerocheck. It also
  does not say whether that consumer gains rounds.
- **Fix.** Add one sentence naming the consumer and how the claim is split, and confirm
  in the ledger bullet that no new challenge is added (INV-2 accounting line).

**S5. Group indexing is not pinned for proofs.**
- Where: RFC-0004-cqis.md:2125-2128; RFC-0005:156-157.
- **The gap.** The text says "the attained-maximum index lies in the group" but does not
  say how. It also does not say how s_{floor(i/g)} is evaluated in the zerocheck over i,
  or how padded groups behave when n/g is not a power of two (Llama FFN: 112 groups).
- **Fix.** State three things:
  - the captured index is local, j_k in [0,g-1], schema 23's scalar g-1, and the global
    position is k*g+j_k;
  - s̃ is the MLE over the high log2(n/g) index bits, which is why g must be a power of
    two;
  - padded groups carry s=0 with zero codes.

**S6. Scope narrowing versus ADR-062 and the task graph.**
- Where: graph.yaml:1006; ADR-062.
- **The conflict.** ADR-062 puts Q/K/V cache rows in scope. The E5-05d title still says
  "for affine inputs and Q/K/V rows", while A15 defers them.
- **The risk for G7.** REPORT.md attributes part of the remaining ~1.1 points to Q/K/V
  rows. So E5-05e may still miss G7 for a reason that A15 deliberately leaves open.
- **The gap in tasks.** The native Model/Bounds/executor task is "still to be created"
  (RFC-0004-cqis.md:2193; RFC-0025 A2). The A14 precedent created E5-05c in the same
  change.
- **Fix.**
  - Fix the title.
  - Record the narrowing in the acceptance ADR. Correct ADR-062's "g-many scale lookups
    per row", which is n/g.
  - Create the native task now, with depends and acceptance.
  - Add a Q/K/V follow-up or an RFC-0019 question.

**S7. New terms are not in the glossary, and "grouped" is overloaded.**
- Where: agents/context/glossary.md.
- **The collision.** "Grouped" already names RFC-0008 A5's "grouped lookup" (used in
  RFC-0023 §1) and the GQA `groups` field of Shape.
- **Fix.** Add "grouped row (Policy mode 2)", "group scale", "fold" and "digit row" as
  glossary entries, each distinguished from the A5 grouped lookup and GQA groups.

### Nits

- **N1.** check_grouped_rows.py:161-166 fixes fraction 10 and output fraction 30, so the
  asserted worst affine record (43567 B) is not the true worst (44460 B, at f=44,
  e=-1099, fo=0). The text is still correct. Add f in {0,44} and fo in {0,30} to the
  grid.
- **N2.** RFC-0007:183-184 writes "b_t of s_k(i)*q_k". There k is both the inner index
  of §5 and the group function. Write "b_t of s_{floor(k/g)}*q_{l,i,k}".
- **N3.** RFC-0004-cqis.md:2079: "inner <= 257" holds for qw = 127 only. Say so.
- **N4.** cqis_torch.py:163 changes the ungrouped int16 lower Input bound from -32767 to
  -32768. This is a real parity fix, matching `model_execution.convert`. It also changes
  ungrouped behaviour. Note it in the commit and REPORT.md, and confirm that no E5-05 or
  E5-05b run rejected with `Input`.
- **N5.** cqis_torch.py:181-184: the grouped path drops `_int_mm` for a float64 matmul on
  folded values. That is exact (bound < 2^53, asserted), but slow on H100 with about
  $10 of the $50 cap left for E5-05e. Per-group int8 matmuls of the codes, multiplied by
  the group scales and summed in int64, keep `_int_mm` and stay exact.
- **N6.** check_cqis_torch.py:149: `group=rng.choice((1,2))` rejects at d=2 (g=n), which
  lowers knob coverage from 200 to 161 accepted cases. Draw g below d instead.
- **N7.** `grouped_checks` exercises only unbiased, int16-output linears. Bias and int24
  grouped outputs are covered only through model twins. Add one biased draw and one
  wide draw.

## Checklist

- **Challenges, absorbs, losses and profiles:** none added. Zerocheck rounds grow by
  log2 T. The digit-claim consumer is not yet stated (S4).
- **Ledger:** no new term. N grows; the counts are corrected in S2.
- **Cost:** as stated in the text, but undercounted (S2). The cut/advice question is S1.
  The weight pass count is unchanged (INV-7).
- **Controls:** NC-0131..0136 are reserved and the catalog test passes. B1 and B2 need a
  rewritten or added control: the X-p alias and a C_t sign flip.
- **Identity:** old Models are byte-identical, and there is one encoding per conversion
  (verified).
- **Native:** no native crate changes. The native task is still to be created (S6).
