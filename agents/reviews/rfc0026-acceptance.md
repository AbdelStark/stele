# RFC-0026 acceptance review (development-profile end-to-end, RFC-0012 A16)

**Scope.** This review covers branch `rfc/RFC-0026-development-e2e`, drafted on
`origin/main` 6cecee7. It reviews:
- RFC-0026;
- RFC-0012 A16;
- Q33 and the Q31 note;
- ADR-074;
- the `stele_ir::relation` API and its plain checker;
- the E16 task entries;
- the NC-1300..1309 reservations.

**Reviewers.** Both passes were done by the drafting agent, so neither is
independent. The independent pass (fix-then-merge, all findings fixed) is recorded
below. These are internal agent reviews, not an external cryptographic audit.
- **Pass 1, soundness-auditor.** It checks what the verifier derives against what
  the prover chooses, the wrap-freedom of every relation kind, the claim-routing
  exactness, transcript order and ledger lines, and whether each line is labelled
  proven or conjectural.
- **Pass 2, implementability.** This pass takes the rfc-author view, plus the
  owners of the affected crates: gkr-reduction-author for stele-reductions and
  cqis-numerics for stele-cqis. It checks whether each E16 task can be built on
  the existing primitives as they stand, conflicts with Accepted text, the
  glossary, the controls and the task graph.

## Verdict

**Accept for the development profile.** The profile certifies no security level.
- Pass 1 found three soundness defects in the first draft, and all three are
  fixed in the text.
- Two obligations remain open. They are recorded rather than settled: the
  per-module output-uniqueness lemmas (§5.2) and promotion to `standard` (Q33).

## Pass 1: soundness

| # | Check | Finding | Disposition |
|---|---|---|---|
| S1 | Identity wrap-freedom | Suppose every factor's centered representative lies in its width. Then `|V| <= Σ|c|Π mag < p`, so `V ≡ 0` implies `V = 0`. This holds even if `c` is i64, because the bound is checked in u128 with saturation. | holds |
| S2 | Width enforcement | Range proof: the lookup of `v − min` into `[0, 2^b)` fixes the centered representative of `v` to lie in the width. A lookup with a selector leaves unselected rows unconstrained, so discipline does not count it. The code test `rejects_selected_lookup_as_discipline` checks this. | holds |
| S3 | Matmul with shared free bits | **Defect in draft 1.** The draft took `out~(ρ) = Σ_y lhs~(ρ,y)·rhs~(ρ,y)` for every matmul. Where a free bit is read by both operands (head and batch bits of `QKᵀ` and `P̂V`), the right side is not multilinear in `ρ`. An honest prover then fails, and the SZ argument does not apply. **Fix:** sum the shared bits under `eq(ρ_shared, x)` (§3.5, §4 step 6), with degree 3 and an SC line of `(s+k)·δ/|K|`. | fixed |
| S4 | Padding | **Defect in draft 1.** Padded weight entries are fixed by the model commitment but never read by the executor. If a module's padded output entries were free, a nonzero padded weight could enter a later sum. **Fix:** every module pins the padding of its output columns to 0 with a public mask identity (§2.1). | fixed |
| S5 | Argmax over a padded vocabulary | **Defect in draft 1.** A padded logit of 0 would exceed a row of real logits that are all negative, so honest proofs would fail. Pinning padding instead of masking it would also let padding compete. **Fix:** `chk[i,v]` masks both unchecked rows and padded ids (§5 row 13). Tie rule: `L[v] = sel` for any `v < c_i` gives `Mg = −1`, so the range check rejects it. | fixed |
| S6 | Column-of-group claims | The column index occupies the high source variables and the verifier knows its bits. The column claim is therefore the source MLE at a point with Boolean high coordinates, which is exact with no SZ term. Zero padding columns are never read, so their content is irrelevant. | holds |
| S7 | Lookup originals inside groups | A5's arithmetic needs each original fixed before its Unit, Beta and Alpha draws. Every group root is absorbed (step 2) before any lookup challenge (step 5). Widening "whole source" to "column of a source" therefore changes the consumer, not the argument. | holds; E16-02 implements and tests it (NC-1308) |
| S8 | Statement binding | The public inputs, model roots and relation digest are absorbed before any challenge. Both sides derive the relation from the plan, and `validate` runs before any proof byte is read. A plan or `[r,e)` mismatch is caught at step 1 (NC-1305, NC-1309). | holds |
| S9 | Identity RLC | The combination is zero for a nonzero identity vector with probability at most `n/|K|` (A16 charges `n/|K|` once per domain size). | holds |
| S10 | Ledger labelling | PCS is conjectural (no admitted parameter set, RFC-0012 A15). FS is unproven (Q12). The development profile reports `ε_interactive` only and claims no profile. | labelled |
| S11 | Encoding soundness | **Open.** The proof shows that some witness satisfies the relations. It equals the executor's run only if each module's relations determine its outputs. This is §5.2's output-uniqueness lemma, which is written and tested with near-miss controls but is not machine-checked. Rounding and attained-maximum patterns in particular have auxiliary freedom, for example `σ` at 0 and ties in `h`. Each module must show that this freedom never reaches an output. | open obligation; Q33 |
| S12 | Weight padding and width | Weights carry a range check in every proof. The model commitment is taken as given, and there is no passport binding (RFC-0011). The statement says so. | stated |

## Pass 2: implementability

| # | Check | Finding | Disposition |
|---|---|---|---|
| I1 | Engine reuse (E16-02) | Each primitive the engine needs already exists: zerocheck (RFC-0006 A3), `claim_batch` (A2 mode 1) and A1 sumcheck in `stele-sumcheck`; LogUp A5 in `stele_reductions::lookup`; and `verify_point` in `stele-pcs`. Two pieces of new code are needed. First, a column-claim path for lookup originals: today `lookup::Descriptor` takes whole `VerifiedCertificate`s. Second, the four labels must be registered in `stele-hash` and in `transcript-labels.json`. | in E16-02 acceptance |
| I2 | `byte_range` transcript | `byte_range` runs on its own transcript, so the engine does not reuse it. Ranges use A5 lookups on the main transcript, against range tables of any width up to 16 bits. | stated in §3.4 |
| I3 | Projections vs RFC-0023/0024 | The executor uses RFC-0025 §2.2 dyadic rounding with multiplier `m_j·s` above u16. RFC-0024 `integer_linear` therefore does not prove the CQIS projection. E16-05 uses M plus limb identities instead. | stated in §5 row 4 |
| I4 | Witness capture (E16-03) | `Executor::full` exposes only cuts, logits and cache. E16-03 instruments the executor to produce a `Capture`. Modules define their own `Capture` types so they can proceed in parallel, and E16-10 maps them. | E16-03 / §3.8 |
| I5 | Wide intermediates | Several values exceed 30 bits: `S` in rmsnorm (up to `2^39` at d=512), `A·m·s` in projections, `T` in P̂V (`< 2^50`) and the gated product (`2^30`). All of them need the limb rule. The research consumers LIMBS, LIMB-PRODUCT and WIDE-RANGE give the digit and carry caps. | §3.5; per-module |
| I6 | Plain checker cost | The checker evaluates each relation over its full domain. At T=64, d=512, that is at most about `2^24` products per projection, so module tests can run it on fixture shapes. | holds |
| I7 | Groups and sources | One group per (layer, module, length) gives on the order of 10^2 PCS sources for 8 layers. Certificate size per source is unmeasured, and E16-11 measures it. The model class excludes wide and grouped rows, so E16 does not depend on RFC-0004 A14/A15 patterns. | E16-11 |
| I8 | Crate edges | `stele-ir` keeps `[cqis]` and becomes no_std + alloc. Only `stele-reductions` imports it (deny.toml). The development verifier sits behind `stele-prover`, so no new edge is needed and `stele-verifier` is unchanged. | holds |
| I9 | Glossary | The RFC avoids the forbidden synonyms; it says "witness columns" and "capture". The new terms are development profile, column, commitment group, identity, limb rule and plain checker. | holds |
| I10 | Controls | NC-1300..1309 are reserved as `todo`, and the catalog snapshot test is updated (172 rows, 73 bindings). Plain-checker unit tests earn no control credit. | holds |
| I11 | Task graph | E16-02..09 depend on E16-01. E16-07 and E16-09 also depend on E16-05, which provides the row-conversion pattern. E16-10 depends on all of them, and E16-11 on E16-10. `test_task_graph.py` passes. | holds |

## Hard questions not settled here

1. **Output uniqueness** (S11). The soundness of the whole statement reduces to
   per-module lemmas that only module authors can write. This RFC fixes their form
   and the near-miss tests; it cannot pre-prove them.
2. **Promotion** (Q33). Promotion needs Q12, an admitted PCS parameter set, formal
   uniqueness statements and passport binding. None of these is within E16.

## Independent pass

**Reviewer.** An independent reviewer outside the drafting session reviewed PR #302
at 8f96069.

**Verdict: fix-then-merge.** The core integer model is sound. The reviewer checked:
- the wrap-free rule;
- discipline on narrow columns;
- `Ref` injectivity;
- transcript order;
- the argmax margin;
- the round-half pattern;
- rmsnorm uniqueness.

E16-05's builder independently reported two further findings, M1 and M2. Every
finding below is fixed in the follow-up commit on this branch.

| # | Finding | Fix |
|---|---|---|
| B1 (blocking) | `validate` could not discipline any witness column wider than 16 bits. A 24-bit matmul `out`, for example, was reported `Undisciplined`, so `A = q·W`, `Z`, quotients and limb-composed values could not be declared. | Added the `Compose` relation kind (RFC-0026 §3.5a). It is an identity under the bound rule, and it disciplines its column when the composed range of its enforced limbs fits the column's width. Discipline is now a fixed point. Tests: honest pass, tampered limb fails (`Violation::Compose`), and a composition wider than its column is `Undisciplined`. |
| M1 | A matmul `out` should be enforced by its own worst case. | Added §3.6 item 3's matmul rule: `out` is enforced when `lhs` and `rhs` are enforced and `Bp = 2^s·mag(lhs)·mag(rhs)` lies within `width(out)` at both ends. Then `out ≡ V` with both values in `(−p/2, p/2)`, so `out = V`. Tests: an int8×int8 out of signed 17 validates with no range; signed 16 (`Bp = 2^15 > 2^15−1`) is `Undisciplined`. |
| S2 | RFC-0008 A2 item 5 was not enforced: a 3-column lookup returned `Ok`. | `validate` now rejects tuple arity outside `{1, 2}` and tables with more than `2^16` rows. Test: `rejects_three_column_lookup`. |
| S3 | The engine silently widened RFC-0006 and RFC-0008. | Workflow 02 amendments, both linked to this review: RFC-0006 A8 (mode-1 claim batching on committed sources) and RFC-0008 A6 (group-column, affine-shift and `Ref`-mapped tuple originals, with the reduction argument). RFC-0026 §4 step 5 now opens multiplicity sources exactly as A5 specifies, not through `claim_batch`, and states item 2's Statement derivation: `N = 2^vars`, `b = min(m, 30)`, `r = 1`, `d = 4`, `σ` = selector or all ones. |
| S4 | Row 3 missed parts of RFC-0025 §2.2. | Added three shared patterns. Zero-row branch: `z·M = 0`, `z·q = 0`, divisor `s + z >= 1`. Row-scale ceiling: a range on `127·s − M ∈ [0, 126]`. Gated-scale ceiling: up to 8454661, through `Compose` limbs. |
| S5 | NC-1303 was a no-op, because `−1` is already `p−1`. | Split into NC-1303 (noncanonical limb `p`, `NoncanonicalField`) and NC-1310 (value `2^30` outside its width, LU rejection). |
| m1 | Ledger: the matmul SC line. | It has `s+k` rounds with `δ = 3` when `k > 0`, in both the RFC table and `soundness-accounting.md`. |
| m2 | §6 did not state the FS consequence. | §6 now says explicitly that QM31 at `r = 1` fails RFC-0012 §4's FS charge at real shapes (the pair round is near `2^-10`, per RFC-0008 A2 item 8). |
| m3 | Row 9 needed a committed masked `P̂`. | Added `P̂m = causal·P̂` as a committed column, because a matmul has only two factors. |
| m4 | Row 2 lacked the `e < 0` branch. | Added the exact-multiply branch of RFC-0021 §2.3, selected through the `a` one-hot. |
| m5 | §2.2's weight-root order was unchecked. | Stated as a plan obligation, checked by the E16-10 verifier before step 1 (`StatementMismatch`). |
| M2 | RFC-0004 A15 grouped rows were excluded. | §1.3 now admits them: the row-conversion pattern runs per group of `g`, and `A'` is handled through limbs. §3.1 and §7 note that `MAX_VARS = 30` caps a matmul domain and that larger shapes split into plan-fixed row blocks. |

Because RFC-0026 had not merged, its text was revised in place rather than through
amendments. The RFC-0006 and RFC-0008 changes are proper amendments.
