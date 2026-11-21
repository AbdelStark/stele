# Soundness Audit Review — Task E19-04, end to end (joined RFC-0029 recursion in the relation engine, profile byte 6)

- **Task:** `E19-04`, Epic `E19`, Lane C
- **Audited commit:** `b62e429e` (parent `ebb5a939`). The branch was rebased during the review; the same patch is now `b32ef22c` (equal `git patch-id`). Line numbers are those of `b62e429e`.
- **Reviewer:** independent `soundness-auditor` agent; did not write the change
- **Governing specs:** RFC-0026 A29; RFC-0029 §§1.3, 2, 5, 6; RFC-0012 A16, A20; RFC-0010 A17; RFC-0027 §2
- **Tier:** development
- **Verdict:** **CHANGES REQUESTED**

## Summary

I did not find an accepted false statement. Transcript order, claim routing, the multiplicity mask and the profile binding match RFC-0026 A29 and RFC-0029 §2. The two BLOCKING findings are controls, which INV-4 and the E19-04 acceptance criteria make merge conditions:

- The one binding this commit introduces (the Q51 mask check) has no control.
- Three of the six controls named after NC-0630..0635 do not test what they name.

Beyond those, no committed control reaches any algebraic check of the new verifier, one ledger line disagrees with RFC-0012 A16, and one proof section is never checked for emptiness.

## Scope

- `crates/stele-reductions/src/relation_recursive.rs` (new)
- `relation_lookup.rs`: `start_with_mu`, `prove_for_stack`, `verify_for_stack`
- `relation.rs`: hooks and ledger helpers
- `crates/stele-prover/src/development.rs` and `development/bundle.rs`: profile byte 6 path
- The two new tests, RFC-0026 A29 and ADR-154

The PCS core in `crates/stele-pcs/src/recursive.rs` was read for its contracts only; its audit is `agents/reviews/e19-04-joined-recursion-pcs.md`.

## Evidence labels

- **[ran]**: executed on a `git archive` export of `b62e429e` outside the repository, test profile (optimised, debug assertions and overflow checks on).
- **[read]**: established by reading only.

Two instruments were added to the scratch copy and never to the repository:

- **Deletion k**: the verifier with exactly one check removed (table in F3).
- **Forging provers A and B**: two dishonest provers for the Q51 path (defined in F1).

## What holds

### 1. Fiat–Shamir order [read; root tampers ran]

Verifier order in `verify_recursive`; the prover mirrors it at `relation_recursive.rs:798-1353`.

| Step | Absorbed | Lines | Challenges that follow |
|---|---|---|---|
| 0 | First frame: public input with every model root, the statement, profile byte 6, `segment_layers` | `development.rs:181-222`, `1032` | none |
| 1 | `relation/statement`: relation digest. `relation/roots`: each model source context and certificate id | `1436-1439`, `592-603` | none |
| 2.1 | `relation/roots`: witness stack root of segment `s` | `1452` | none |
| 2.2 | `relation/roots`: `mu_stack` root of segment `s` | `1464` | none |
| 2.3a | Zerocheck instance, rounds, finals | `1478-1507` | identity lambdas, zerocheck challenges |
| 2.3b | Lookup statement; multiplicity bundle naming the `mu_stack` source context, root included | `relation_lookup.rs:250-259` | `(beta, alpha)`, tree and selected-product challenges |
| 2.3b | Prefix instance (table claim as its sum); batch descriptor with every `mu_stack` claim; level-0 statement, `pcs/level-root`, `pcs/opening-columns` | `1555-1596`, `684-737` | prefix rounds; batch coefficient and rounds; column indices; `pcs/level-beta` |
| 2.3c, 2.4 | Matmul instance with `out(rho)`; Linear operand values; virtual batch descriptors | `1607-1807` | `relation/point`, round challenges |
| 2.5, 3 | Witness batch and level-0 close of segment `s-1` (last segment at step 3); per model source the batch and certified level-0 | `1811-1927` | as for `mu_stack` |
| tail | Statement naming every block's source id, opening id, `u_1` root, beta and claim | `1929-1942` | `pcs/level-gamma`, row rounds, indices |

- Each segment's witness root and multiplicity root precede that segment's identity lambdas, `(beta, alpha)` and every sumcheck challenge.
- A carried column's root was absorbed one segment earlier.
- Model roots sit in the first frame and in step 1.
- Every fresh level-0 point is the claim batch's sumcheck point, drawn after the root, which is the precondition of `verify_fresh_level0_at_point`.
- No transcript label is added.
- A one-bit change of a witness root or a `mu_stack` root rejects, and so does swapping either between segments [ran].

### 2. Claims and consumers [read]

| Claim on | Discharged by |
|---|---|
| Witness column of segment `s`, carried ones included | `recursive_group_claims` (`605-616`), claim batch, fresh level-0 close at step 2.5 of segment `s+1` or step 3, joined tail |
| Virtual column | Step 2.4 of its own segment; a leftover is `ProofShape` (`1946-1951`) |
| Table-side multiplicity numerator | Directly when `t = 2^k`, else the prefix sumcheck; then the `mu_stack` batch, its level-0 close, joined tail |
| Table-side denominator | `check_table`, verifier-computed (`relation_lookup.rs:731`) |
| Lookup-side leaves | Selected product, `check_members`, then column claims |
| Weight column | `recursive_weight_claims` (`618-633`), claim batch, certified level-0 close, joined tail |
| Public column | Verifier evaluation (`1953-1961`) |
| Level-1 claim of each block | `verify_joined_tail` |

No claim is dropped or sent to another source. A claim reaches a segment's stack only from that segment or the next (`stele-ir/src/relation.rs:911-933`), and the stack closes after both.

### 3. Multiplicity path

- `eq_prefix_mle` is the multilinear extension of `eq(z, x)·[x < t]` [ran]. It agrees with the brute-force sum for every `t` at `k = 0..=8` (15,318 comparisons, Boolean points and per-coordinate linearity included). It also agrees with a masked table folded leading variable first at 10,000 random `(k, t, z, r)`, `k = 1..=10`.
- The final check uses it correctly [ran]: forging prover A is accepted, as it should be, and forging prover B is rejected with `EqMismatch` (F1).
- Offsets come from `checks[*].k` in the plan (`511-538`), with a stable sort and aligned blocks. No proof byte takes part [read].
- The one-layer fixture exercises the path honestly: three non-power-of-two tables unsegmented, five segmented [ran].

### 4. Profile byte and parameters

- The verifier dispatches on `public.sources`, read from the bundle magic or its `sources` byte. The byte is in the first transcript frame; the suffix encoding after `next` is unambiguous [read].
- With the container header restamped, a profile 6 proof under `CircleAll` rejects with `Commitment(ProofShape)`, and a segmented profile 3 proof under profile 6 rejects with `Engine(Recursive(ProofShape))` [ran].
- `segment_layers` is a field of the verifier's input, so whoever writes the bundle chooses it, as under A27. It is absorbed, the relation derives from it, and a proof for one value rejects under another (`Engine(ProofShape)`) [ran].
- Level and query counts come from `select_fresh_level0` (`107`), `select_certified_level0` (`152`) and `select_tail_levels` (`188`). The copies inside proofs are compared with the plan; a changed tail level byte or block count gives `ProofShape` [ran].

### 6. One-value differences [ran]

- Unit fixture: 13,528 single tampers, none accepted. That covers every byte of the sections up to 2,048 bytes, 912 positions in each larger one, and a one-byte truncation and extension of each of the 20 sections.
- Segmented one-layer proof: 532 single-bit tampers, at least one in each of its 382 sections, none accepted. No panic in either sweep.
- Five witnesses differing in one value (lookup value, carry, carried boundary, two identities): the plain checker rejects each. The prover aborts on four; on the lookup case it emits a proof the verifier rejects with `Fraction(RootMismatch)`.
- An honest proof against a verifier holding another model root rejects.

## Findings

### F1 — BLOCKING (INV-4): the Q51 mask binding has no control

- **Where:** check at `relation_recursive.rs:1565-1568`; the control named for it at `2205-2213`.
- **What happens [ran]:** the control flips the last byte of the lookup section, which is the multiplicity evaluation. The verifier rejects one line earlier with `Sumcheck(FinalEvaluationMismatch)`, inside the accepted pattern `Sumcheck(_) | EqMismatch | NoncanonicalField`. With the check deleted (deletion 1), both committed tests still pass, on both fixtures and both segment modes. The `stele-prover` test has no control for this binding at all.
- **Why it matters:** this line alone ties the prefix sumcheck to a verifier-known function. Without it the table-side numerators are not bound to the committed multiplicities.
- **Failing input, no prover seam:**
  1. Add a non-power-of-two table read only through an all-zero public selector, so its multiplicities are zero.
  2. Flip one bit of the first final value of its prefix sumcheck (byte `len - 32` of that lookup section).
  3. The verifier returns exactly `EqMismatch`. Under deletion 1 the same bytes reject later with `Fraction(Sumcheck(RoundSumMismatch))`, so an exact-match assertion detects the deletion.
- **Failing input, forging prover B:**
  1. Add +1 and −1 to the first two padded rows of `small5`'s multiplicities.
  2. Commit them in `mu_stack` and use them unmasked as right-tree numerators.
  3. Run the prefix sumcheck without zeroing `eq_pref[t..]`.
  4. The verifier returns `EqMismatch`; under deletion 1 it accepts.
- **Requested:** a control asserting `Error::EqMismatch` exactly, with an id reserved in `tests/negative-controls/catalog.md` and named in A29 item 5.

### F2 — BLOCKING (E19-04 acceptance, A29 item 5, INV-4): composed NC-0630, NC-0632 and NC-0635 are not exercised

| Label in the tests | Tamper | Catalogue reason | Unit test [ran] | `stele-prover` test [ran] |
|---|---|---|---|---|
| NC-0630/0631 | last byte of segment 0 witness opening | 0630 `ColumnMismatch`, 0631 `RootMismatch` | `Merkle(RootMismatch)` | same |
| NC-0632 | byte `len-16` of the tail | `ValueMismatch` or `ColumnMismatch` | `Merkle(RootMismatch)` | same |
| NC-0633 | tail shortened by one byte | `ProofShape` | `ProofShape` | same |
| NC-0634 | first byte of segment 0 claim batch | `RoundSumMismatch` | `RoundSumMismatch` | same |
| NC-0635 | certificate at another radius; certificate byte 0 | `CertificateContext` | not executed | `ProofShape` |

- **Where:** `relation_recursive.rs:2176-2203`, `2233-2258`; `crates/stele-prover/tests/development.rs:2759-2811`.
- **NC-0630 and NC-0632:** both tampers land in a Merkle sibling, so they repeat NC-0631. A flip inside `u_L` also ends in `RootMismatch`, because `u_L` is absorbed before the indices are drawn [ran]. No byte flip can reach these two reasons; the accept patterns are wide enough to hide it.
- **NC-0635, unit test:** the fixture's model plan has `certified_radius() = 1`, so `wrong_radius = 0` and the `if` at `2235` skips the control silently [ran].
- **Failing input:** narrow the matchers to the catalogue reasons, and replace the `if` at `2235` with an assertion. Both tests then fail.
- **Requested:** either an adversarial builder through the engine, as `build_joined` does at the PCS level, or labels and acceptance wording that say NC-0630 and NC-0632 are covered at the PCS level only. For NC-0635: a fixture weight large enough for `e_c >= 2`, no silent skip, and in the `stele-prover` test a certificate registered at another radius.

### F3 — MEDIUM (INV-4): the copied bindings have no control on this path

`verify_recursive` and `verify_for_stack` re-implement steps 2.3(a), 2.3(c), 2.4, the final claim checks and the lookup replay of `verify_segmented` and `lookup::verify`.

| k | Check removed | Line |
|---|---|---|
| 1 | prefix mask `EqMismatch` | `relation_recursive.rs:1565` |
| 2 | `LinearMismatch` | `1661` |
| 3 | matmul `EqMismatch` | `1622` |
| 4 | contraction `EqMismatch` | `1725` |
| 5 | pointwise `EqMismatch` | `1792` |
| 6 | leftover virtual claims | `1948` |
| 7 | public-column evaluation | `1956` |
| 8 | `check_table` | `relation_lookup.rs:731` |
| 9 | `check_roots` | `relation_lookup.rs:730` |
| 10 | `check_members` | `relation_lookup.rs:743` |

- **Result [ran]:** all ten deletions survive the committed controls, replayed with their own accept patterns, on the unit fixture and on the one-layer fixture in both segment modes. Deletions 3, 4 and 7 are exercised only by the one-layer fixture.
- **Consequence [ran]:** under deletion 9 the proof of a lookup of 5 in a table holding 0..4 is accepted.
- **Cause [read]:** the catalogue's development controls (NC-13xx) pick `Expander`, `Circle`, `CircleAll` or `CircleAllGrind` and use forging provers that exist only for the older engine.
- **Requested:** move the copied steps into functions both verifiers call, so the existing controls cover them, or run the catalogue's development controls under `Sources::CircleRecursive`. Needed at promotion at the latest.

### F4 — MEDIUM (INV-2, RFC-0012 A16): identity RLC ledger line

- **Where:** `relation_recursive.rs:1509-1516`.
- **What:** it records `n - 1`, and nothing when `n = 1`. A16 charges `n`; `relation.rs:3246` and `4805` record `n`.
- **Evidence [ran]:** on the unit fixture, segment 0 (one identity, one lambda drawn) has no RLC entry; segment 1 (two identities) has numerator 1.
- **Fix:** the two lines of `verify_segmented`.

### F5 — LOW: `openings` is not checked for a segment without a witness stack

- **Where:** `relation_recursive.rs:1811-1836` and `1841-1865` lack the `else` branches of `relation.rs:5070-5072` and `5102-5106`.
- **Evidence [ran]:** for a relation with one weight column and one range, a junk section appended to `segments[0].openings` is accepted.
- **Reach:** only a relation with no witness group, so not the development pipeline.

### F6 — LOW: specification and record gaps

- A29 does not define the step-1 model absorb (one `relation/roots` frame of source context and certificate id; A5 absorbs roots).
- A29 does not say what the multiplicity-layout fields of the lookup statement mean under profile 6. A version-1 layout from `mu_layout` (`relation.rs:849`) is still absorbed, though no such source exists.
- RFC-0029 §1.3 and §8, RFC-0019, `docs/plan.md` and `agents/context/architecture.md` still say multiplicity sources stay version 1 and Q51 is open.
- `tests/digests/development.json` pins bytes 3 and 5 only; profile 6 bytes are unpinned.
- ADR-154 says an L2a ledger is recorded in `bench/ledger/`; none is in the tree at this commit.

### F7 — LOW: test and API hygiene

- The unit fixture's comment (`1994`) names Contraction columns; the fixture has none, and no matmul or public column either.
- The committed mask test has 132 comparisons at six random point pairs; `agents/guardrails/soundness.md` asks for 10^4 random points.
- The profile-mismatch control is decided by the prover-written container header, not the engine.
- `eq_prefix_mle` is public and checks equal lengths only with `debug_assert_eq!`.
- The older engine entry points accept `Sources::CircleRecursive` and treat it as `CircleAll`; only `stele-prover` keeps it away from them.

## Review checklist

- **RFC section per public item:** A29 items 1–4; `eq_prefix_mle` is item 3; ledger helpers are RFC-0012 A20. The step-1 absorb has no text (F6).
- **Challenges and absorbs:** table above; RFC order; no new label.
- **Claims and consumers:** table above; same objects.
- **New bindings and controls:** F1, F2, F3.
- **Ledger:** new lines are the prefix SC, per-source batch RLC and SC, level-0 beta, tail gamma, SC and tensor, and registration. Identity RLC is wrong (F4). `soundness-accounting.sh` not run.
- **Bound certificate:** no new integer identity; counts stay below `2^30` by the existing `m <= 30` cap.
- **Padding and masks:** table padding is masked (forging provers A and B); no claim addresses stack padding; selectors unchanged.
- **Determinism:** no hash-map iteration, stable sorts; two proofs byte-identical on both fixtures [ran].
- **Parity:** no SIMD or CUDA code touched; not run.
- **Cost model:** `T_cuts`, `c_c`; no ledger in the commit (F6).
- **Verifier:** `no_std`; lengths from the plan except F5; no panic in 14,060 tampered verifications.
- **Glossary:** lint passes.
- **Tier:** development; `registry::publish` refuses profile 6.
- **Commit rule:** the only new committed object is the multiplicity stack, which is advice; no column made virtual.
- **Plain checker:** accepts the honest witness, rejects the five near misses [ran].
- **Segments:** `plan_recursive` validates first (`362`); NC-1335 not run under profile 6.
- **Proof bytes:** bytes 3 and 5 unchanged, four pinned digests reproduced [ran]; byte 6 is new under A29 and unpinned.
- **Ladder:** L0 fixture only; no before/after ledger pair.
- **Moved claims:** the multiplicity claim moves from RFC-0008 A5 prefix functionals on a version-1 source to a point claim on `mu_stack`, fixed before `(beta, alpha)`. Witness and weight claims move to fresh and certified level-0 closes.

## What I ran

- `cargo test -p stele-reductions --lib relation::recursive::`: 2 passed.
- `cargo test -p stele-prover --test development accepts_recursive_profile_6`: 1 passed.
- `dumps_development_digests`: four proofs equal `tests/digests/development.json` in length, FNV-1a and SHA-256.
- `cargo fmt --check` on the three crates; `rfc-status`, `docs-links`, `glossary-lint`, `rust-policy` gates: pass.
- Scratch drivers: the mask comparisons, plan and ledger dumps, exact rejection of every committed control, 38 further one-value tampers, both sweeps, the deletion survey, forging provers A and B, false-witness runs, the witness-free relation, both cross-profile directions.

## Not checked

- The PCS core, by instruction.
- A27 segmentation and `Layout::declare`.
- A `--release` build, the workspace suite, clippy, and the `native`, `negative-controls`, `soundness-accounting` and `digest` gate scripts.
- Thread-count independence.
- The L2a size claim.
- Byte 5 against byte 6; it has the same source structure as byte 3.
- Forging provers for the copied checks other than the false lookup.
- Deletions beyond the ten listed.

I tried to break it by committing multiplicities on the padded rows of a non-power-of-two table and running the Q51 sumcheck against the unmasked `eq` table, by proving a lookup of a value outside its table, by changing one committed witness, carried or weight value, by flipping single bits in every section of two proofs, and by offering a proof under another profile byte or segment size. The verifier rejected each (`EqMismatch`, `Fraction(RootMismatch)`, sumcheck and Merkle mismatches, `ProofShape`), but no control committed with this change rejects the first two for those reasons: the committed controls rejected only the Merkle-path, section-length and batch-round tampers (composed NC-0631, NC-0633, NC-0634).

## Resolution

Fixed in the change that carries this record, on top of the audited commit.

| Finding | Resolution |
|---|---|
| F1 | NC-0636 added. Catalogue row and registered control `pcs_recursive::nc_0636`, through `relation::verify_recursive`: a 3-row table read only under an all-zero selector, one bit of the `eq` final of its prefix sumcheck, `EqMismatch` exactly. The engine unit test runs the same control on the composed fixture. With the mask check removed the control fails. A29 item 5 names it. |
| F2 | The engine tests assert exact reasons and are labelled as what they run: NC-0631 (a level-0 close and the joined tail), NC-0633, NC-0634, NC-0635, NC-0636. NC-0635 is no longer skipped: the unit fixture has a 128-entry weight column (certified radius 15) and a certificate registered at radius 14 is `CertificateContext`; the `stele-prover` test changes the radius field of the registration certificate, also `CertificateContext`. NC-0630 and NC-0632 are stated as run on the joined recursion in `stele-pcs` (A29 item 5 and the catalogue note). |
| F3 | Not fixed here. A29 item 5 makes it a condition of promotion, and task `E19-10` (a dependency of `E21-09`) carries it: the NC-13xx development controls under profile byte 6, with a control that fails for each of the ten removed checks. |
| F4 | The identity RLC line charges `n`; the SC lines are those of `verify_segmented`. |
| F5 | A segment without a witness stack must have no opening section; `ProofShape` otherwise. |
| F6 | A29 item 5a defines the step-1 absorb and the lookup statement fields under byte 6. RFC-0029 A1 records Q51 for the development tier; RFC-0019, `docs/plan.md` and `agents/context/architecture.md` follow. `tests/digests/development.json` pins L0 and L1 under byte 6 (the digest gate checks six proofs). The L2a ledger is `bench/ledger/e19-04-dev-stories42m-t64-byte6-24t.json`, in the next commit of the branch. |
| F7 | Fixture comment corrected. The mask test adds 10^4 random `(k, t, z, r)`. `eq_prefix_mle` is crate-private. The planners of the older engine refuse `Sources::CircleRecursive`. The profile-mismatch control is unchanged: the container header decides first. |

## Re-audit

- **Commit:** `e85cae9b` (parent `0f1a932c`), branch `task/E19-04-joined-recursion`. The audited patch is `e3b0a864` there, with the same `git patch-id` as `b62e429e`.
- **Verdict:** **APPROVE** (development tier)

Both BLOCKING findings are resolved, and F4, F5 and F7 are fixed. F3 stays open under task `E19-10` as a promotion condition, which is what its MEDIUM rating asked for. F6 is fixed except for the L2a ledger. Five LOW items remain; R1 is a merge condition for the branch.

Evidence labels are as above: **[ran]** on `git archive e85cae9b` exports outside the repository, test profile; **[read]** otherwise. "Deletion k" and "forging prover B" are the instruments of the first audit, re-applied to `e85cae9b`.

### Findings of the first audit

| Finding | Status | Evidence |
|---|---|---|
| F1 | Resolved | NC-0636 passes, and fails when the mask check is removed [ran] |
| F2 | Resolved | Both tests return the exact reasons they assert; NC-0635 runs [ran] |
| F3 | Open, tracked | `E19-10`, a dependency of `E21-09`; A29 item 5 [read] |
| F4 | Resolved | Identity RLC numerators are 1 and 2 for one and two identities [ran] |
| F5 | Resolved | An extra opening section on a witness-free segment is `ProofShape` [ran] |
| F6 | Resolved except the ledger | Six digests reproduced [ran]; documents [read]; see R1 |
| F7 | Resolved | Older entry points return `Unsupported` for `CircleRecursive` [ran] |

F3 is unchanged in substance: deletions 2 to 10 are still unnoticed by both tests, and deletion 9 still accepts the false lookup [ran].

### 1. NC-0636 [ran]

- The registered control returns `Ok` with all features, as do NC-0630..0635.
- Against a verifier built without the mask check it returns `expected EqMismatch, got Err(Fraction(Sumcheck(RoundSumMismatch)))`. The committed unit test fails at its NC-0636 assertion on the same build.
- Against a verifier that compares with the unmasked closed form it returns `honest proof rejected: EqMismatch`.
- Of the 128 single-bit changes of the `eq` final, 124 give `EqMismatch` and four give `NoncanonicalField`. The control's bit is one of the 124.
- Forging prover B is still rejected with `EqMismatch`.
- `MASKED_SECTION = 0` is sound, and needs no change:
  - The plan puts tables before ranges in first-use order, so section 0 is `small3`.
  - A wrong index fails closed. The same flip in section 1 gives `Fraction(Sumcheck(FinalEvaluationMismatch))`, and that relation has no other source of `EqMismatch`.

### 2. Honest paths

- **[ran]** One-layer proofs under bytes 3, 5 and 6, with `segment_layers` 0 and 1, all verify.
- **[ran]** Eight-layer proofs under bytes 3, 5 and 6 verify (digest producer).
- **[ran]** The existing one-layer tests for the Expander set and byte 2, and the segmented test, pass.
- **[ran]** A witness-free relation verifies under byte 6. A small relation still verifies under `CircleAll` through the older engine.
- **[read]** Every byte 6 path in `crates/stele-prover/src/development.rs` returns before the older engine (`749-835` for proving, `1033-1065` for verifying). The zk and registry paths refuse byte 6 earlier.
- **[read]** An honest prover writes `openings` only inside the `witness_plan` branches (`relation_recursive.rs:1257-1304`), so the F5 check cannot reject it.

### 3. A29 items 5 and 5a [read]

They match the code: the step-1 frame, the lookup statement bytes, the multiplicity bundle, the opening-section rule and the ledger line. Three wording slips are listed under R3.

### 4. Regressions and unbound values [ran]

- 14,090 single tampers on the new composed fixture and 532 on the segmented one-layer proof: none accepted, no panic.
- The four digests of bytes 3 and 5 are unchanged, and the two byte 6 pins reproduce.
- Cross-profile rejections are unchanged, with the header restamped:
  - byte 6 under 3 or 5: `Commitment(ProofShape)`
  - byte 3 or 5 under 6: `Engine(Recursive(ProofShape))`
  - `segment_layers` flipped: `Engine(ProofShape)`
- The catalogue counts the harness asserts hold: 259 rows, 163 registered, 85 of 127 bindings, 96 missing.

### Remaining findings (all LOW)

- **R1 — L2a ledger.** ADR-154 (`agents/context/decision-log.md:4783`) and the F6 row of the Resolution table say it is recorded. `bench/` at `e85cae9b` has no byte 6 ledger. Land it or reword both before the branch merges (INV-14).
- **R2 — Resolution table, F2 row.** It gives certified radius 7 and a certificate at radius 6. The fixture's plan is `(ell 4, m 4, b 2)` with radius 15, and the control registers at 14 [ran]. The test code is generic; only the record is wrong.
- **R3 — A29 wording.**
  - Item 5 lists NC-0635 under "through `relation::verify_recursive`". `relation::verify_recursive_model` decides it before that call.
  - Item 5 says the NC-13xx controls run under bytes 3 and 5. Some run under byte 2 and the Expander set (`tests/negative-controls/src/development.rs:205`, `417-419`).
  - Item 5a says the layout fields "name no committed source". Check 0's layout id `(s << 16) + 3` equals the `mu_stack` id, though its `ell` and `blowup` do not describe it.
- **R4 — no test for the F5 check.** `relation_recursive.rs:1427-1435` is exercised only by my scratch run. Add a test or list it under `E19-10`.
- **R5 — misplaced doc line.** `tests/negative-controls/src/pcs_recursive.rs:803`: "Dispatch NC-0630..0635 …" now heads `nc_0636`, and `run` has none.

Two notes that are not findings:
- `relation::model_layout` and `model_layout_for` still answer for `Sources::CircleRecursive` with a version-1 layout [ran]. Nothing can prove or verify with it.
- The E19-04 acceptance line in `agents/tasks/graph.yaml` still reads "controls of E19-03 pass on the composed proof". A29 item 5 is now the text that says where NC-0630 and NC-0632 run.

### What I ran

- `cargo test -p stele-reductions --lib`: 189 passed, 1 ignored. `--test relation`: 21 passed, 5 ignored.
- `cargo test -p stele-prover --test development accepts_ -- --skip dev_zk --skip eight_layer --skip registry`: 11 passed.
- `dumps_development_digests`: six proofs equal `tests/digests/development.json`.
- `pcs_recursive::run` for 630 to 636 with `--all-features`.
- `cargo fmt --check` and `cargo clippy -- -D warnings` on `stele-reductions` (all targets), `stele-prover` (tests) and the `stele-negative-controls` lib: clean.
- `rfc-status`, `docs-links`, `glossary-lint`, `rust-policy`; the static `standard_quarantine` check; the static part of `field_sources`; the digest method of `scripts/tests/test_native_gate.py`: pass.
- Scratch drivers for everything marked [ran] above.

### Not checked

- The whole `stele-prover` development suite, and the negative-controls harness that executes all 163 controls.
- `native.sh`, `digest.sh`, `negative-controls.sh`, and a `--release` build.
- The cargo-driven part of `field_sources` and the other methods of `test_native_gate.py`.
- The L2a ledger and size claim.
- The later commits on `task/E22-10-capture-single-pass`.
- The PCS core, as before.

I tried to break it by removing the mask check, by swapping its closed form for the unmasked one, by aiming NC-0636 at the other lookup section, by replaying forging prover B, by adding an opening section to a witness-free segment, by sending `Sources::CircleRecursive` into the older planners, and by 14,622 single tampers of two proofs. Control NC-0636 failed on the first two as it should, the wrong section could not produce `EqMismatch`, and the verifier rejected the rest with `EqMismatch`, `ProofShape`, `Unsupported` and Merkle or sumcheck mismatches.

### After the re-audit

R1 to R5 are closed in the commits that follow `e85cae9b`: the L2a ledger is `bench/ledger/e19-04-dev-stories42m-t64-byte6-24t.json` (R1), the Resolution table gives radius 15 and 14 (R2), A29 items 5 and 5a are reworded (R3), the F5 check is an acceptance line of `E19-10` (R4), and the dispatch comment heads `run` (R5).
