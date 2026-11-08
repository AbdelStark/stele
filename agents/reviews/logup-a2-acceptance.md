# RFC-0008 A2 / RFC-0012 A8 review (characteristic-safe lookups)

Reviewed: branch `rfc/RFC-0008-A2-accept` on `origin/main` 871f0e2.
These are internal agent passes, not an external cryptographic audit.

Reviewers:
- **Pass 1, soundness-auditor.** An independent reviewer agent that did not draft the
  text. It read A2, A3, A5, formal/native-lookup.md, formal/weighted-logup.md,
  formal/logup-characteristic.md, RFC-0012 A8/A11 and `stele-reductions/src/lookup.rs`.
- **Pass 2, rfc-author and gkr-reduction-author (stele-lookup/stele-reductions owner).**
  A same-author pass by the drafting agent, checking spec completeness and
  implementability against A5 and E3-07. It is not independent.
- **Pass 3, independent cryptography review** of PR #293 at 7a14484, by a reviewer outside
  this drafting session. Recorded under "Independent pass" below.

**Verdict: accept after fixes.** All fixes are applied in this branch. No soundness gap
was found in the interactive argument for A9-bound sources. A2 selects no new protocol.

## Gap analysis of the Draft's "Before acceptance" list

| Draft item | Closed by | Where |
|---|---|---|
| Full protocol | A5 grouped-unit mode, unchanged, as the only mode | A2 item 1 |
| Layouts, bytes, labels | A5 §3/§4 and RFC-0012 A11 (Accepted, implemented in E3-07b) | A2 item 1 |
| Static certificates | b=min(m,30), so each group has at most 2^30<p positions; N, b, sigma and r come from plan/profile | A2 item 2 |
| Selectors, poles | Verifier sigma, (0,1) neutral leaves, check_roots, abort without retry, honest pole at most r*t/\|K\| | A2 items 3, 6 |
| Tuple bound | c in {1,2}, t<=65536, (c-1)t compression term | A2 item 5 |
| GKR degrees, rounds | A5 §5 counts, all degree 3 | A2 item 7 |
| Source/table/committed consumers | A9 point openings for every column; mu prefix-mask openings | A2 item 4 |
| Privacy | Deferred to RFC-0013 A1; the A9 replacement interface is stated | A2 interfaces |
| Negative controls | NC-0400..0403 and NC-0415..0419 done in E3-07b; NC-0420/0421 reserved | A2 controls |

Selected mode: A5 is the smallest complete choice. Ordinary unit weight alone (m<=30)
cannot take one stacked instance at real shapes. Under the cost-model §3 projections,
Llama-3.1-8B gives 1.1–3.9·10^10 positions (N/p 5.1–18.2, m=34..36) and 405B up to
5.7·10^11 (m=40). Partitioning instead would add trees and multiplicity commitments per
part, and a new protocol. A5 is already Accepted and implemented natively.

## Pass 1 — soundness (independent)

Checked correct:
- 2^30 = 1073741824 < p.
- e_LU = (h+(c-1)t)/|K| + (N+t-1)/|K|.
- Honest pole bound r*t/|K|.
- Draw and round counts against A5 §5.
- Every real-shape number against cost-model §3, including log2 e_LU -84..-90 (QM31)
  and -208..-214 (OM31).

Failed attacks:
- p copies inside one group.
- Late mu.
- Shared units across repetitions.
- Selector flip (NC-0402).
- Table-tail mu.
- Zero or supplied roots.
- c=2 collisions.
- b=31 (NC-0415), r=1 under treaty (NC-0421) and a reused pair (NC-0403).
- h=0, which is Haböck's lemma with N<p.

Findings:
- **B1 (blocking): companion and ledger out of step.**
  - Problem: the reviewer saw an intermediate tree in which RFC-0012 A8, ADR-065, this
    record and the E3-07 status were not yet written.
  - Closed: A8 is Accepted with exact replacement text for the §4 LU row and an
    annotation of the §5 figures. The soundness-accounting LU row is replaced. ADR-065,
    this record and E3-07 `ready` are in the same change.
- **N1: e_LU^r is not a Fiat–Shamir bound.**
  - Problem: a concrete grinding attack exists at QM31, m=36, h=6.
    1. Choose group counts n_g = 2^popcount(g), so R(Y) = prod(1+Y_k).
    2. Grind the Statement through free source entries until some theta_k = -1, about
       2^120.4 hashes. Repetition 0 then passes identically.
    3. Grind free mu tail bytes for alpha_1, about 2^88 hashes.
  - The total is about 2^120 work, against the advertised interactive 2^-176. Item 6
    also misquoted INV-8.
  - Closed: A2 item 8 and A8 now say the r-th power is interactive only, that the
    non-interactive unit round costs about r*h/|K|, and that Q12 must not adopt e_LU^r.
    "Doubled at r=2" is removed. The first fix also said the treaty margin comes from
    OM31 and not from r=2; pass 3 (S1) showed that is wrong, and it is corrected. Item 6
    now states prover determinism and no resampling path. Profiles were never admitted
    by A2, so this narrows a claim and leaves the protocol unchanged.
- **N2: source ownership.**
  - Problem: a separately committed valid (in', out') pair satisfies the lookup while
    downstream consumes another out.
  - Closed: an Ownership interface item now says certificate identity with the
    producer and consumer is RFC-0005/E5 work. Values at positions with sigma=0 must not
    be relied on. A5 §1 already disclaimed CQIS ownership.
- **N3: real shapes are not runnable.**
  - Problem: committed columns, N selector bytes in the Statement and O(N) verifier
    scratch.
  - Closed: the real-shape paragraph and the cost line now say so. They name the
    missing producer, virtual-column amendment and succinct selector. The ADR repeats it.
- **N4: the weighted path cannot be tested at practical sizes.**
  - Problem: under b=min(m,30), plan lookups only reach h>0 at m=31.
  - Closed: stated in A2. Positive tests of h>0 remain A5 primitive tests, which plans
    may not use.
- **N5: "charged once per repetition" was imprecise.**
  - Closed: changed to "charged as A5 §5 lists, never squared".

## Pass 2 — spec completeness and implementability

- **S1 (blocking, fixed): contradictions with A5.**
  - Problem: three sentences of Accepted §2/§6 contradicted A5:
    - "virtual → further reductions";
    - multiplicities "once per table";
    - one batched opening for both pairs.
  - Fix: A2 item 4 and item 8 now withdraw each one explicitly. Otherwise E3-07 would
    face two incompatible laws.
- **S2 (blocking, fixed): virtual tuple columns.**
  - Problem: A5's theorem (weighted-logup.md §1) fixes "authenticated ordered source
    tuples" before the Unit draws. No Accepted producer fixes an uncommitted column.
  - Two claims about one uncommitted tensor at different points have no common oracle.
    A matmul claim and a SelectedProduct claim on out are an example.
  - Fix: A2 item 4 admits only A9-bound columns. The open item is recorded in Q31.
    E3-07's criteria do not need virtual columns.
- **S3 (fixed): b was unspecified.**
  - Problem: A5 allows any b<=min(m,30). A prover-visible choice would break
    determinism and allow mode substitution.
  - Fix: b=min(m,30), as weighted-logup.md §1 proposed, and r follows the profile.
    Plan admission rejects other values (NC-0420 GroupBound, NC-0421 Statement), before
    any transcript work. A5's own descriptor range is unchanged, so E3-07b's b=0/b=m
    tests remain valid.
- **S4 (fixed): NC-0420 sizing.**
  - Problem: NC-0420 first used m=31, which implies a 2^31-entry selector shape.
  - Fix: changed to m=3, b=2, which is the ordinary-to-grouped substitution at a cheap
    shape.
- **S5 (checked): catalog snapshot.**
  - The catalog grows from 146 to 148 rows, with 55/148 controls, 93 MISSING and 21/61
    bindings unchanged.
  - The `lookups` binding already exists. `cargo test -p stele-negative-controls --test
    catalog` passes.
- **S6 (checked): no new label, challenge or registry entry.**
  - The transcript-label JSON, the accounting gate inputs and the cost-model constants
    are untouched. No pinned digest covers the edited documents. No research script was
    edited, so the bench ledgers that pin check_characteristic.py still match.

## Independent pass

Verdict at 7a14484: fix, then merge. No forgery was found against the interactive
argument. Each finding was closed on this branch as follows.

- **S1 (significant): "the treaty margin comes from OM31, not from r=2" was wrong.**
  - Problem: all r Unit vectors come from one transcript state, and all r (Beta, Alpha)
    pairs from another. Under RFC-0012 §4's charge Q times the largest round error, with
    treaty Q=2^100 and target 2^-128:
    - r=1 on OM31 gives about 2^-108 at m=40 and 2^-114 at m=34, and fails;
    - r=2 gives about 2^-144 and passes.
    The text also credited both grinding routes to the unit round. Grinding the
    multiplicity tails re-rolls the pair round instead.
  - Recomputed: unit round Q*r*h/|K| and pair round Q*e_LU^r for d=4/8, m=34/36/40,
    Q=2^80/2^100. The results match the reviewer's: OM31 with r=1 gives a pair round of
    -108 to -114; OM31 with r=2 gives a unit round of -143.7 to -145.
  - Closed: A2 item 8, RFC-0012 A8 and ADR-065 now give the round-by-round split. The
    unit round is about r*h/|K| and is re-rolled by grinding the Statement. The pair round
    is about e_LU^r and is re-rolled by grinding free multiplicity bytes; one state cannot
    be split across repetitions. All three state that treaty requires r=2 and OM31, and
    label the split a hand derivation for Q12.
  - Also observed: under the same charge, standard QM31 at r=1 with Q=2^80 fails at real
    shapes (pair round about 2^-10). A2 now says no standard-profile Fiat–Shamir bound is
    claimed; E12-02 and Q12 own it.
- **S2: d was not derived from the profile.**
  - Problem: a treaty plan with d=4 and r=2 passed admission, and its unit round is about
    2^-20.
  - Closed: A2 item 2 derives d=4 for standard and d=8 for treaty. Any other value rejects
    with Statement. NC-0422 is reserved for that rejection.
- **S3: incomplete plan-to-Statement mapping.**
  - Closed: A2 item 2 says every other field comes from the consuming operation's Accepted
    RFC (RFC-0023 §2.3, RFC-0024 §§1.1, 2.3). The fields are the lookup id, multiplicity
    ids and layouts, source order and certificates, and the Table.
  - A consumer without such an RFC is not admitted. E3-07's admission criterion names
    RFC-0023/0024 consumers only. Both RFCs already use min(total_bits,30).
- **S4: virtual columns conflict with the attention and SiLU designs.**
  - Closed: E7-05, E7-06 and E7-07 are added to A2's affected tasks. Their graph statuses
    gain "RFC-0008 Q31 virtual-column amendment" and keep their existing blockers.
- **M1.** A2 item 1 now withdraws §1's "virtual or committed" tuples and F-valued m. It
  also withdraws §2's stacking of all instances of one table.
- **M2.** NC-0423 is reserved: m one above the least covering power of two rejects with
  Statement. NC-0424 is reserved: one padded position marked selected rejects with
  Statement.
- **M3.** Adoption lines with proven/conjectural labels are added to the four formal
  notes. No digest pins them; only Markdown links reference them.
- **M4.** The reviewer list states that pass 2 was same-author and that pass 3 is
  independent.
- **Catalog.** 151 rows, 55/151 controls, 96 MISSING, 21/61 bindings unchanged.

## Concrete forgery the accepted text rejects

The p-copy instance: p selected copies of 2 against table {0}, with mu=0.
- **Ordinary formula.** It accepts, because the numerator is 0 (check_characteristic.py:
  33 collapses).
- **Under A2.** m=31 forces b=30. The copies split into groups with counts c_0=2^30 and
  c_1=p-2^30=2^30-1, both nonzero mod p.
  - The residue is R(theta) = c_0(1-theta)+c_1*theta = 2^30-theta.
  - Its only root is theta=2^30, so it vanishes with probability 1/|K|. This was checked
    in Python over M31.
- **Descriptor b=31.** Rejected with GroupBound by the done NC-0415.

## Evidence run on this branch

- `check_characteristic.py`, `check_units.py` and `check_lookup.py` pass:
  - 96 QM31/OM31 complete lookups;
  - 258 limb-view identities;
  - 528 subset cases and 3618 challenge points.
- `cargo test -p stele-reductions lookup` passes.
- The catalog test passes.
- docs-links, glossary-lint and rfc-status pass.
- `scripts/ci_tests.py` passes, except a local-only missing `cargo-deny`; CI installs it.

## Not reviewed

- A3/A9 internal losses beyond A5 §5.
- The RFC-0013 A1 contents.
- A Fiat–Shamir composition (Q12).
