# RFC-0010 A3/A6 acceptance review (certified openings, v2 sources, one element per value)

Reviewed: branch `rfc/RFC-0010-A3-A6-accept` on `origin/main` 96cf993. Companions:
RFC-0012 A15 and RFC-0007 A7. These are internal agent passes, not an external
cryptographic audit.

Reviewers:
- **Pass 1, soundness-auditor.** Same-author pass by the drafting agent. It checked
  error terms, theorem citations, proven or conjectural labels, Fiat–Shamir rounds,
  setup and every place a parameter could come from the prover.
- **Pass 2, rfc-author and pcs-engineer (stele-pcs owner).** Same-author pass by the
  drafting agent. It checked consistency with Accepted text, the glossary, the claim
  graph, task statuses and implementability against A9 and E4-03a.

Both passes are by the author. Neither is independent; an independent review of the
PR is still wanted, as for PR #293.

**Verdict: accept after fixes.** All blocking findings are closed on this branch.
No soundness gap remains in the interactive argument. No profile is admitted: under
the Fiat–Shamir hand derivation, Policy 1 fails both profiles, and that is recorded
for E4-05/E12-04 instead of hidden.

## Gap analysis of the Draft "acceptance still requires" lists

A3:

| Draft item | Closed by | Where |
|---|---|---|
| Native statement/proof bytes | A9 §§1-4 for Circle; version-2 source bytes for v2 differ only in version and code ID | A3 item 2 |
| Labels, order, unbiased sampling | A9 §7 and RFC-0012 A10, unchanged; v2 reuses the nine labels | A3 item 2, A15 |
| Canonical leaf interpretation | A8/A9 canonical M31 columns | A3 item 2 |
| Source/extraction | Unique near message of A8's frozen oracle; no extractor claimed, scope labelled | A3 item 6 |
| Multi-opening semantics | A9 separate executions plus the adopted adaptive-reuse union bound | A3 items 1, 6 |
| Arbitrary/batched modes | Arbitrary: A9 §4 on a certified source. Batched: §2's single-opening form withdrawn; batch/grouping protocols not admitted | A3 item 1 |
| Parameter policy | Policy 1: Circle tables (A9), v2 table (A3), both checked | A3 items 3-4 |
| Prover/verifier APIs | A9 API with version-2 sources | A3 item 2 |
| NC-0600/0601/0603/0605 | 0600/0601 done (A9). 0603 redefined by A6 for E4-03. 0605 stays with E4-04 | A3 item 9, A6 item 4 |
| Q12 | Still open; hand-derived rounds recorded | A3 item 7 |

A6:

| Draft item | Closed by | Where |
|---|---|---|
| 1. Layout bytes, decoding, comparison | One element per value, A9 layout 0; packed30 compared and rejected | A6 item 1 |
| 2. Decomposition/range reduction | None needed; whole-source range lookup with all-one selector | A6 item 2 |
| 3. Original B and RFC-0007 | Affine offset or identity; RFC-0007 A7 for §3; short columns stay A1 | A6 item 3, RFC-0007 A7 |
| 4. NC-0603/0605 | NC-0603 redefined against the actual byte-range verifier; NC-0605 E4-04 | A6 item 4 |

## Pass 1 — soundness-auditor

Parameter provenance, checked field by field:
- **Verifier-derived.** purpose, version, layout, policy (constants); N, C, D, e, q_c, q_o
  (from code ID and policy).
- **From the consuming statement.** K, tensor ID, ell, R, C and code ID come from the
  consuming RFC's statement. The root comes from the passport or a pre-challenge commitment.
- **From the proof.** Only t, u and column responses. No proof byte selects a parameter.

Theorems and labels:
- **Diamond–Posen Theorem 2.** Proven, for any linear code at e<=floor((D-1)/3).
- **Query and near-matrix lemmas.** Proven: tensor-opening.md §3,
  certified-functional-opening.md §2.
- **Distance.** Circle: proven and deterministic. v2: floor(k/25)+1, outside the A7 setup event.
- **Setup.** The A7 bound is proven in the ideal-oracle model for BLAKE3 setup
  expansion. That is a labelled assumption, not a conjecture. The bound covers all
  2^256 seeds at once, so a prover that picks or grinds its seed is covered.
- **Merkle.** A8's classical ideal-hash lemma.
- **Not used.** No Johnson-radius, list-decoding or capacity conjecture appears.

Findings:
- **P1 (blocking): the Draft text admits a certificate-free fresh-tensor mode, and §5
  says a fresh tensor needs no certificate.**
  - Problem: accepted as written, fused weight openings could skip the certificate.
    The fresh-tensor argument is sound per opening interactively. Under Fiat–Shamir its
    tensor round is re-rolled by grinding the inference input, and E4-03 does not need it.
  - Closed: A3 item 1 admits only the A9 certified opening, withdraws §5's claim and
    leaves the fresh-tensor mode for a new amendment (Q27).
- **P2 (blocking): the Fiat–Shamir margin of the query rounds.**
  - Problem: CertificateColumn and OpeningColumn each draw all q columns from one
    state. A cheating prover re-rolls them by changing t or u. Under RFC-0012 §4's
    charge of Q times the largest round error, Policy 1's 2^-130 gives 2^-30 at treaty
    (Q=2^100) and 2^-50 at standard (Q=2^80).
  - Closed: A3 item 7 states that Policy 1 cannot be admitted to either profile. It
    gives the least counts at 2^-228: Circle rate 1/4 q_c=550, q_o=228; rate 1/2
    867/390; v2 J=14 23627/11774. E4-05 gains an acceptance line for it.
  - check_expander_policy.py verifies all of these numbers.
- **P3 (blocking): the certificate tensor round under Fiat–Shamir.**
  - Problem: changing one leaf re-rolls CertificateWeight for about log2(N) hashes.
    The round error 2·ell·(e+1)/|K| times Q:
    - fails both profiles in QM31 for every ell>=1 (standard: at least 2^-43);
    - passes standard in OM31;
    - fails treaty in OM31 unless 2^229·ell·(e+1)<=p^8. ell·(e+1)=2^18 passes and 2^19
      fails. At ell=20 that already fails at J=14 (v2, about 2^-121) and at Circle 2^30
      rate 1/4 (about 2^-115).
  - Closed: recorded in A3 item 7, RFC-0012 A15, ADR-068 and E4-05's new criterion.
    Fixing it needs a changed certificate (for example independent repetitions) or a
    Q12 theorem. Both are E4-05/E12-04 decisions, not this amendment's.
- **P4: J=15 is outside the sampler.**
  - Problem: N=2^31 exceeds RFC-0012 A10's domain N<=2^30. The Draft's own example
    table used J=15.
  - Closed: item 2 rejects it as UnsupportedSource before any transcript work.
    NC-0613 is reserved.
- **P5: evidence substitution.**
  - Problem: source bytes carry no evidence ID. A future premise change could
    silently change D under an existing source.
  - Closed: item 3 makes policy byte 1 pin the three evidence IDs. A new premise
    needs a new policy byte, which changes the source bytes and certificate ID.
    NC-0612 includes the edited-registry variant.
- **P6: setup term composition.**
  - In the interactive model the verifier's coins are independent of the setup
    oracle, so the union of the setup event and the protocol failure is valid.
  - The A7 caveat about conditioning under Fiat–Shamir stays with Q12.
  - The term is charged once per ledger that contains a v2 source with J>=4.
- **P7: two embeddings for one source.**
  - Problem: the source context has no embedding field. A signed consumer and an
    offset consumer of the same root read integers that differ by 2^(w-1).
  - Closed: A6 requires one embedding per source context, fixed by the plan. E8-02
    gains the enforcing criterion.
- **P8: NC-0603 must target the range consumer.**
  - Problem: the PCS proves no width, so a decomposition-preserving tamper is
    correctly accepted by the PCS alone.
  - Closed: A6 item 4 runs NC-0603 through the actual RFC-0024 §1.1 byte-range
    verifier on an honestly certified tampered source.
- **P9 (non-blocking): small v2 sizes are inefficient.**
  - J=4 has D=11 of N=512, so q_c=11489.
  - This is a cost fact, not a soundness issue; item 10 records the counts.
- **P10: knowledge soundness.**
  - Item 6 states that soundness is relative to the unique near message. RFC-0016
    recursion must supply an extractor if it needs one.

## Pass 2 — rfc-author and pcs-engineer

- **S1 (blocking): RFC-0007 §3 says R_stack is "packed 2 per M31".**
  - Problem: that conflicts with A6, so the repository would have two laws.
  - Closed: RFC-0007 A7 (Accepted) replaces the parenthesis with one element per
    value under §2's signed embedding. RFC-0007 A1 stays Draft for the short-column
    fold and the full fused schedule.
- **S2 (blocking): §2's batched functional `a = Σ_t γ_t eq⊗eq` is not one rank-one
  opening when the b_t differ.**
  - Problem: it contradicts A9's separate-openings rule.
  - Closed: A3 item 1 withdraws it explicitly.
- **S3 (blocking): §6's RS Johnson-radius and standard capacity options.**
  - Problem: they would remain law next to the unique-decoding policy.
  - Closed: both are withdrawn in item 6.
- **S4: RFC-0012 §4's PCS row.**
  - Problem: `ε_gap+(1−δ)^q+ε_Merkle` conflicts with the exact terms, and it charges
    the Merkle lift as a PCS term.
  - Closed: RFC-0012 A15 replaces the row and moves Merkle to H. soundness-accounting.md
    follows.
- **S5: NC-0612 named `CodeIdentityMismatch`, which no Accepted error set has.**
  - Closed: refined to three variants with A9/A1 errors: CertificateContext,
    ColumnMismatch and InvalidRegistry.
- **S6: the Draft A6 replacement text proposed packed30.**
  - Closed: the resolution supersedes it. packed-commitments.md and fused-layout.md
    record what is adopted.
- **S7: per-proof certificates.**
  - Problem: making the certificate mandatory charges a certificate on every
    per-proof source.
  - Closed: item 10 says so. RFC-0023/0024 sources already pay this.
- **S8: the cost model.**
  - Closed: a new cost-model section records one element per value (non-wide int16
    cut messages double) and the v2 query counts. No constant is refitted.
- **S9: E4-03's title still says "packing int8/int16".**
  - Kept unchanged, with the original criteria. Under A6 the deliverable is the
    storage-to-message expansion under both embeddings.
  - Added criterion: NC-0613, an independent check of the v2 table against native
    values, and the A6 expansion.
- **S10: other "packed" wording.**
  - RFC-0011 §1 item 5 ("packed int8 weights") and RFC-0001 D4 ("raw packed weights")
    describe physical storage, which A6 keeps separate. No conflict.
  - RFC-0008 A1 stays Draft for a future packed format; RFC-0008 is not edited here.
- **S11: implementability against E4-03a.**
  - The native verifier must parse a 55-byte code ID and a per-J table, and call
    `Encoder::from_code_id` for v2.
  - The A1 adapter's fixed-length assumption becomes per-version.
  - No new label, error kind or crate dependency is needed.
- **Catalog.** 152 rows, 60/152 controls, 92 MISSING, 21/61 bindings unchanged.
  `cargo test -p stele-negative-controls --test catalog` passes.
- **Research inventory.** One stdlib command added to `algebra`: 182 commands, of
  which 181 inherited. The test counts and the inventory digests are updated.

## Concrete attacks the accepted text rejects

- **Decomposition-preserving byte tamper.**
  - The tamper: an offset int8 source with (x0,x1)=(5,3) becomes (261,2). The
    withdrawn packed word 5+256·3=773=261+256·2 is unchanged.
  - The PCS certificate and openings accept the tampered root, because they prove no
    width.
  - The byte-range lookup rejects, because 261 is not in range_8. That is NC-0603.
- **Base-only identity swap.**
  - The swap: v2 J=3 and Circle(6,1) encode the same map. A certificate verified for
    the Circle source is offered for the v2 source.
  - The source bytes differ in version and code ID, so the certificate IDs differ.
    The handle's context does not match, and the opening rejects with
    CertificateContext. That is NC-0612.
- **Unsupported size.** A v2 manifest with J=15 rejects before any transcript work
  (NC-0613).

## Evidence run on this branch

- `python3 research/merkle-oracle/check_expander_policy.py` passes. It checks:
  - 12 v2 pairs, each minimal at 2^-130;
  - J=15 outside the sampler;
  - the 2^-228 counts above;
  - every Fiat–Shamir comparison in A3 item 7.
- Four mutants of the checker were each killed: q_c(J=4)±1, q_o(J=14)-1, and D off
  by one.
- `python3 research/merkle-oracle/check_native_policy.py` still passes, unchanged.
- The catalog test passes.
- docs-links, glossary-lint and rfc-status pass. `scripts/ci_tests.py` results are in the PR.

## Not reviewed

- Q12's actual Fiat–Shamir/QROM theorem.
- RFC-0013 A1 privacy and A7 blinding.
- The RFC-0007 A1 fused schedule.
- Native code: none is changed by this PR.
