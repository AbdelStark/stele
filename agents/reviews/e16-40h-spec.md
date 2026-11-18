# E16-40h Spec/soundness review — lane E

**PASS, code review only.** Reviewed
`8b70d341692db8e8fc06aec6a1b59b79ac03b5d5...87cae62494ebbb9337954fe60003eebbce563c75`
(claim `4f5ad86b`, implementation `87cae624`). No implementation or scope findings.

The widened arithmetic is correct for `[0,2p)`: the product fits `u64`, and
the final folds are at most `p+4 < 2p`. Canonicalization therefore needs one
subtraction. QM31 arithmetic preserves RFC-0003 §2's tower and limb order.

Independently ran the million-case host test successfully. It compiles the
actual CUDA helper prefix and compares every returned word with actual
`stele-field`. Restoring the base helper prefix reproduced the old add,
multiply and stored-`p` failures; the reviewed head returns the expected values.

The device launch has adequate `8*count` input and `28*count` output
allocations, bounded indexing, disjoint output slices, and synchronization
before verification. Its safety comment covers these invariants.

Workflow 03 checklist: no new production API, challenge, absorb, claim,
binding, accounting line, certificate, padding, mask, verifier dependency,
committed column or segment behavior. Static field bounds checked; seeded
fixtures and fixed reduction order preserve determinism. No glossary issue
or tier promotion. Plain relation checker untouched. Production proof paths
unchanged by inspection; digest/accounting gates were not rerun. No measured
cost-model or ladder claim.

Acceptance remains partial: the task requires "required H100 parity evidence
and mandatory gates in stack order before merge." The H100 primitive test
and existing canonical masked-round/source comparisons still need completed
receipts. Host-expression parity does not establish device or full-proof parity.

Skipped hardware and full workspace/native/parity suites as instructed.
This PASS does not authorize merge or establish hardware qualification.
