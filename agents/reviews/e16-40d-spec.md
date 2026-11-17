# E16-40d — owning lane V GPU/spec review

Reviewed PR 399 at fixed base
`6abc98cb836a504064811d6f34ba0fe175213116` and implementation head
`9aecca0b8936dc978cb6944c3beecd9be37641cb`, using `cuda-kernel-author`,
Workflows 03/06/09/12 and the task's RFC sections.

**PASS for the research harness implementation's specification scope; no
blocking finding.** This is not completion of E16-40d, hardware parity approval,
backend promotion or permission to merge without the remaining gates.

The exporter accounts for the complete merged inventory; the Rust parser rejects
empty/incomplete records and unsupported or malformed geometry. Ordered mask
events, simultaneous events, the first round and preceding unmasked rounds
survive reduction. The fixed 1,000-case schedule covers all 64 shapes in base,
extension and mixed storage with distinct odd seeds and canonical edge values.
Each device case compares initial tables, every requested round node and every
post-fold table against production `Masked`. Errors cannot reach the success
marker. A fresh context and all NVRTC preparation/cache misses lie within the
campaign timer, as do synthetic preparation, reference work and transfers.

The experiment honestly qualifies structural evaluation/fold code paths. Its
original degree selects the requested nodes; arbitrary synthetic factors do not
establish the production degree theorem. Original and reduced exponents remain
distinct. Compact finals, actual-size factor construction, raw lazy limbs,
full-proof parity and a complete device budget are explicitly excluded.

Outstanding evidence follows the task's exact requirement: “run exactly 1000
seeded complete round/fold comparisons on an H100” (`graph.yaml`, E16-40d).
The documented “one CPU campaign and one H100 campaign before reporting” and
validated ledger, matching campaign receipts, source/inventory/host provenance
and complete process accounting remain required. ADR-127 stays NO-GO. Workflow
12 requires “Take `main` in before you ask for a merge”: PR 396 CI 953 is the
designated full-suite run, not evidence for this head or a subsequent merge tree.
Current-base mandatory gates and the separate other-lane review remain merge
requirements.

Workflow 03 checklist:

- [x] Public items: `Inventory`, `Case`, parsing/case generation and the example implement research qualification under RFC-0014 §5/§6; their inputs describe RFC-0013 A5 item 3 and RFC-0008 A7 item 4. No production interface changes.
- [x] Challenges: none added to any transcript. Existing deterministic synthetic `challenge(round)` is only a parity input; no proof challenge or witness seed is imported.
- [x] Claims: no protocol claims emitted or moved. Returned tables and node values feed direct equality comparisons; production claim consumers are unchanged.
- [x] Bindings: none added; no new NC required. Malformed count/index/field and disabled-binding controls reject; absent-driver and empty-inventory commands fail without a success marker.
- [ ] Ledger: no soundness-accounting line changes by inspection. Full native/accounting gates and the hardware evidence ledger remain outstanding.
- [x] Bounds: production static certificates are unchanged. Harness size bounds fail explicitly; synthetic node comparisons do not validate formal degree bounds.
- [x] Padding/masks: factor/term order is retained; sorted retained coordinates preserve simultaneous and ordered vanishing events. Generated mask tables omit their vanishing coordinate. Production padding, selectors and compact-final expansion are not reconstructed.
- [x] Determinism: seeds, shape order, representation rotation and challenges are fixed. Hash sets are used only for duplicate membership, never iteration order. Reference repeatability tests pass.
- [ ] Parity: comparison logic covers canonical initial/folded table entries and all round nodes. Actual H100 execution is pending; CPU tests and missing-driver rejection do not establish GPU parity. Lazy-range and prover-level gates receive no credit.
- [x] Cost model: `c_sc` implementation coverage and cold compilation risk only; no measured constant, speedup, source pass or scoreboard cell is claimed. RFC-0014 A1 device-budget obligations remain open.
- [x] Verifier: untouched; no new verifier dependency, panic or proof-selected parameter.
- [x] Glossary: no forbidden synonym introduced.
- [x] Tier: bounded research/development qualification; no security, privacy, standard/treaty admission or GO claim.
- [x] Commit rule: no committed or virtual columns added or changed.
- [x] Plain checker: independently ran the four `stele-ir` lookup tests, including honest unselected rows and one-value selected/ordinary lookup rejection; all pass.
- [x] Segments: no relation or carried-column access changes.
- [x] Proof bytes: production algorithms, kernels, transcript and serialization are unchanged by this diff. Digest gate remains a merge requirement, not a result of this review.
- [ ] Ladder: no new rung/performance claim. L0/L1, workspace/native and applicable parity gates must cover current `main` and the intended merge tree; this review did not run the full suites.

Independent evidence: three Python exporter tests, four Rust inventory tests,
four targeted plain-checker lookup tests, command-level absent-driver and
empty-inventory rejection, and `git diff --check` pass. Reported author red/green,
Clippy/fmt/docs and default-research checks are supplemental, not independently
repeated here. No CPU/H100 campaign was consumed by this review.

I tried to break it by omitting records, changing a mask/term index and removing
the CUDA driver, and the controls `rejects_incomplete_or_malformed_inventory`
and the failing `check` command rejected it. I also changed one lookup value;
`rejects_lookup_tamper` rejected it with `Violation::Lookup`.

Skipped full suites and hardware execution as assigned; remaining risk is
unqualified generated-kernel compilation/allocation/parity on the H100.

## Numeric canonicality follow-up

Reviewed `bd4bd5b1..8038e131e93d59c08328c7c94a979f3c551058e1` independently.
**PASS for this parser fix; no new finding.** E16-40d requires “validate the
complete nonempty inventory, refuse unsupported fields, malformed terms, masks
and counts.” Rejecting leading zeros in the shared `number()` parser closes the
numeric-alias route around string-based duplicate detection. All its callers
(declared count, variables, degree, mask coordinates and term indices) receive
the same validation. Canonical `0` remains accepted where the caller permits it;
empty/non-ASCII/signed strings and overflow retain their rejection behavior.
Generated cases, CUDA kernels and production code are unchanged.

Independently reran all four Rust inventory tests and the fixed-diff whitespace
check; both pass. I tried to break it by replacing `vars=28` with `vars=028`, and
the control `rejects_incomplete_or_malformed_inventory` rejected it. The previous
Workflow 03 checklist and research-only approval limits otherwise stand.

The coordinator reports job 6630 was cancelled before allocation with zero
elapsed time and no assigned node. It supplies no campaign or parity evidence;
H100 execution, matching CPU/device receipts, validated ledger and current-main
merge gates remain pending. No campaign was executed by this reviewer.

Skipped full suites and hardware execution; H100 compilation, allocation and
parity remain unqualified by this follow-up.
