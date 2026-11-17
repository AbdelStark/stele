# E16-10b0 independent specification review

Reviewer: `root_control_spec_review`, lane C; repository `soundness-auditor` and
`rfc-author` skills. Fixed base: `aa42a55fcccb681c3e5f41c69345a1e628ec05e6`.
Inspected head: `5c8694f6b23e27f63a369dd2817962098243c660`, including the complete
three-dot diff from that base and the follow-up to `6f71c82bd591ad4b23cc99d26d2462553d0a6a32`.

**Decision: APPROVE** A17 as a development-tier erratum under Workflow 02 item 4.
No open findings, scope creep, weakened predicate, production change or new
executed-control credit. Policy 1 retains its exact Merkle error; Policy 2 requires
the exact nested grinding error on declared fixtures (RFC-0026:2251–2264).

Resolved finding: the original “before any Merkle-path check” was too broad.
Accepted A15 §6.4 verifies model certificates before the stacked certificate
(RFC-0026:1652–1663). The final text correctly limits precedence to the substituted
stacked-source certificate (2258–2259), and explicitly cites **RFC-0010** A14.
That contract checks grinding before column draws (RFC-0010:1037–1050,1077–1080);
the root enters the certificate transcript before randomness
(`formal/native-field-pcs.md`:94–108). Existing authentication remains mandatory.

Independently reran the supplied `stele verify-dev` binary on both recorded L0/L1
byte-5 public fixtures: honest proofs returned `YES`/exit 0; mutations returned
`NO: Engine(Pcs(Transcript(GrindMismatch)))`/exit 1. Parsed section lengths,
matched all four recorded SHA-256 values, verified that only bytes 90–121 were
replaced by the first multiplicity root, and restored complete byte equality.
Original files were read only. This qualifies precedence, not Policy 1, byte 3,
Merkle-path rejection, or catalog execution.

I tried to break it by substituting the first multiplicity root for the stacked
root, and the control experiment rejected it with the exact nested
`GrindMismatch` on both byte-5 fixtures. NC-1306 remains `todo`.

Acceptance bookkeeping remains with the author: RFC index, ADR, task dependency
and catalog/snapshot updates plus the required catalog test. E16-10b owns actual
composed-control execution. This signoff grants no profile admission.

## Required checklist

- [x] Public items: no API; exact NC-1306 contract, RFC-0026 A17.
- [x] Challenges: unchanged; root-bound construction, optional tensor grind,
  CertificateWeight, CertificateRow absorb, column grind, CertificateColumn.
- [x] Claims/consumers: none new or moved; existing openings unchanged.
- [x] Bindings/controls: no new binding; NC-1306 expectation only, still unregistered.
- [x] Ledger: no changed lines; did not rerun soundness-accounting.
- [x] Bound certificates: no new instances or changed static bounds.
- [x] Padding/masks: unchanged; no relation change.
- [x] Determinism: unchanged algorithms; declared fixtures required.
- [x] Parity: no backend changes; parity gate not rerun.
- [x] Cost model: no term moves or performance claim; no new ledger required.
- [x] Verifier: unchanged `no_std`, panic and plan-length behavior.
- [x] Glossary: checked; added-line forbidden-pattern search found no match.
- [x] Tier: development only; no security-level or promotion claim.
- [x] Commit rule: no committed or virtual columns changed.
- [x] Plain checker: 27 relation tests passed via existing
  `/tmp/stele-codex-e8-02f3c/target/debug/deps/stele_ir-07399959bc34638b`
  with `relation::tests:: --nocapture`; no rebuild claimed.
- [x] Segments: no changed relation or cross-segment read.
- [x] Proof bytes: honest encoding unchanged; adversarial root-only change checked.
- [x] Ladder: existing byte-5 L0/L1 artifacts verified; no new proof generation,
  benchmark or before/after ledger pair. Fixed-base diff check passed.

Skipped duplicate workspace/native/parity gates and final merge-tree validation;
the author owns them. Risk: Policy 1, byte 3 and composed NC-1306 execution remain
unverified here and receive no coverage credit.
