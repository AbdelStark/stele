# Native exponential generator review (E5-02)

Reviewer: codex-root, also author. Same-author cqis-numerics and soundness-auditor
passes; not independent audit. RFC-0021 §§2.1,3,4,6 / RFC-0004 A4.

Workflow 03 checklist:
- Public items: complete high/low/direct/correction table generation. Exact
  natural arithmetic and interval helpers are private, with no table-truth hook.
- Challenges: none; ordinary TableId hashing is unchanged.
- Claims/consumers: deterministic public integer tables only. No configuration,
  membership, original-claim, passport or proof acceptance follows.
- Bindings: ordinary primitive rejection tests; no new claim-graph edge or catalog
  credit. NC-0412/0413/0414 remain pending actual consumers.
- Ledger: no loss/label/profile change. Uniform exp/correction bounds remain the
  proved RFC-0021 §5 statements, not a maximum inferred from these samples.
- Bounds: current rational denominators need <=512*(39+9) bits, plus at most 269
  scaling bits; scratch cap is 2^18 bits. Limb products plus stored limb/carry fit
  u64 exactly. This is generator arithmetic, not a field-faithfulness certificate.
- Padding: all inclusive endpoints and complete correction rows are generated;
  padding stays zero. Valid-row proof selectors remain separate obligations.
- Determinism: exact common-denominator Taylor recurrence, identical rational
  stopping condition, outward dyadic squaring and fixed 32/64/128/256 schedule.
- Parity: 10,000 entries match both exact Python methods; complete four-component
  data digests match. All precision levels, maximum shapes and the full B14
  correction distribution pass. Wider arithmetic matches 72 Python vectors and
  10,000 u128 cases, including multi-limb carries and capacity boundaries.
- Cost: all correction component generation/storage and exact scratch work remain
  T_misc; no measurements, fitted constant, weight pass or new commitment.
- Verifier: no_std/no unsafe/no floats. All integer buffers reserve fallibly,
  borrowed operands remain unchanged on failure, and incomplete tables are dropped.
  No external big-integer dependency or test-only verifier bypass is introduced.
- Glossary: component data is not full function/configuration or proof authority.

Tests preceded both arithmetic and table APIs. I tried to break it by carrying
across every limb, overflowing capacity, dividing by zero, changing table rows,
and selecting unsupported precision/domain values, and the control checks in
the native primitive tests rejected those inputs. These tests earn no NC credit.
Activation/GeLU generation, native function/manifest bytes, NumPy/MLE parity and
all actual lookup/private PCS/ZK/inference obligations remain required.
