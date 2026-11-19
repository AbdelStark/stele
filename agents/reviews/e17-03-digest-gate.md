# Review record — Task E17-03 (real digest gate and required CI L0 smoke)

- **Task:** `E17-03` (Lane B · RFC-0020 §5, RFC-0027 §7)
- **Branch:** `task/E17-03-digest-gate-l0-ci`
- **Tier:** Development (T0; no protocol behavior changed, digest gate and CI wiring only)

## 1. Lane P (protocol & prover crate) independent review

- **Initial review:** **REQUEST CHANGES** (F1–F4).
  - **F1:** `_verify_accepted_amendment` scanned the full RFC for `Status:` instead of the RFC preamble and lacked word boundaries on `Accepted`.
  - **F2:** Heading/bullet amendment matchers needed fenced-code-block stripping, scoping to the unique `## Amendment log` section, exact heading/bullet ID matching, combined heading+bullet uniqueness, immediate `Accepted` after closing `**`, and Draft-subsection rejection for bullet entries.
  - **F3:** Missing synthetic RFC negative tests for the `_verify_accepted_amendment` edge cases in `scripts/tests/test_native_gate.py`.
  - **F4 (minor):** Loose type checking on tuple-key fields (`t`, `profile_byte`, `rung`, `case`, `sources`) before constructing the `spec` key in `development_digests`.
- **Second review:** **REQUEST CHANGES** (F5).
  - **F5:** Greedy `[^\n]*\*\*` in the bullet-amendment matcher could skip past a Draft status to a later bold span on the same line, and `^##\s` preamble termination allowed an early `###` heading to leak into the preamble.
- **Final re-review:** **APPROVE**.
  - **F1–F5 resolved:** Added `_strip_fenced_blocks` (fail-closed on unclosed fences), terminated RFC preamble at `^#{2,6}\s`, required exact preamble `Status: Accepted\b`, scoped lookup to the unique `## Amendment log` section, used non-greedy bullet matching `^- \*\*A{n}\s+[—–-][^\n]*?\*\*(.*)$` with immediate `Accepted\b` and Draft-subsection rejection, validated exact types before building `spec`, and added 14 synthetic RFC + loose-type negative tests in `scripts/tests/test_native_gate.py`.
  - **Independently verified:** `scripts/gates/digest.sh` proves and verifies all four L0 (`one-layer`, T=16) and L1 (`eight-layer`, T=64) development proofs (RFC-0026 A12 byte 3 and A14 byte 5), independently checks length, FNV-1a-64, and SHA-256 against `tests/digests/development.json`, enforces Accepted RFC amendment references, removes the `stele-prover` and `stele-proof` exact-surface scaffold allowlists, adds the required `INV-15` L0 prove-and-verify smoke check in `.github/workflows/ci.yml` (`scripts/tests/test_ci_readiness.py`), and preserves all control, accounting, and parity gates.
