# Independent Soundness Audit — `E19-01` (RFC-0029 Policy 3 parameters & companion amendments)

- **Task / Lane:** `E19-01` · Lane C (PCS)
- **Reviewer:** Independent `soundness-auditor` (Workflow 03, subagent `92507d93`)
- **Reviewed commits:** `42755836` (`FIX-THEN-MERGE`), re-audited at `5c17278f` (`APPROVE`, base `dd795477`)
- **Governing specs:** `RFC-0029` §§1–9, `RFC-0010` A2/A3/A17, `RFC-0012` A10/A20, `RFC-0030` §3, `RFC-0027` §2

## Findings Resolved Before Approval

1. **`m + b <= 30` M31 domain ceiling (RFC-0010 A2, RFC-0012 A10):** Enforced `MAX_DOMAIN_BITS = 30` in `circle_params`, all DP loops, `_assert_plan_domains_valid`, unit tests, `PINNED_RECEIPTS`, `REPORT.md`, and `RFC-0010 A17` item 1.
2. **Certified level-0 unconditional `2·ell·(e_c + 1) <= cap` (RFC-0029 §1.3, RFC-0010 A9):** Removed `per_round` from level 0 of `minimise_certified_weight_opening` (single-round registration certificate always pays `2·ell·(e_c + 1)`), added exact cap-boundary candidate, and updated `REPORT.md §4` & `ADR-151`.
3. **Faithful multi-segment level-1 joining (RFC-0029 §2 "Segments"):** Replaced `level0_blocks` with `minimise_segmented_proof` modeling `k` independent level-0 segments joining as `k` row blocks at level 1 (`blocks = k`, `k` Merkle paths per level-1 query), recording Q44 evidence in `REPORT.md §4`.
4. **Normative spec consistency:** Reconciled `RFC-0029` §§1.1–1.4, 2, 6, 8, 9 to source version `u8(4)`, defined canonical ASCII `code_id = stele/circle-coeff-m31/v1 || u8(m) || u8(b)` + reserved §7 `u16` ZK fields in `RFC-0010 A17` item 1, and restricted `policy = u8(3)` to version-4 sources (preserving `NC-0613`).
5. **Strong Fiat–Shamir absorb order (RFC-0012 §2, RFC-0030 §1.2):** Documented absorbing clear `u_L` under `pcs/level-root` before drawing the final level's `opening-column` queries, absorbing queried column payloads under `pcs/opening-columns` before drawing `pcs/level-beta`, reused A1/A10 labels, and `C_i = 1 => D_i = N_i` in `RFC-0029 §2` and `RFC-0012 A20`.
6. **Exact `Fraction` cap checks, `1 <= e_c <= e_max`, clear-`u_L` `emit_root = False`, and transparent Bet B3 reporting** (`b >= 2` strict QM31 `8,388,256 B`, `b = 1` strict QM31 `3,810,608 B < 8 MB`, Q50 `0.950–1.570 MiB`), plus `RFC-0030-security-accounting.md` link fix.

## Verdict

**APPROVED** (`APPROVE`) for development-tier merge (`E19-01`). No `standard` or `treaty` admission is granted here (Workflow 10).
