FIX — independent benchmark Spec review, E16-40f importer.

Reviewed the complete added files against AGENTS.md, benchmark-runner, Workflows 04/09, RFC-0018/A1/A2, and E16-40f acceptance. Eight supplied Python 3.12 tests pass. Synthetic probes found four gaps:

1. `package.py:72–106` ignores `started_utc` and never checks execution order or overlap. Resealed receipts with invalid timestamps still produce six records. Thus lines 128–132 assert alternating cold pairs and checks-before-measurement without rechecking them. E16-40f acceptance (`/tmp/stele-codex-e16-40f/agents/tasks/graph.yaml:5280–5281`) requires both. Parse timestamps, require sequential completion, and check the capture order, including candidate-before-baseline in pair 2; add rejection controls.

2. `package.py:97–105` checks pair roots but does not link the ell11/m16 seed-1 production check to pair 1. Changing both check roots to another matching value, updating parsed evidence and resealing still emits six records with different measured roots. Compare those identical-input roots. Basis: AGENTS.md INV-8 and task acceptance lines 5279–5281; Workflow 09 line 13.

3. `package.py:107,124` sets `plan_digest` to the raw evidence-manifest hash. RFC-0018 lines 6–8 requires a plan digest; `bench/README.md:203–205` specifies the canonical benchmark plan for micro records. Retain the separate evidence hash and derive `plan_digest` from an explicit canonical operation/configuration plan.

4. `package.py:76` delegates receipt success to the permissive cross-platform `gnu_time`. Resealed reports containing `Exit status: 01`, or only BSD timing lines without a GNU exit status, are accepted despite this pinned Linux GNU-time campaign. Require one exact GNU success status and reject contradictory/malformed receipt fields; the request requires failing/altered evidence to be refused.

No scope creep found: all six paired records and measured negative hypotheses are retained; micro-only claim limits are explicit.

Reviewed SHA256:
- package.py: 204e1a6f34dc360a39fb3d32e40e96c6b6ac01a3d12508c6ac84eca4f6e70a4b
- test_package.py: ce1107fdd69eef29d76f4920155622e3400538370965b7fd4f0b8bb5ad9f3480
- Pinned, unchanged capture.py: b31c0a867cb291aed2ab911d124d1458b95e12c304fd1bae6ac1d5e19f2a6e5d

Skipped hardware, full gates and schema-executable invocation. Job 6643 remains pending; synthetic fixtures are not measurement evidence. FIX.

Re-review — PASS (revised files). All four findings above are resolved. Twelve tests pass. Independent synthetic CLI checks produced six native-validated records for both positive and negative campaigns, with a stable canonical plan digest. Original malformed timestamp, status-01 and BSD-only counterexamples now reject; the same-seed root regression rejects. Overwrite preserves existing output, validator failure creates no output, and optimized execution refuses. No remaining requirement gap or scope creep found.

Final reviewed SHA256:
- package.py: e711a2db22a81a2e49d13f1981cb3d0ec8ffd4b1115acc60ca08f440b1be72be
- test_package.py: a11f7a4875daa44dc111fd95b5d87b1b77222fec727bccf40221f4e7f037b611
- capture.py: unchanged at the hash above.

Skipped hardware and full gates. Temporary synthetic records were deleted; no measurement evidence exists. Final parser delta rejects prefixed GNU clock/RSS fields; twelve tests pass. Final verdict: PASS.
