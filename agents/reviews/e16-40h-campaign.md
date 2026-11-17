# E16-40h campaign review — code only

Independent Spec and Standards agents reviewed the complete bounded capture and
submission scripts. Both PASS the final files; hardware evidence remains pending.
The scripts and controls are retained in the coordinator's external validation
directory. Runtime is fixed at `87cae62494ebbb9337954fe60003eebbce563c75`.

| Artifact | SHA-256 |
| --- | --- |
| Source archive | `d82bcc9f9a421d04234789c929a31bce1ad787624ad67b196156115778dcb2e1` |
| `e16-40h-capture.py` | `2c74dc8cfeed26f67b29b7b97f7a63f6b2ffaa14595913a2f4288498d763f2cc` |
| `e16-40h-campaign.sbatch` | `defd033a3835c0646f05b02366aaeba8526c11b2bcd0d098cd50e33d8ca72dd1` |
| `test_e16_40h_capture.py` | `a35b658e7fb7eb91f032417ef56f433a58001706a277131e155d66ab1acbcbec` |

## Spec

PASS. Actual host/H100 helper tests cover one million deterministic cases with
canonical-output checks. Receipt validation requires eight canonical masked
comparisons at log sizes 8/12/16/20 and 1,000 complete-source comparisons. Missing,
duplicate, zero-case, wrong-device and skipped receipts reject. Individual and
campaign timeouts bound execution. The identified cleanup gap is fixed: SIGKILL
reaches the isolated process group even after its leader exits. Source, binary
hashes, command output, completion records and runtime failures are retained.
Cargo artifact discovery selects only test executables and rejects missing or
duplicate targets. Inspected runtime files match the pinned archive and commit.
Self-check and both regression tests pass, including a TERM-ignoring descendant.

## Standards

PASS. No remaining documented-standard violations or actionable Fowler findings.
The initial build-control finding is resolved: separate bounded dependency
provisioning precedes `--frozen` compilation, satisfying the security guardrail's
"no network at build" rule. Receipt validation, process-group cleanup and artifact
selection preserve the task's bounded scope. Repeated expected fixture descriptions
support independent checks. Both focused tests and shell syntax validation pass.

Neither review executed hardware, remote operations or repository-wide gates.
Queue dependencies were not reviewed. The campaign makes no performance,
complete-proof or ADR-127 GO claim and cannot substitute for earlier campaigns.

Coordinator follow-up: the old cleanup behavior fails the new descendant control;
the final implementation passes. Actual Cargo output reproduced the extra non-test
binary and validates the new filter. Optimized Python execution is rejected.
Lucid job 6667 was submitted once with `afterany:6640:6643`; archive/capture/sbatch
hash checks and the capture self-check passed on the remote submission host.
Submission is not device execution or parity evidence. Earlier archives are unchanged.

Final capture-code findings: zero Spec, zero Standards. This review does not
authorize merge.

## Completed hardware evidence

Job 6667 completed successfully. The [receipt](e16-40h-h100.json) pins all four
executed tests. The coordinator rechecked all 32 hashed payload files, exact
commands, nonempty receipts, successful sequential completion and three remote
test-binary hashes. Manifest SHA-256 is
`2aa034957170a5087cf360b7ea756d2d90c746fe6d397c90d7fa2705e114a761`.
No performance import or full-proof parity follows. The later host-assembly
rollback changes two source-material files; helpers, kernels and tests remain
identical. Independent evidence review and mandatory merge-tree gates are separate.
