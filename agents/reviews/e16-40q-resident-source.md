# E16-40q resident source implementation review

Fixed base `a2e1a147bded0635324bd7316978c997a280e89b`; implementation
`6034113f67ace10258b48c90e973db291a0a4d99`. Tests first: `056ab26f`.
Research scope: [resident responses](../../research/gpu-gating/RESIDENT-SOURCE.md).

## Spec — owning lane E

Independent `resident_source_spec_review`: approve implementation readiness.
No implementation defects or scope creep found. Reviewed ownership and immutable
shape/device lifetimes, validated slice arithmetic, canonical M31 payloads,
production salts, bottom-up paths, root-only/full-material preservation and
transfer/retained-buffer accounting. No complete-device-peak claim follows.

## Standards — independent lane B

Independent `resident_source_standards_review`: ready for H100 qualification;
no blocking source-level standards violations. Minor judgment smell: the selected
payload helper repeats the existing full-material salt/word serialization. Kept
the small duplication to preserve the complete-material allocation behavior;
no extra abstraction was requested or needed for this slice.

## Checks and limitations

Host selected-payload parity and malformed-input tests pass. Existing complete
material and thread-count regressions pass. Default and CUDA all-target Clippy,
CUDA-feature device-test compilation, formatting, task graph and docs links pass.
Explicit required-device execution on the Mac fails with absent CUDA, as intended;
this is a launcher refusal check, not hardware evidence. Reviewers inspected code
and supplied logs; neither claimed independent device execution.

Both axes require actual H100 execution of resident and complete-material parity,
fresh evidence review and mandatory stack gates on the intended merge tree before
merge. No GPU qualification, speedup, integrated proof or ADR-127 GO is granted.
