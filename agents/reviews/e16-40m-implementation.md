# E16-40m production GKR consumer — implementation review

Scope: `b49fd821e9514e65867fb08e26063d11f3553dc3` through implementation
`51259ab4e2e69b29e131fa5c863a9b76aa8f701e` and the reviewed corrections in this
commit. Development research, lane V; no production backend or proof change.

## Spec / owning GPU axis

Independent reviewer `gkr_device_spec_review`: PASS before hardware. The adapter
preserves factors, domains, terms, degrees, mask coordinates and actual challenges.
Every compact slot is checked before production expansion and complete claim
routing. Raw injection and retained-buffer/transfer accounting match the existing
fixed device path. No protocol, backend or dependency additions.

Two findings were fixed before qualification: odd cases originally used ordinary
narrow proofs, not narrow lifetime sources; every statement now supplies an actual
Narrow or Balanced lifetime with its root and disclosure. The observer now requires
nonempty GKR and exact per-statement callback count, in addition to sequential step
indices. Final metadata-only delta was reviewed and approved; it exposes only
synthetic geometry/storage/term arities for independent byte accounting.

## Standards / lane B axis

Independent reviewer `gkr_device_standards_review`: PASS before hardware, no hard
violations or actionable smells. Existing fixtures/packing/lazy injection are
reused. No challenge, commitment, verifier, dependency, unsafe code or production
interface changes. CPU construction, expansion, routing and memory exclusions are
explicit. The reviewer independently ran the original three GKR controls and
lookup near-miss test, then reviewed both coverage corrections and metadata.
Reviewed final blobs: `gkr_cases.rs` cc6ea55503c3b96e91e8f63f8b95776b83f7d4d6;
`GKR-DEVICE.md` e6773fbd9d9c7147743566c7acfa15cdba3e123b.

## Validation and limits

Honest tests failed against the pre-implementation stub. Corrected final source
passes the research CPU all-target suite, including every step of 1,000 verified
lifetime proofs and the changed expansion-ignored compact-slot control. CUDA
all-target Clippy with warnings denied and formatting pass. The host metadata is
checked against fixture-derived domains by the qualification parser.

H100 qualification and current-main/intended-merge-tree gates remain pending.
These observed CPU proofs supply no integrated GPU-proof or performance credit.
