# E16-40o: current Mac CPU stage evidence

Development research, lane V; RFC-0018 A1/A2 and RFC-0027 §3. The task changes no
production algorithm, proof bytes, challenge, binding, dependency or interface.
It observes c_sc, c_lu, c_c and T_misc without claiming a constant improvement.

The [stage report](../../research/gpu-gating/STAGE-INVENTORY.md#quiet-start-mac-baseline-e16-40o)
links all three ledgers and their scoreboard rows. Each recorded proof passed
ordinary expected-model verification and its wrong-model rejection control.
These are complete CPU proofs; they earn no integrated GPU proof count, device
memory qualification, speedup or ADR-127 GO credit.

Source `60f2a39af07e749d6a85ba0dbfa10d34556b2157` was clean throughout capture.
Actual Cargo artifact reports identify the release CLI and validators built with
Rust 1.90.0. All public input hashes equal the earlier stories42M profile inputs.
The source archive contains all 2,391 files from that exact tree. Private model
state, its lock and crash temporary files are excluded from public evidence.

The immutable package lives outside the checkout at
`/Users/abdel/dev/stele-validation/e16-40o-mac-profile`. It retains the capture,
controls, build reports, source archive, raw proof and command records, resource
reports, validated ledgers, terminal exit and independent audit. Its public
archive contains regular file bytes, including the targets of internal convenience
symlinks; no external symlink is exported.

- Capture pins SHA-256: `e5b43b9b0fb0ed31ff12390e17a14432b44e894c72dad40c0b891cd54db795d8`.
- Public archive SHA-256: `3bffbf5154a86aa3259bf59149f3b37d6a36dc3469a9f6461f04f4948c254aba`.
- Raw manifest SHA-256: `84ed82d0bbccd81c14e20fd2512aa1e8f42c3dc8d3f4930e2fde0001d476288a`.
- [Verification and import receipts](e16-40o-profile.json) retain every proof,
  public-bundle and raw/repository ledger digest. Import changes JSON whitespace
  only; parsed records are identical. The scoreboard is generated.

Both pre-execution reviewers approved the pinned capture after fixing missing
command receipts on quiet-wait and observation failures. Seven capture controls
passed, including those failures, process-group timeout cleanup and secret-file
exclusion. Two additional audit controls reject altered command/exit/limit/load
or environment records and check the complete public file inventory.

Capture exited zero after all three proof/control pairs and ledger validations.
The terminal audit verified all 101 raw payload hashes, exact measured and
ledger commands, time/RSS records, source and binary pins, complete stage
hierarchies and every public archive payload. It reran the ledger validator,
without rerunning proofs. No measured command was retried or discarded.

Post-execution Spec and another-lane Standards reviews and mandatory branch
gates are pending. Current-main/intended-merge-tree validation still precedes
merge in lane-stack order. The task remains in progress until then.
