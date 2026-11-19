# H100-authored masked sumcheck proofs

Lucid job 6792 ran the checked RFC-0013 A4 producer on 1,000 seeded CPU/H100 pairs. Across 13,000 device rounds, the prover consumed each device polynomial before the transcript supplied the fold challenge. The final input evaluations also came from the H100. The existing host implementation produced the mask binding, certificate and opening. [Hardware ledger](../../bench/ledger/e16-40ad-bound-masked-h100.json)

Every pair matched on the complete typed proof, including all certificate and opening bytes, and the subsequent transcript challenge. The ordinary verifier checked each A4 proof and the test checked both remaining input evaluations against the original fixture tables. Changing a single first-round coefficient produced the expected `RoundSumMismatch`. [Checked producer, verifier and control](../../research/gpu-gating/masked/src/gpu_bound_tests.rs)

Lane Z independently reviewed the producer and verifier order, transcript continuation, device call counts and rejection reason at `39ebbaf4`. Slurm recorded a successful exit on one H100 NVL. The ledger pins the source archive, executable, allocation, test output and GNU time receipt. This establishes masked subproof parity. The 50-model whole-inference gate requires a run through the integrated prover.
