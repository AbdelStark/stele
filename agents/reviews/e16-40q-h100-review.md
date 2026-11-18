# E16-40q H100 resident source review

Both reviewers accept Lucid job 6773 as component parity evidence for the
development-tier research source implementation. Slurm recorded a successful
exit on one H100 NVL with zero restarts and requeues. The [hardware receipt](e16-40q-h100.json)
identifies the source, three release binaries, raw archive, timings and payloads.

**Owning GPU lane E.** `resident_source_actual_spec` verified the source archive
against Git `6034113f`, reran the corrected terminal auditor and compared its
result byte for byte with the committed receipt. The test compared every root
and all 8,000 requested payloads and sibling paths against `PreparedSource` over
1,000 seeds. Openings used the production salt, canonical M31 words and bottom-up
paths. Ordinary Merkle verification succeeded. One changed word per seed
produced `RootMismatch`. The root-only regression, duplicate and reversed
requests, invalid indices, noncanonical words and accounting overflow were covered.

**Independent lane B.** `resident_source_evidence_review` matched all 2,404
source files to Git and checked the six exact test receipts, executable readbacks
and hardware attribution. The existing 1,000 complete-material cases passed.
The tests checked the 32-byte root download, the transfer for each response and
the retained encoding and tree buffer counts. Both reviewers verified all 46
evidence payloads and passed all four synthetic auditor tests with Python 3.12.

The capture and reviewed branch have identical Rust sources and dependencies.
The evidence covers the resident source response path. Complete prover parity,
whole-prover timing and peak memory require separate runs. Mandatory gates on
the intended merge tree remain pending.
