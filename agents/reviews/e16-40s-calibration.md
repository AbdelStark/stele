# T32 stage calibration

Development research in lane V measures the GKR and relation rounds (`c_sc`), lookup trees (`c_lu`) and the host work and transfers needed by each device call (`T_misc`).

Lucid job 6775 ran the E16-35 relation and interior-GKR templates from commit `60f2a39a`. Each of the six geometries has three independent runs on each host. The quiet-start M4 Max and H100 NVL produced matching round and final digests in all 18 pairs. The ledger records the resident round and fold medians. Reconstructing factors, transferring inputs, compiling CUDA, routing claims, binding masks and opening sources incur additional costs in a complete prover. [Paired micro ledger](../../bench/ledger/e16-40-paired-h100-mac-rounds.json)

Job 6776 uses the original T32 proof and source lifetimes to compare the first lookup tree and top construction, each GKR tree rebuild and the three ordinary claim batches. The CPU transcript supplies every batch challenge. The GPU returns raw dense polynomials for comparison before mask addition. The CPU continues to compute the complete proof and an independent verifier checks it. The shared batch, masks, transcript and authenticated openings remain CPU work. The benchmark includes the existing GPU rebuild's extra top computation and full material downloads.

Job 6776 completed on one H100 NVL. All 21 first visits, all 21 rebuilds and the 69 dense batch rounds, folds and three finals matched their production CPU results. The independently pinned verifier accepted the 21,411,006-byte proof and rejected the changed expected model. The source archive is pinned at `dd6bdae9ae436356b8006693158541f0a3b1755f65333f8bd65bf9dde86594e7`. The stage ledger pins the public command receipts, verifier identity, Slurm disposition, resource records and raw timing log. [T32 stage ledger](../../bench/ledger/e16-40s-t32-lookup-batch-h100.json)

| Operation | Same-node CPU (s) | H100 with host work (s) |
|---|---:|---:|
| First lookup trees and tops | 17.980 | 51.996 |
| Later lookup tree rebuilds | 16.584 | 49.675 |
| Ordinary batch weights and face | 11.467 | 17.890 |
| Ordinary dense rounds, folds and finals | 4.137 | 0.225 |

The measured GPU path took 119.786 s across these operations, plus 5.523 s for CUDA startup. The same-node CPU took 50.168 s. Each lookup visit family returned 31.023 GB, including the complete tree on the first visit. Batch setup uploaded 19.178 GB. The resident-round calibration in job 6775 therefore cannot establish an end-to-end gain for the measured path. The existing ADR-127 disposition stands. [T32 stage ledger](../../bench/ledger/e16-40s-t32-lookup-batch-h100.json)
