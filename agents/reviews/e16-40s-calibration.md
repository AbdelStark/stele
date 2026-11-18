# T32 stage calibration

Development research in lane V measures the GKR and relation rounds (`c_sc`), lookup trees (`c_lu`) and the host work and transfers needed by each device call (`T_misc`).

Lucid job 6775 ran the E16-35 relation and interior-GKR templates from commit `60f2a39a`. Each of the six geometries has three independent runs on each host. The quiet-start M4 Max and H100 NVL produced matching round and final digests in all 18 pairs. The ledger records the resident round and fold medians. Reconstructing factors, transferring inputs, compiling CUDA, routing claims, binding masks and opening sources incur additional costs in a complete prover. [Paired micro ledger](../../bench/ledger/e16-40-paired-h100-mac-rounds.json)

Job 6776 uses the original T32 proof and source lifetimes to compare the first lookup tree and top construction, each GKR tree rebuild and the three ordinary claim batches. The CPU transcript supplies every batch challenge. The GPU returns raw dense polynomials for comparison before mask addition. The CPU continues to compute the complete proof and an independent verifier checks it. The shared batch, masks, transcript and authenticated openings remain CPU work. The benchmark includes the existing GPU rebuild's extra top computation and full material downloads.
