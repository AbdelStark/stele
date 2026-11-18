# E16-40v complete T32 calibration

Lucid job 6781 ran the ordinary stories42M dev-zk T32 producer at source `0a59b594` on one H100 NVL and 16 CPU cores. An independent verifier accepted the expected model and rejected a different model. The public archive digest is `02abc7e701ce07b23ca149036dfbec0e8eb0737c350165608c2633137614d716`. Job 6778 supplies the seeded device and CPU controls for the identical kernels. Its subsequent CLI compilation failure was fixed before job 6781. The CPU authored the proof and supplied the comparison transcript. [Combined ledger](../../bench/ledger/e16-40v-t32-resident-gkr-batch-h100.json)

| Matched stage | CPU seconds | Candidate seconds | Coverage |
|---|---:|---:|---|
| Lookup tops | 19.238 | 17.856 | 21 tops, 8,736 bytes downloaded |
| Resident rebuild | 18.904 | 16.851 | 21 trees, 1,452 checked child views |
| GKR construction and rounds | 232.617 | 162.723 | 383 device steps and 2 budget fallbacks, including 100.611 seconds residual CPU and a 26.579-second upper bound for compact routing |
| Ordinary batch preparation | 12.304 | 9.849 | All three source messages |
| Ordinary dense rounds and folds | 4.145 | 0.224 | All 69 rounds and three finals |

The GKR comparison retains the entire CPU factor-construction interval on each of the 20 admitted compact leaves. These intervals include the host routing map needed to expand the compact finals. The two fallback steps already charge all their CPU work.

The rebuild qualification copied 31,023,168,864 additional bytes and took 7.497 seconds. Charging the entire readback and its synchronization raises the rebuild path to 24.348 seconds. The cold CUDA context took 5.227 seconds. Driver allocator high waters through the final batch were 29,259,566,480 bytes used and 30,098,325,504 reserved. The two GKR fallback steps retained their full CPU cost. [Combined ledger](../../bench/ledger/e16-40v-t32-resident-gkr-batch-h100.json)

Packing 397,986,146 positions produced 3,129,309 runs and 400,551,552 scheduled tile-position run checks. Including the small term descriptors, preparation uploaded 10,779,938,120 bytes. The preceding grouped implementation uploaded 19,178,106,040 bytes and took 17.890 seconds on the same fixture and node, including its host construction and transfers. The candidate stages allocated up to 5,759,274,216 bytes for one host pack and 11,127,983,336 bytes for one device construction. [Previous ledger](../../bench/ledger/e16-40s-t32-lookup-batch-h100.json) · [Combined ledger](../../bench/ledger/e16-40v-t32-resident-gkr-batch-h100.json)

The combined process took 1,139.9 seconds including both implementations and their comparisons. It wrote timing output to the shared filesystem. The 560 small relation setup intervals containing geometry output totalled 54.859 seconds at millisecond resolution. The 363 child-bearing device construction intervals containing an output line totalled 30.223 seconds. These inclusive intervals bound possible logging time. All stage totals retain it. The preceding capture did not enable detailed stage logging. [Combined ledger](../../bench/ledger/e16-40v-t32-resident-gkr-batch-h100.json)
