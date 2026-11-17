# E16-40i independent H100 capture reviews

Fresh Spec reviewer `lookup_capture_spec_review` and lane-B Standards reviewer
`lookup_capture_standards_review` approve the pinned campaign scripts. No
implementation finding remains. Approval covers the capture, not device parity
or merge. Source: `b6f094b297e687cd7901fcb693437e9ef663bbd9`.

| File | SHA-256 |
|---|---|
| source.tar.gz | 152e58e82b31b7040b9001fd5fa8c73a58b7f3b7374f32d5a5d2c135b2ac8de2 |
| capture.py (both local copies) | 2e5e7bfc3371db779d1a3ff363a8cbbb28a81f1dc42ed10c271252685877ab70 |
| campaign.sbatch | f7c4886596a848a1ab06edf3411276ff85113642cd2d0c40e1c78f36e3240fc9 |
| campaign.sha256 | a51fe2c9785e53b021b9c3596ab0dcf9bc3bda4ee4c16b4280708f92cc32e9a5 |
| test_e16_40i_capture.py | cff128f9b095126aeb9c59afce80d7f85ae91aa40f53ed2059d1a91aa2349b14 |

The reviewers independently verified the archive against the reviewed git tree,
script hashes, shell syntax, strict nonempty receipts and actual Rust names,
counts and seed. Both passed the receipt and TERM-ignoring descendant controls,
self-check and optimized-Python rejection. Spec also checked individual zero-count
mutations. Existing isolated process-group cleanup, terminal failure manifests,
separate dependency fetching and frozen compilation are retained.

Seven exact tests run: host field helpers, host lookup inverse, host lookup
kernels, device inverse, device trees (including separate lazy-input kernel checks
and near misses), canonical masked rounds, and complete-source material. No
absent-device, skipped, wrong-device/seed/count or partial receipt is accepted.
No real witness or credential is logged.

The allocation is one H100 NVL, 16 CPUs, 64G, 75 minutes, with a 4,200-second
capture deadline. Supply `--dependency=afterany:6667` at submission; it is not
embedded in the reviewed sbatch file. Earlier queued archives remain unchanged.
A compile, allocation or parity failure stops for a report under the task budget.
Job 6683 completed successfully. The [hardware receipt](e16-40i-h100.json) records
all seven exact tests. The coordinator checked all 41 hashed payload files, exact
commands, successful sequential completion and all three remote binary hashes.
Manifest SHA-256 is
`ad17fd351585683976385894db66e10b1037ef18ca914b0ad63c44ad99682346`.
The later host-assembly rollback leaves lookup kernels and tests unchanged.
Independent evidence review and mandatory merge-tree gates remain separate;
no performance or full-proof result follows.
