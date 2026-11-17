# E16-40j independent H100 capture reviews

Fresh Spec reviewer `batch_capture_spec_review` and lane-B Standards reviewer
`batch_capture_standards_review` approve the pinned capture. No blocking code
finding remains. Source: `ffdf611cb3a38dfcc5a1bdae478d708ad5e5be94`.
This is capture approval, not hardware parity or merge approval.

| File | SHA-256 |
|---|---|
| source.tar.gz | 1da7e3e406e6d36acbba04e2db715c88eda9661c82cc094b9c49f5d8da0ba526 |
| capture.py (both copies) | c9f550c589134e2cdd8a51a98d413028c03bedf30d3199212340586d52e04cb5 |
| campaign.sbatch | c2a26e79ab661938bf7363d42858dc20f93e101b56383b75551f0ef1de9a578e |
| campaign.sha256 | cba36903c56fffb8d29d7e8a299e4a468f868e7ec869e474941a38914069ae74 |
| test_e16_40j_capture.py | 150c60b3f8cdf816a3932a712d7ad10989e8ca83cee8c6fd078615edf0b65b05 |

Both reviewers independently verified archive/source equality, test names and
counters, seeded distinct source/face coverage, exact nonempty receipts, script
hashes, shell syntax, optimized-Python rejection and the two regression controls.
They also exercised terminal failure records; Spec checked controlled launch
failure, and Standards checked nonzero exit, spawn failure and timeout. These
produced failed results and hash-valid evidence manifests. The TERM-resistant
descendant control confirms group cleanup. No credential or real witness is logged.

The eleven exact tests include the earlier field/lookup/source/masked regressions,
new batch construction, malformed shapes, ordinary RoundSumMismatch and actual
resident GPU Dense rounds/folds/finals. Device batch receipts require the actual
1,000 distinct sources, canonical/raw kernel and dense cases, seed 275414777857
and the claimed-value near miss. No absent-device or skipped result can pass.

One H100 NVL, 16 CPUs, 64G, 75 minutes; capture deadline 4,200 seconds. Supply
`--dependency=afterany:6683` at submission. Earlier archives remain unchanged.
Frozen compilation follows separate locked provisioning. Compile, allocation or
comparison failure stops for a report under the task budget. Actual H100 receipts,
compiled-binary hashes and full mandatory stack-order gates remain pending.
