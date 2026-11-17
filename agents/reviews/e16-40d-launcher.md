# E16-40d launcher failure and bounded correction

Lucid job 6640 failed before compilation. Cargo was invoked from the staging
directory with a source-relative manifest; rustup found no selected/default
toolchain there. The archived source has the pinned `rust-toolchain.toml`.
No inventory CPU/GPU cases ran and no parity or performance result follows.
The coordinator reported this failure before preparing another attempt.

Retained failure files in the external validation directory:

| File | SHA-256 |
| --- | --- |
| `e16-40d-failure-6640/build-6640.log` | `6a074a343822150a98548e92f6d5d2ef8092067a8711a01ef69e638e2030444c` |
| `e16-40d-failure-6640/campaign-6640.log` | `129762986b5107335b545f740c06145184fe5de4fa9551357b741a9ac3f1892c` |

Scope: one corrected launcher and one bounded allocation, with the unchanged
source, inventory and capture. No generator, kernel or reference change, no
global rustup default, no automatic retry. A further failure stops for a report.
The corrected launcher changes directory into the archived source before Cargo,
separates bounded locked dependency provisioning from frozen compilation, then
returns to staging for the unchanged capture. It also pins the launcher/capture
files and removes `PYTHONOPTIMIZE` so capture assertions remain enabled.

| Artifact | SHA-256 |
| --- | --- |
| Source archive at `8038e131e93d59c08328c7c94a979f3c551058e1` | `448a5654bad7451e1264f95cc883baa8b58f4c27bc26987fd0b29468928921da` |
| Inventory | `f48869074e88abf2ab29fa8e3792b46beb998abc5aeb262f5908e536cd043868` |
| Unchanged capture | `07515fff3081be5a50ccade1378717f5c3cf8d22c6dc4c53b95099f147634802` |
| `e16-40d-inventory-toolchain.sbatch` | `715f575f2744e696e2a0c534d752b66d99f4b66656fc2b5652b49b9109f1932e` |
| `test_e16_40d_launcher.py` | `972156deaff878390a49e66768c6d13e368eeacc3c193e68f6b6c3238e28be96` |

Local shell syntax and assertion-based launcher tests pass. Stub executables
check the source working directory, manifest and frozen flags, provision/build
order, assertion environment and return to staging. Build failure and missing
toolchain controls stop before capture. These are launcher controls, not hardware
evidence. Fresh independent review precedes submission; mandatory merge-tree
gates and the validated inventory evidence remain pending.

Fresh independent Spec and Standards reviews both PASS `c50c5f6b` and the exact
launcher hash above, with zero actionable findings. Both verified every recorded
artifact/failure hash and passed the launcher controls, shell syntax, capture
self-check under Python 3.12 and diff checks. No production behavior or protocol
changes. Neither reviewer ran SSH, hardware or full suites. The unchanged capture
requires Python 3.10 or newer; target interpreter selection is a submission
preflight. The outer allocation cap remains 90 minutes, even though individual
step maxima sum higher. A truncated run or incomplete evidence remains failure;
the capture requires both complete campaigns and matching receipts for success.
These reviews authorize only the scoped attempt, not parity, merge or GO.
