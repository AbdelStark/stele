# Original GKR work on the T32 laps host

The M4 Max completed three stories42M T32 development proofs at consecutive indices of a fresh commitment. Each run started below a one-minute load average of three. The separately built verifier accepted each proof with the original model pin and rejected a one-nibble change. The uninstrumented producer source was `392afdaa`. The disposable timing overlay was `e825e390`. [Measurement and public receipt digest](../../bench/ledger/e16-40aa-t32-mac-gkr-calibration.json)

Each proof supplied 385 GKR steps. Their order and dimensions matched the Lucid proof, including all 21 compact leaves. Subtracting only measured table construction and round arithmetic leaves the following host work. [Three-sample ledger](../../bench/ledger/e16-40aa-t32-mac-gkr-calibration.json)

| Proof index | Factor preparation retained | Round work retained | Combined |
| --- | ---: | ---: | ---: |
| 0 | 0.460 s | 4.211 s | 4.671 s |
| 1 | 0.516 s | 3.852 s | 4.368 s |
| 2 | 0.507 s | 3.963 s | 4.470 s |

An independent reviewer from lane Z checked the timing boundaries. The factor interval retains expansion metadata and original column copies. The round interval retains transcript work, masks, final expansion and step destruction. A scoped guard covers the arithmetic's mixed-field early return. The receipt rejects overlapping intervals, omitted steps and a compact leaf with the wrong dimensions. [Receipt checks](../../research/gpu-gating/t32-mac-gkr/test_receipt.py)

A whole-prover projection must charge these host intervals together with the device's measured construction, rounds, copies and synchronization. The host calibration supplies one term of that calculation.
