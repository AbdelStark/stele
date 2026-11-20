# RFC-0029 Policy 3 Parameter Checker & Recursive Size Model (`E19-01`)

Governing specs: [RFC-0029](../../docs/rfcs/RFC-0029-succinct-interleaved-commitments.md) §§1–5,
[RFC-0010](../../docs/rfcs/RFC-0010-pcs.md) A2/A3/A17,
[RFC-0012](../../docs/rfcs/RFC-0012-transcript-and-soundness-accounting.md) A20,
[RFC-0030](../../docs/rfcs/RFC-0030-security-accounting.md) §3.

Reproduced by exact integer arithmetic (`int` / `Fraction`):

```sh
python3 research/rfc0029-pcs/check_policy3.py --check
python3 research/rfc0029-pcs/check_policy3.py
```

## 1. Policy 3 Fresh Query Counts (`RFC-0029 §5`)

For coefficient-form Circle RS with `C = 2^m`, `N = 2^(m+b)`, distance `D = N - C` (`C >= 2`) or `D = N` (`C = 1`),
and proven proximity radius `e = floor((D - 1) / 3)` (`e < D/3`), Policy 3 chooses the exact least positive integer `q`
such that `2^T · (N - e - 1)^q <= N^q`, verifying failure at `q - 1` (`2^T · (N - e - 1)^(q - 1) > N^(q - 1)`).
Because `e < D/3`, the near-case base `(N - D + e) / N` is strictly at most `(N - e - 1) / N`, so `q` covers both cases.

| Rate | Blow-up `b` | `m = 16` `D` | `e = floor((D-1)/3)` | `q (T = 100)` | `q (T = 130)` |
|---|---:|---:|---:|---:|---:|
| 1/4 | 2 | 196,608 | 65,535 | 241 | 314 |
| 1/8 | 3 | 458,752 | 152,917 | 202 | 262 |
| 1/16 | 4 | 983,040 | 327,679 | 185 | 241 |

## 2. Recursive Opening Proof Bytes (`2^20` to `2^34` M31 entries, `T = 100`)

Exact DP minimisation of RFC-0029 §3 proof bytes over per-level `(ell_i, m_i, b_i)` (with level-0 M31 elements at 4 bytes,
levels `>= 1` at `4 · deg` bytes, 32-byte Merkle paths and level roots, degree-2 row-round sumchecks at levels `>= 1`,
and final vector `u_L` sent in the clear). Exact QM31 cap at 100 bits: `floor(p^4 / 2^100) = 2^24 - 1`.

| Entries | QM31 uncapped | QM31 capped (`2·ell·(e+1)`) | QM31 capped per-round (`2·(e+1)`) | QM31 `b = 2` capped | Ext6 Q50 capped | OM31 Q50 capped |
|---|---:|---:|---:|---:|---:|---:|
| `2^20` | 299,376 (0.286 MiB) | 299,376 (0.286 MiB) | 299,376 (0.286 MiB) | 349,168 (0.333 MiB) | 327,672 (0.312 MiB) | 355,968 (0.339 MiB) |
| `2^21` | 329,024 (0.314 MiB) | 329,024 (0.314 MiB) | 329,024 (0.314 MiB) | 387,776 (0.370 MiB) | 369,184 (0.352 MiB) | 403,328 (0.385 MiB) |
| `2^22` | 373,632 (0.356 MiB) | 373,632 (0.356 MiB) | 373,632 (0.356 MiB) | 435,968 (0.416 MiB) | 416,544 (0.397 MiB) | 456,704 (0.436 MiB) |
| `2^23` | 420,992 (0.401 MiB) | 420,992 (0.401 MiB) | 420,992 (0.401 MiB) | 497,664 (0.475 MiB) | 477,536 (0.455 MiB) | 524,800 (0.500 MiB) |
| `2^24` | 474,320 (0.452 MiB) | 474,320 (0.452 MiB) | 474,320 (0.452 MiB) | 565,328 (0.539 MiB) | 529,272 (0.505 MiB) | 575,328 (0.549 MiB) |
| `2^25` | 512,768 (0.489 MiB) | 523,168 (0.499 MiB) | 512,768 (0.489 MiB) | 611,648 (0.583 MiB) | 576,632 (0.550 MiB) | 628,704 (0.600 MiB) |
| `2^26` | 560,128 (0.534 MiB) | 605,216 (0.577 MiB) | 560,128 (0.534 MiB) | 667,552 (0.637 MiB) | 624,064 (0.595 MiB) | 688,000 (0.656 MiB) |
| `2^27` | 610,656 (0.582 MiB) | 666,912 (0.636 MiB) | 610,656 (0.582 MiB) | 729,248 (0.695 MiB) | 690,976 (0.659 MiB) | 762,016 (0.727 MiB) |
| `2^28` | 663,984 (0.633 MiB) | 984,768 (0.939 MiB) | 679,824 (0.648 MiB) | 1,043,520 (0.995 MiB) | 753,656 (0.719 MiB) | 818,464 (0.781 MiB) |
| `2^29` | 720,192 (0.687 MiB) | 1,478,336 (1.410 MiB) | 783,072 (0.747 MiB) | 1,537,088 (1.466 MiB) | 801,912 (0.765 MiB) | 877,760 (0.837 MiB) |
| `2^30` | 767,552 (0.732 MiB) | 2,465,472 (2.351 MiB) | 906,464 (0.864 MiB) | 2,524,224 (2.407 MiB) | 855,264 (0.816 MiB) | 942,976 (0.899 MiB) |
| `2^31` | 820,880 (0.783 MiB) | 4,439,744 (4.234 MiB) | 1,153,248 (1.100 MiB) | 4,498,496 (4.290 MiB) | 928,096 (0.885 MiB) | 1,022,912 (0.976 MiB) |
| `2^32` | 877,328 (0.837 MiB) | 8,388,288 (8.000 MiB) | 1,646,816 (1.571 MiB) | 8,447,040 (8.056 MiB) | 996,696 (0.951 MiB) | 1,085,280 (1.035 MiB) |
| `2^33` | 936,576 (0.893 MiB) | 16,285,376 (15.531 MiB) | 2,633,952 (2.512 MiB) | 16,344,128 (15.587 MiB) | 1,050,872 (1.002 MiB) | 1,150,496 (1.097 MiB) |
| `2^34` | 998,656 (0.952 MiB) | 32,079,552 (30.593 MiB) | 4,608,224 (4.395 MiB) | 32,138,304 (30.649 MiB) | 1,110,144 (1.059 MiB) | 1,221,632 (1.165 MiB) |

## 3. Q50 Wider-Field Pricing (`2^32` to `2^34`, `T = 100` and OM31 `T = 128`)

Under the `ℓ`-fold QM31 cap (`2·ell·(e+1) <= 2^24 - 1`), row length `C` at level 0 is capped at `2^19` (`b = 2`), so
a `2^32` witness needs `2^13` rows and reaches `8,388,288 B` (`7.9997 MiB`, just under 8 MiB); at `2^33`..`2^34`
level-0 columns double with every bit. Moving commitment challenges to a wider extension (`Ext6` = `p^6`, ~186 bits,
24 B/elem; or `OM31` = `p^8`, ~248 bits, 32 B/elem) lifts the proximity cap completely, keeping `2^32`..`2^34` openings
around `0.95–1.17 MiB` at `T = 100` (`1.31–1.47 MiB` on OM31 at `T = 128` treaty). If the per-round proximity bound
`2·(e+1) <= 2^24 - 1` holds on QM31, QM31 alone achieves `1.571 MiB` at `2^32` and `4.395 MiB` at `2^34`.

## 4. Certified Model Sources & Multi-Segment Batching

- **Certified model sources (`RFC-0029 §§1.3, 5`, rate 1/4 at level 0, `T = 100`, per-round cap):**
  Choosing `e_c = floor(e_max / 8)` trades `q_cert = 2,184` one-time registration queries for `q_open = 55` per-proof
  opening queries, yielding **`518,064 B` (0.494 MiB)** for `2^29` weights up to **`714,768 B` (0.682 MiB)** for
  `2^33` weights (full 8B model scale).
- **Multi-segment level-0 batching (`k = 32` segments joined at level 1):**
  `2^30` witness = `7.139 MiB` (`2·ell·(e+1)` QM31) / `5.415 MiB` (per-round QM31) / `5.365 MiB` (Ext6 Q50).
  Merkle paths scale linearly with `k` (Q44), so coarser segments (e.g. `k = 4..8`) save 4–8× on level-0 Merkle bytes.

## 5. Build-Program Bet B3 Assessment (`docs/plan.md §2`)

Bet B3's kill criterion asks whether `E19-01` can show 100-bit proven parameters under **8 MiB (`8,388,608 B`)** for a
`2^32`-cell witness under RFC-0030 §3 caps with Q50 priced:
- **Cleared:** Even under strict `2·ell·(e+1) <= 2^24 - 1` on QM31, `2^32` requires `8,388,288 B < 8,388,608 B` (`7.9997 MiB`).
- With Q50 per-round QM31 (`1.571 MiB`), Q50 Ext6 (`0.951 MiB`), or Q50 OM31 (`1.035 MiB`), `2^32` leaves `6–7 MiB` of
  headroom for Q49 data-parallel lookup tree proofs and sumcheck rounds inside the 8 MiB M3 / 4 MiB M6 proof budgets.
- Bet B3 stays active; no fallback is triggered.
