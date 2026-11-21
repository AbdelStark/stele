# RFC-0029 Policy 3 Parameter & Recursive Proof-Size Study (Task E19-01)

Governing specifications: [RFC-0029](../../docs/rfcs/RFC-0029-succinct-interleaved-commitments.md)
§§1–5, [RFC-0010](../../docs/rfcs/RFC-0010-pcs.md) A2/A3/A17,
[RFC-0012](../../docs/rfcs/RFC-0012-transcript-and-soundness-accounting.md) A10/A20,
[RFC-0030](../../docs/rfcs/RFC-0030-security-accounting.md) §3.
Exact-integer script: [check_policy3.py](check_policy3.py) (`python3 research/rfc0029-pcs/check_policy3.py --check`).
Every query count, proximity cap, and byte total below is derived by exact Python integer and
`Fraction` arithmetic enforcing the M31 circle coset and column-sampler domain ceiling
`m + b <= 30` (`N = 2^(m+b) <= 2^30 < p`, RFC-0010 A2 & RFC-0012 A10).

## 1. Policy 3 exact query counts (`e = floor((D - 1) / 3)`)

For coefficient-form Circle RS of row length `C = 2^m`, blow-up `2^b` (`b in {1, 2, 3, 4}`,
`m + b <= 30`), codeword length `N = 2^(m+b)`, and distance `D = N - C` (`D = N` when `C = 1`),
Policy 3 sets `e = floor((D - 1) / 3) < D / 3`. In fresh mode and at every recursion level
`i >= 1`, `q` is the exact least positive integer with `2^T * (N - e - 1)^q <= N^q` (verified
failing at `q - 1`), which also covers the near case because `N - D + e <= N - e - 1`:

| Rate | Blow-up `b` | `m = 16` distance `D` | `e = floor((D-1)/3)` | `q (T = 100)` | `q (T = 130)` |
|---|---:|---:|---:|---:|---:|
| 1/2 | 1 | 65,536 | 21,845 | 381 | 495 |
| 1/4 | 2 | 196,608 | 65,535 | 241 | 314 |
| 1/8 | 3 | 458,752 | 152,917 | 202 | 262 |
| 1/16 | 4 | 983,040 | 327,679 | 185 | 241 |

At `C = 1` (`m = 0, b = 2`), `D = N = 4`, `e = 1`, and `q = 100` (`(2/4)^100 = 2^-100`).

## 2. Recursive opening proof sizes (`2^20` to `2^34` M31 entries, `T = 100`, `m + b <= 30`)

Exact DP over `(ell_i, m_i, b_i)` minimising RFC-0029 §3 wire bytes:
`sum_i (root_i + sc_i + q_i * (elem_i * 2^ell_i + 32 * k_i * (m_i + b_i))) + elem_ext * 2^m_L`,
where `root_i = 32 B` for committed transitions (`0 B` when `u_L` is sent in the clear),
`sc_i = 3 * ell_i * elem_ext` for levels `i >= 1` (`0` at level 0), `elem_0 = 4 B` (M31),
and `elem_{i>=1} = 4 * deg(K)` bytes. Under RFC-0030 §3, every level enforces
`2 * ell_i * (e_i + 1) <= floor(|K| / 2^T)` (exact QM31 cap at `T = 100`: `2^24 - 1 = 16,777,215`),
`q_i <= cap`, `(k_i - 1) <= cap`, and `m_i + b_i <= 30`.

| Entries | QM31 uncapped (`b>=2`) | QM31 capped (`b>=2`) | QM31 capped (`b>=1`) | QM31 per-round (`b>=2`) | Ext6 Q50 (`b>=2`) | OM31 Q50 (`b>=2`) |
|---|---:|---:|---:|---:|---:|---:|
| `2^20` | 299,344 (0.285 MiB) | 299,344 (0.285 MiB) | 299,344 (0.285 MiB) | 299,344 (0.285 MiB) | 327,640 (0.312 MiB) | 355,936 (0.339 MiB) |
| `2^21` | 328,992 (0.314 MiB) | 328,992 (0.314 MiB) | 328,992 (0.314 MiB) | 328,992 (0.314 MiB) | 369,152 (0.352 MiB) | 403,296 (0.385 MiB) |
| `2^22` | 373,600 (0.356 MiB) | 373,600 (0.356 MiB) | 373,600 (0.356 MiB) | 373,600 (0.356 MiB) | 416,512 (0.397 MiB) | 456,672 (0.436 MiB) |
| `2^23` | 420,960 (0.401 MiB) | 420,960 (0.401 MiB) | 420,960 (0.401 MiB) | 420,960 (0.401 MiB) | 477,504 (0.455 MiB) | 524,768 (0.500 MiB) |
| `2^24` | 474,288 (0.452 MiB) | 474,288 (0.452 MiB) | 474,288 (0.452 MiB) | 474,288 (0.452 MiB) | 529,240 (0.505 MiB) | 575,296 (0.549 MiB) |
| `2^25` | 512,736 (0.489 MiB) | 523,136 (0.499 MiB) | 523,136 (0.499 MiB) | 512,736 (0.489 MiB) | 576,600 (0.550 MiB) | 628,672 (0.600 MiB) |
| `2^26` | 560,096 (0.534 MiB) | 605,184 (0.577 MiB) | 605,184 (0.577 MiB) | 560,096 (0.534 MiB) | 624,032 (0.595 MiB) | 687,968 (0.656 MiB) |
| `2^27` | 610,624 (0.582 MiB) | 666,880 (0.636 MiB) | 666,880 (0.636 MiB) | 610,624 (0.582 MiB) | 690,944 (0.659 MiB) | 761,984 (0.727 MiB) |
| `2^28` | 663,952 (0.633 MiB) | 984,736 (0.939 MiB) | 884,528 (0.844 MiB) | 679,792 (0.648 MiB) | 753,624 (0.719 MiB) | 818,432 (0.781 MiB) |
| `2^29` | 720,160 (0.687 MiB) | 1,478,304 (1.410 MiB) | 1,079,600 (1.030 MiB) | 783,040 (0.747 MiB) | 801,880 (0.765 MiB) | 877,728 (0.837 MiB) |
| `2^30` | 767,520 (0.732 MiB) | 2,465,440 (2.351 MiB) | 1,469,744 (1.402 MiB) | 906,432 (0.864 MiB) | 855,232 (0.816 MiB) | 942,944 (0.899 MiB) |
| `2^31` | 820,848 (0.783 MiB) | 4,439,712 (4.234 MiB) | 2,250,032 (2.146 MiB) | 1,153,216 (1.100 MiB) | 928,064 (0.885 MiB) | 1,022,880 (0.975 MiB) |
| `2^32` | 877,296 (0.837 MiB) | 8,388,256 (8.000 MiB) | 3,810,608 (3.634 MiB) | 1,646,784 (1.570 MiB) | 996,664 (0.950 MiB) | 1,085,248 (1.035 MiB) |
| `2^33` | 936,544 (0.893 MiB) | 16,285,344 (15.531 MiB) | 13,114,464 (12.507 MiB) | 2,633,920 (2.512 MiB) | 1,050,840 (1.002 MiB) | 1,150,464 (1.097 MiB) |
| `2^34` | 1,017,728 (0.971 MiB) | 32,079,520 (30.593 MiB) | 25,599,072 (24.413 MiB) | 4,608,192 (4.395 MiB) | 1,129,216 (1.077 MiB) | 1,240,704 (1.183 MiB) |

## 3. Q50 wider-field pricing (`2^32`..`2^34`, `T = 100`, plus OM31 treaty `T = 128`, `m + b <= 30`)

| Entries | QM31 capped (`b>=2`) | QM31 capped (`b>=1`) | QM31 per-round | Ext6 (`p^6`, 24 B) | OM31 (`p^8`, 32 B) | OM31 treaty (`T = 128`) |
|---|---:|---:|---:|---:|---:|---:|
| `2^32` | 8.000 MiB | 3.634 MiB | 1.570 MiB | 0.950 MiB | 1.035 MiB | 1.308 MiB |
| `2^33` | 15.531 MiB | 12.507 MiB | 2.512 MiB | 1.002 MiB | 1.097 MiB | 1.388 MiB |
| `2^34` | 30.593 MiB | 24.413 MiB | 4.395 MiB | 1.077 MiB | 1.183 MiB | 1.497 MiB |

## 4. Certified model sources and faithful multi-segment level-1 joining (`T = 100`)

### Certified model sources (rate 1/4 at level 0)

Under RFC-0029 §1.3 and RFC-0010 A9, a registration certificate runs no sumcheck (all `ell`
coordinates are drawn together), so level 0 unconditionally enforces the strict single-round
cap `2 * ell * (e_c + 1) <= 2^24 - 1 = 16,777,215` (never `per_round`):

| Model entries | `(ell, m, b)` | `e_c` / `e_max` | `2*ell*(e_c+1)` | `q_cert` (one-time) | `q_open` (per-proof) | Opening bytes |
|---|---|---|---:|---:|---:|---:|
| `2^29` | `(8, 21, 2)` | 32,767 / 2,097,151 | 524,288 | 17,710 | 51 | 510,992 (0.487 MiB) |
| `2^30` | `(9, 21, 2)` | 32,767 / 2,097,151 | 589,824 | 17,710 | 51 | 563,216 (0.537 MiB) |
| `2^31` | `(8, 23, 2)` | 131,071 / 8,388,607 | 2,097,152 | 17,710 | 51 | 616,384 (0.588 MiB) |
| `2^32` | `(9, 23, 2)` | 131,071 / 8,388,607 | 2,359,296 | 17,710 | 51 | 668,608 (0.638 MiB) |
| `2^33` | `(9, 24, 2)` | 262,143 / 16,777,215 | 4,718,592 | 17,710 | 51 | 722,000 (0.689 MiB) |

### Multi-segment joining at level 1 (RFC-0029 §2 "Segments", Q44 evidence)

Each of `k` equal segments closes independently at level 0 (freeing its matrix), and all `k`
pending `u_1^(s)` sources join as `k` row blocks of the logical level-1 source (`k` Merkle paths
per level-1 query, one shared recursion from level 1 onward):

| Total witness | Segments `k` | QM31 capped (`b>=2`) | QM31 capped (`b>=1`) | QM31 per-round | Ext6 Q50 |
|---|---:|---:|---:|---:|---:|
| `2^26` | 8 | 2.367 MiB | 2.367 MiB | 2.367 MiB | 2.466 MiB |
| `2^28` | 32 | 8.871 MiB | 8.871 MiB | 8.871 MiB | 9.064 MiB |
| `2^30` | 32 | 10.318 MiB | 10.318 MiB | 9.682 MiB | 9.861 MiB |
| `2^32` | 32 | 13.705 MiB | 13.705 MiB | 11.144 MiB | 10.696 MiB |

Q44 engineering finding: `k = 32` independent level-0 Merkle trees incur ~9–13 MiB of Merkle
paths even on Ext6; keeping segment count modest (e.g. `k <= 8` segments of 4+ layers each once
RFC-0028 shrinks per-layer witness cells by `>= 10x`) keeps segmented openings at ~2.4 MiB.

## 5. Bet B3 verdict (`docs/plan.md §2`)

Bet B3's kill criterion is a recursive opening above `8 MB` (`8,000,000 B`) at `2^32` M31
entries and 100-bit security under RFC-0030 §3 caps:

- On **QM31 with `b in {2, 3, 4}`** and the conservative `2 * ell * (e + 1)` union bound, a
  `2^32` opening is `8,388,256 B` (`8.000 MiB`), which sits `388 KB` above `8,000,000 B` decimal
  with no headroom for Q49 lookups/sumchecks.
- **Admitting `b = 1` (rate 1/2, already defined in RFC-0010 A2)** drops strict `2 * ell * (e + 1)`
  QM31 at `2^32` to **`3,810,608 B` (`3.634 MiB`)** — more than `4 MB` below the `8 MB` threshold
  with zero Q50 assumption.
- **Q50** clears the `8 MB` budget with `6–7 MB` of headroom even at `b >= 2`: **`1.570 MiB`**
  (QM31 per-round proximity), **`0.950 MiB`** (Ext6 commitment challenges), and **`1.035 MiB`**
  (OM31 commitment challenges), scaling to **`1.077–1.183 MiB`** at `2^34` and **`1.497 MiB`**
  for `T = 128` treaty security on OM31.

Bet B3 is **not killed**; it remains active, with `b = 1` already clearing `8 MB` strictly on
QM31 and Q50 providing sub-MiB headroom at `2^32..2^34`.

## 6. Actual recursive opening bytes (`2^20`..`2^28` QM31, task E19-03)

Measured by running `stele_pcs::recursive::{PreparedRecursive::commit, open_fresh_at_point, verify_fresh_at_point}`
(`cargo run --release --features std -p stele-pcs --example recursive_oracle -- --measure 20 28`)
under RFC-0030 §3 capped Policy 3 plans (`b in {2, 3, 4}`, `T = 100`, QM31). Every proof verified
cleanly, and the body byte count matches the E19-01 model in Section 2 to the single byte (plus
the fixed `2 + 3 * L` byte verifier-checked plan header for `NC-0633`):

| Entries | Plan levels `(ell, m, b)` | E19-01 model (B) | Measured body (B) | Header (B) | Total proof (B) |
|---|---|---:|---:|---:|---:|
| `2^20` | `(6,14,4) -> (3,11,4)` | 299,344 | 299,344 | 8 | 299,352 |
| `2^22` | `(6,16,4) -> (4,12,4)` | 373,600 | 373,600 | 8 | 373,608 |
| `2^24` | `(7,17,4) -> (5,12,4)` | 474,288 | 474,288 | 8 | 474,296 |
| `2^26` | `(6,20,2) -> (4,16,4) -> (4,12,4)` | 605,184 | 605,184 | 11 | 605,195 |
| `2^28` | `(9,19,2) -> (4,15,4) -> (4,11,4)` | 984,736 | 984,736 | 11 | 984,747 |

Independent Python parity is verified by
`uv run --offline --script research/rfc0029-pcs/verify_recursive.py` (10 seeded QM31 vectors:
5 honest acceptances across `L = 1, 2, 3` and 1-/2-claim fresh batching with bit-exact transcript
continuation, plus exact rejection parity on `NC-0630..0634`).
