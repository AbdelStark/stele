# Reading list — what to extract from each source

| Source | Extract |
|---|---|
| Thaler, "Time-optimal interactive proofs for circuit evaluation" (2013) | matmul sumcheck §4; the `O(n·d + d·m)` prover |
| GKR08; Xie et al. "Libra" (2019) | layered reductions; SIMD/data-parallel trick (used as layer stacking) |
| Haböck "Multivariate lookups based on logarithmic derivatives" (2022); Papini–Haböck "Improving logarithmic derivative lookups using GKR" (2023) | LogUp identity, selectors, fraction-tree GKR, soundness `N/|K|` |
| Bagad–Dao–Domb–Thaler 2025/1117; Dao–DeStefano–Bagad–Domb–Thaler 2026/587; Bagad–Domb–Thaler 2024/1046 | small-value prover, product-of-many, streaming prover; extension-field cost ratios |
| Gruen, "Some improvements for the PIOP for ZeroCheck" (2024) | eq-trick and univariate skip |
| Haböck–Levit–Papini "Circle STARKs" (2024/278) | circle group, circle FFT (one-time encoding), proximity for circle codes |
| Ben-Sasson et al. "Proximity gaps for Reed–Solomon codes" (2020) | proven gap up to Johnson bound (treaty PCS params) |
| Diamond–Posen, logarithmic randomness (2023) and FRI-Binius (2024) | tensor-structured combination suffices; consolidation of proximity + evaluation |
| Khatam (2025) | multilinear-evaluation proximity gaps for all linear codes (RAA codes) |
| Ligero (AHIV17), Brakedown (GLSTW21), Orion, Blaze, Bolt (2026/310), Ligerito (NA25), DeepBrake (2026/1561), LigeSIS (2026) | interleaved-code PCS, linear-time codes, succinct columns, distribution |
| Jolt / Twist and Shout / Jolt Atlas (2026) | claim-graph organisation, streaming, BlindFold ZK |
| Thaler, BlindFold (2025) | ZK masking for sumcheck SNARKs |
| SASH research note + repo (2026) | measured costs, negative-control practice, digest gate, segment bindings |
| DeepProve (CCS'26, 2026/1112); zkLLM (CCS'24); zkGPT (USENIX'25) | GKR zkML designs, tlookup/zkAttn, what they commit |
| SoK: hash-based PCS and LDTs (2026/1367) | parameter and conjecture landscape |
