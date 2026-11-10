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
| FlashProve technical report and repository (Anthropic, Nov 2026; `guide/`, `docs/model.md`, `docs/protocol.md`, `lean/THEOREM.md`) | the system to beat: committed step values per segment, virtual arithmetic, one weight opening per batch, masked sumcheck, link proofs, the Lean statement and its stated gaps |
| Novakovic–Angeris, Ligerito (2025/1187); TensorSwitch (2025/2065); WHIR (2024/1586) | recursive interleaved-code openings, code switching, proof-size reference points (RFC-0029) |
| Diamond–Gruen, proximity gaps in interleaved codes (2024/1351); Angeris–Evans–Roh (2024/1399); Khatam (2024/1843) | proven radii for interleaved and general linear codes under tensor-structured combination (Q39) |
| Ben-Sasson–Carmon–Haböck–Kopparty–Saraf (2025/2055); Diamond–Gruen (2025/2010); Crites–Stewart (2025/2046) | what is proven up to the Johnson bound, and why capacity conjectures are not a fallback |
| Chiesa–Fenzi–Weissenberg (2026/391); VEIL (2026/683) | zero knowledge for hash-based sumcheck arguments: bounded-query encodings with masked sumcheck, or pad-and-prove (RFC-0013 A2) |
| Ben-Sasson–Chiesa–Spooner (BCS16); Chiesa–Yogev, *Building Cryptographic Proofs from Hash Functions*; Block et al. (2023/1071) | round-by-round soundness and its compilation to the random-oracle model (RFC-0030) |
| Khovratovich–Rothblum–Soukhanov (2025/118); Fenzi (2026/1838) | the Fiat–Shamir attack on proofs whose statement can encode the hash, and the statement-binding fix |
| Soukhanov, logup* (2025/946) | indexed lookups that commit a table-sized vector and no outputs (Q35) |
| Bagad–Dao–Domb–Thaler (2025/1117); Dao et al. (2026/587); Gruen (2024/108); Dao–Thaler (2024/1210) | small-value rounds, split-eq, univariate skip, streaming: the CPU and GPU sumcheck fast paths (E20) |
| "LLM Inference in a Flash!" (arXiv 2609.16161); SmoothQuant; I-LLM (arXiv 2405.17849) | integer-only W8A8 with equalisation, group scales and 16-bit norm and softmax inputs (Q36) |
| Ethereum Foundation `soundcalc` reports; inferenceproofs.ai | how deployed systems state bits of security; a public cross-system benchmark normaliser |
| ArkLib, VCVio, CompPoly (Lean 4) | starting libraries for R-FORMAL (E21-06) |
