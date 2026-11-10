# State of the art (October 2026) — what exists, what it costs, what Stele takes from it

This note is the research basis for the design. Numbers are either *reported* by the cited source, or
*derived* here (marked ∂). Treat ∂ numbers as order‑of‑magnitude.

## 1. Proof‑of‑inference systems

| System | Family | Arithmetic | PCS / field | Hardware | Reported rate | Proof | Notes |
|---|---|---|---|---|---|---|---|
| **SASH zk‑inference‑prover** (open, Sep 2026) | commit‑the‑trace Circle STARK (Stwo fork + NitrooZK CUDA), LogUp, Freivalds for weight matmuls, 5 sumcheck‑style reductions | int8 matmuls (per‑token dyn. scale), bf16 elsewhere via lookups | Blake2s Merkle + circle FRI, M31 | 1×H100 | Llama‑3.1‑8B, 4096+512: **1.0–1.5 h** (1.25 pos/s loop; 16 pos/s proof‑system ceiling; 27 pos/s commit ceiling) | 18.5 GiB (4.3 MB/pos) | 79 M committed cells/position; proof system = 5% of time; not ZK; 100‑bit conjectural; 405B projected 16–24 h |
| **Attestable** (closed, 2026) | hash‑based, family undisclosed | int8 matmuls, floats elsewhere | hash only, 100‑bit | 1×H100 | Llama‑8B b4: 195 tok/s; Gemma‑4‑31B: 53–77 tok/s | 4.3–7.9 MiB | ≤16k ctx; proves seed+policy |
| **DeepProve** (Lagrange, CCS'26, ePrint 2026/1112) | sumcheck + LogUp‑GKR (Ceno lineage) | 12‑bit ints | HyperKZG/BN254 (trusted setup) | 16–24 CPU cores; distributed | GPT‑2 124M: 174 tok/min; 1,855 tok/min distributed | 24 MiB | commits only layer I/O; curve PCS is the ceiling |
| **zkLLM** (CCS'24) | sumcheck/GKR + tlookup, zkAttn | fixed point | Pedersen/Hyrax, BLS12‑381 | A100 | Llama‑2‑13B, 2048 pos in 803 s | <200 kB | 255‑bit field arithmetic is the ceiling |
| **OpenLLM** (2026) | sumcheck | fixed point | — | 32‑core CPU | Qwen‑3‑8B one pass 258 s | 55.7 MB | |
| **FlashProve** (Anthropic, open, README at `9e2bdd8`) | zkSNARK over the committed weights; ZK | 4‑bit weights (Maverick) | not compared here | 1×H100 80 GB | Llama 4 Maverick, 1,024‑token context: ~110 tok/s prefill at 24 requests/batch; route 3 "small model" (8‑layer synthetic): 23–30 s commit+prove+verify, 10 GB RAM | ~19 MB per 1,024‑token request | statement and figures from the README and `guide/performance.md`; Stele's development comparison is in `docs/development-e2e.md` |
| **zkPyTorch / zkGPT / Jolt Atlas** | GKR / Lasso / Shout‑style lookups over ONNX | fixed point | various | CPU | 150 s/pos (8B, zkPyTorch) | | Jolt Atlas: DAG of sumchecks, streaming, BlindFold ZK |
| **VerInf** (2026 draft) | interactive, info‑bound statement | int64 | | DGX Spark | 400B MoE 1000 pos: 14.3 h, 93.6 GB | | different statement |
| Seal‑then‑Sample (arXiv 2609.27367) | DeepProve backend, sampled layers to 70B | | HyperKZG | | | | sampling as cost lever |

### 1.1 Where SASH's time goes (reported)
- Interaction (lookup) columns 42%, base trace 35%, segment setup 12%, proof system 4.6% (GPU).
- Attention tiles 15% of cells and the only term that grows with context; dequantisation 24%; residual‑stream ops 24%.
- **Weights appear nowhere in the per‑position cost** (Freivalds + preprocessed Merkle tree) — the right idea, applied inside the wrong paradigm: every *activation* and every *lookup* still becomes a committed, LDE'd, hashed cell.

### 1.2 ∂ Cost per unit of work
- SASH proof system: 1.3·10⁹ cells/s on an H100 that does ~10¹³ 32‑bit int ops/s ⇒ **≈ 7,000 int‑ops per committed cell** (hashing + LDE + quotient + FRI).
- A LogUp‑GKR lookup (RFC‑0008): ≈ 3 QM31 mults at the leaves + sumcheck work ≈ **60–150 M31 mults** per lookup, no hashing.
- A weight element in a sumcheck matmul (RFC‑0007): 1 base×QM31 MAC ≈ 4 M31 mults, or ≈ 4 adds with bucketing (int4/int8) ⇒ bandwidth‑bound.
⇒ Per *element*, sumcheck/GKR is ~50–100× cheaper than a committed cell, and the number of elements per position is ~10× smaller (no per‑MAC cells, no requant columns). Both factors compound (RFC‑0018).

## 2. Proof‑system primitives (2024–2026)

| Primitive | Source | What Stele uses it for |
|---|---|---|
| Sumcheck matmul, O(data) prover | Thaler 2013 | every matmul (RFC‑0007) |
| GKR, data‑parallel/SIMD GKR | GKR08, Libra, Expander docs | layer‑stacked reductions: the layer index is the SIMD index (RFC‑0006) |
| LogUp, LogUp‑GKR | Haböck 2022; Papini–Haböck 2023 | commitment‑free lookups for all nonlinearities (RFC‑0008) |
| Small‑value & streaming sumcheck provers; product‑of‑many‑polys algorithm | Bagad–Dao–Domb–Thaler 2025/1117, Dao–DeStefano–Bagad–Domb–Thaler 2026/587; Dao–Thaler | base‑field first rounds, memory reduction (RFC‑0006 §5, RFC‑0014 §4) |
| eq‑polynomial / univariate‑skip optimisations | Gruen 2024 | zerochecks and eq‑weighted sumchecks (RFC‑0006 §5) |
| Twist & Shout, Lasso decomposition | Jolt 2025/26 | decomposable tables (exp, rsqrt); prefix–suffix structure for streaming (RFC‑0008 §4) |
| Circle group over M31, circle FFT | Haböck–Levit–Papini 2024/278; Stwo | *one‑time* RS encoding of weight commitments only (RFC‑0010 §3); recursion wrapper (RFC‑0016) |
| Ligero / Brakedown / Orion interleaved‑code PCS | AHIV17, GLSTW21 | hot‑path commitments: opening = one streaming pass over raw data (RFC‑0010) |
| Logarithmic‑randomness proximity gaps (consolidated proximity + evaluation) | Diamond–Posen 2023/24; Khatam (2025) for all linear codes | soundness of the **fused opening** (RFC‑0010 §5) |
| Ligerito, Blaze, Bolt (sketched codes), BrakingBase, DeepBrake/BrakeWHIR, LigeSIS (distributed) | 2025–2026 | succinct column dimension / proof size; distributed PCS (RFC‑0010 §7, RFC‑0015) |
| BaseFold / WHIR / STIR | ZCF23, ACFY24 | not on the critical path (FFT‑bound openings); candidate for the wrapper's PCS |
| ZK for sumcheck‑based SNARKs with small overhead (BlindFold) | Thaler 2025 (used by Jolt Atlas) | treaty‑profile zero‑knowledge (RFC‑0013) |
| Negative controls, digest gate, agent‑built GPU backend | SASH repo practice | adopted and extended (INV‑3, INV‑4) |

## 3. The gap, stated

Vanilla STARK → Circle STARK moved the cost of a **field operation** down ~10×. Commit‑the‑trace systems still
pay ≈ 10³–10⁴ field‑op‑equivalents per *computed value*. The inference‑native design pays ≈ 10² per *nonlinear
value*, ≈ 4 per *weight byte*, and **0 per multiply‑accumulate**. For a transformer with inner dimension d, the
MAC count exceeds the value count by a factor of d (10³–10⁴). That factor, not the field, is the next gap.

## 4. What we deliberately do not take

- A zkVM or gate‑level circuit layer (stwo‑circuits, Cairo): generality we do not need and a 10³× cost we cannot afford.
- Curve‑based PCS (HyperKZG, Hyrax): trusted setup or 255‑bit arithmetic, not post‑quantum.
- FRI/WHIR openings on the hot path: they need the codeword (2–4× the data) in memory per opening and an FFT; the fused interleaved‑code opening needs the raw packed weights once.
- bf16 lookups for nonlinearities (SASH): we use int16 fixed point; same table sizes, no rounding‑chain gadgets.
- Trace segments as the unit of parallelism: we parallelise over *layers and heads inside one proof* (stacked GKR), which keeps one weight pass per proof instead of one per segment.

## 5. Update, November 2026: FlashProve and what it settles

Sources: the FlashProve repository at v0.16.0 (`README.md`, `guide/performance.md`, `guide/known-limits.md`,
`docs/model.md`, `docs/protocol.md`, `lean/THEOREM.md`) and its technical report. All figures are *reported*.
Its statement differs from Stele's development proofs (zero knowledge, GPU, fixed 1,024-token window).

| Aspect | FlashProve |
|---|---|
| Statement | post-hoc prefill of an integer model; checked tokens are the greedy choice; no sampling; fixed 1,024-token window; up to 64 requests share one weight opening |
| Model and numerics | Llama 4 Maverick (48 layers, d 5,120, 128 experts, top-1 routing); 13-bit weights from a public 4-bit file; 12-bit clamped activations; static per-layer power-of-two shifts; tables of at most 2^16 entries |
| Field and commitment | Goldilocks with a cubic extension; interleaved Reed–Solomon (rate about 0.10), BLAKE2b Merkle columns; fold and code-switch proximity test in the list-decoding regime under a proven theorem (ePrint 2025/2055) |
| Argument | masked sumchecks (about 2,000 per request); lookups by grand-product trees; Thaler matmul on committed weights; step values committed per segment (25 segments); approximate range checks by 128 random ternary projections |
| Zero knowledge | bounded-query encodings with an opening budget, linked fresh copies, committed masks; Lean-checked for single requests; a declared list of what is not hidden |
| Soundness | "about q/2^124 + 2^-101" for the Lean verifier; the C++ verifier and the CUDA prover are not covered by the theorem |
| Performance | 17.4 tok/s for one request (58.8 s), 111 tok/s at batch 24, 123 tok/s at batch 64; proof 18.78 MB; verification 17 to 21 s; commit 39 min; 257 to 300 GB host RAM |
| Fidelity | top token differs from the 16-bit float model at 6.81% of positions; no task benchmark; no reply served by a float engine passes exact match |

What it settles for Stele:

1. **The shape works at 400B on one GPU.** Sumcheck over committed step values, virtual arithmetic, one weight
   opening per batch, segments to bound memory. §3's gap argument holds; the remaining gap is constants.
2. **Step values are committed.** No published sound system leaves the outputs of rounding and tables
   uncommitted. RFC-0001 §1.4 item 1 was too strong (`docs/assessment.md` §5; RFC-0028, Draft).
3. **Reed–Solomon on the per-proof path is affordable on a GPU.** §4's rejection of FFT-based encoding for per-proof
   commitments is withdrawn for the witness; it stands for the weights (no codeword over the weights per proof).
4. **The field question is open, not closed.** FlashProve pays for 64-bit arithmetic to gain headroom for
   approximate range checks. Stele keeps M31 and exact lookups; bet B2 of `docs/plan.md` states the measurement
   that would change this.
5. **Where it is weak is where to be strong:** single-request latency, proof size, verifier time, context length,
   fidelity measured on tasks, sampling, multi-GPU.

Other reference points since §1 was written (each self-reported; see `docs/assessment.md` §6): Attestable claims
4 to 8 MiB proofs and sub-second verification on a dense 31B model; a public cross-system benchmark
(inferenceproofs.ai) normalises cost per token per bit of active weights; integer-only W8A8 inference with
equalisation and 16-bit norm and softmax inputs is reported near float perplexity on Llama-3.1-8B
(arXiv 2609.16161).
