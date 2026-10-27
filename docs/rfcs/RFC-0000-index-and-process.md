# RFC-0000 — Index and RFC process

Status: Accepted · Version: 0.1.0

## 1. Why RFCs
Stele's protocol is the product. Code is a projection of the RFCs. An agent that cannot point to the RFC section
a line of code implements has not finished the task. RFCs are written to be read by a hostile expert.

## 2. Status lifecycle
`Draft` → `Review` (soundness-auditor + two implementing skills must sign) → `Accepted` (law) → `Amended`
(append-only amendment log inside the RFC; code must follow the latest amendment) → `Superseded` (points to the successor).
Research RFCs carry `Research` status and never bind implementation.

## 3. Mandatory sections for a protocol RFC
1. Statement (what is proven, public inputs, witness)
2. Protocol (prover/verifier messages, in transcript order)
3. Prover algorithm with cost in the symbols of `docs/cost-model.md`
4. Verifier algorithm with cost
5. Soundness: error terms, which theorem each rests on, proven vs conjectural, profile table
6. Negative controls (ids in `tests/negative-controls/catalog.md`)
7. Open questions (numbered, mirrored in RFC-0019)
8. Amendment log

## 4. Index

| RFC | Title | Status |
|---|---|---|
| 0000 | Index and RFC process | Accepted |
| 0001 | First principles, statement, architecture | Accepted |
| 0002 | Threat model, security and soundness requirements | Accepted |
| 0003 | Fields: M31, CM31, QM31, octic; dual-prime option | Accepted |
| 0004 | CQIS — Canonical Quantised Inference Semantics | Accepted |
| 0005 | Tensor IR, claim graph, witness capture | Accepted |
| 0006 | Sumcheck engine and layer-stacked GKR core | Accepted |
| 0007 | Matmul reduction, residual cuts, four-phase weight passes | Accepted |
| 0008 | Lookups: LogUp-GKR, table registry, range discipline | Accepted |
| 0009 | Attention protocol | Accepted |
| 0010 | Interleaved-code PCS, fused opening, certified commitments | Accepted |
| 0011 | Model passport and checkpoint binding | Accepted |
| 0012 | Transcript, Fiat–Shamir, soundness accounting | Accepted |
| 0013 | Zero-knowledge | Accepted |
| 0014 | GPU prover architecture | Accepted |
| 0015 | Distributed proving | Accepted |
| 0016 | Verifier, proof format, recursion wrapper | Accepted |
| 0017 | Architecture coverage: GQA, MoE, MLA, windows, sampling | Accepted |
| 0018 | Benchmarks, targets, cost-model protocol | Accepted |
| 0019 | Research agenda | Research |
| 0020 | Monorepo and crate architecture | Accepted |

## 5. Notation used everywhere
`F = F_p`, `p = 2^31 − 1`; `K = QM31 = F_{p^4}`; `x̃` = multilinear extension of the tensor `x` over `{0,1}^{log|x|}`
(row-major, dimensions padded to powers of two, padding = 0); `eq(a,b) = ∏(a_i b_i + (1−a_i)(1−b_i))`;
a *claim* is `(tensor id, point ∈ K^m, value ∈ K)`; a *reduction* consumes claims and emits claims;
`ℓ` is always the layer index, `i` a position, `j` an output feature, `k` an inner feature, `s` a head.
