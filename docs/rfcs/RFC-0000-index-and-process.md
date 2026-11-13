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
| 0001 | First principles, statement, architecture | Accepted (A3, A4); A1, A2 superseded by A3 |
| 0002 | Threat model, security and soundness requirements | Accepted (A1) |
| 0003 | Fields: M31, CM31, QM31, octic; dual-prime option | Accepted (A1, A5); A2–A4 superseded by A5 for RFC-0025 |
| 0004 | CQIS — Canonical Quantised Inference Semantics | Accepted (A1, A4, A5, A13, A14, A15); A2 superseded by A4; A3, A6–A12 superseded by A13 |
| 0005 | Tensor IR, claim graph, witness capture | Accepted (A1, A2, A3, A5, A6, A7); A4 superseded by A5 |
| 0006 | Sumcheck engine and layer-stacked GKR core | Accepted (A1, A2, A3, A4, A5, A6, A7, A8) |
| 0007 | Matmul reduction, residual cuts, four-phase weight passes | Accepted (A1, A2, A3, A4, A5, A6, A7); A8 Draft |
| 0008 | Lookups: LogUp-GKR, table registry, range discipline | Accepted (A2, A3, A4, A5, A6, A7 conditional, A8); A1 Draft |
| 0009 | Attention protocol | Accepted (A1, A4); A2, A3 superseded by A4 for RFC-0025 |
| 0010 | Interleaved-code PCS, fused opening, certified commitments | Accepted (A1, A2, A3, A4, A5, A6, A8, A9, A10, A11, A12, A13, A14, A15); A7 Draft |
| 0011 | Model passport and checkpoint binding | Accepted (A2, A8); A1 Draft; A3–A7 superseded by A8 for RFC-0025 |
| 0012 | Transcript, Fiat–Shamir, soundness accounting | Accepted (A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18) |
| 0013 | Zero-knowledge | Accepted (A2, A4, A5, A6, A7, A8, A9, A10, conditional; dev-zk admitted at the development tier, ADR-109; A8 byte 4, ADR-114; A9/A10 stories42M T ≤ 64, ADR-117/119); A1, A3 Draft |
| 0014 | GPU prover architecture | Accepted (A1) |
| 0015 | Distributed proving | Accepted (A1) |
| 0016 | Verifier, proof format, recursion wrapper | Accepted (A4); A1 Draft; A2, A3 superseded by A4 |
| 0017 | Architecture coverage: GQA, MoE, MLA, windows, sampling | Accepted (A3); A1, A2 superseded by A3 |
| 0018 | Benchmarks, targets, cost-model protocol | Accepted (A1, A2) |
| 0019 | Research agenda | Research |
| 0020 | Monorepo and crate architecture | Accepted (A1, A2, A3, A4, A5, A6, A7, A8, A9) |
| 0021 | Canonical nonlinear functions, tables and representations | Accepted (A3); A1, A2 superseded by A3 |
| 0022 | Closed static arithmetic records | Accepted |
| 0023 | Integer Requant with a fixed advice cut | Accepted (A1) |
| 0024 | Centered signed-int8 matmul and Requant | Accepted |
| 0025 | Canonical full-model CQIS and checkpoint conversion | Accepted (A1, A2, A3) |
| 0026 | Development-profile end-to-end prefill proof | Accepted (A1, A2, A3, A4, A5, A6, A10, A11, A12, A13, A14; A9 conditional); A7, A8 Draft |
| 0027 | Build program: tiers, ladder, lanes and milestones | Accepted |
| 0028 | Relation IR v2: the commit rule, virtual columns and segments | Draft |
| 0029 | Commitment scheme v3: interleaved circle Reed–Solomon with a recursive opening | Draft |
| 0030 | Security accounting: round-by-round error, Fiat–Shamir and the profiles | Draft |

RFC-0027 §2 adds a shortened acceptance path for development-tier protocol changes; §2 above is unchanged for
everything a `standard` or `treaty` proof depends on.

## 5. Notation used everywhere
`F = F_p`, `p = 2^31 − 1`; `K = QM31 = F_{p^4}`; `x̃` = multilinear extension of the tensor `x` over `{0,1}^{log|x|}`
(row-major, dimensions padded to powers of two, padding = 0); `eq(a,b) = ∏(a_i b_i + (1−a_i)(1−b_i))`;
a *claim* is `(tensor id, point ∈ K^m, value ∈ K)`; a *reduction* consumes claims and emits claims;
`ℓ` is always the layer index, `i` a position, `j` an output feature, `k` an inner feature, `s` a head.
