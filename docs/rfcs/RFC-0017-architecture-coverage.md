# RFC-0017 — Architecture coverage

Status: Accepted · Version: 0.1.0 · Depends: RFC-0004, RFC-0009

| # | Feature | Treatment | Cost impact |
|---|---|---|---|
| 1 | GQA / MQA | `K,V` indexed by group; public broadcast MLE `g(s)`; `K,V` committed-free as before | none |
| 2 | RoPE variants (NTK, YaRN, partial rotary, interleaved vs half) | public rotation tables per variant, id in `cqis_id` | none |
| 3 | QK-norm | RMSNorm reductions on `Q`, `K` per head (CQIS §5.3) | `O(n·d)` |
| 4 | MoE (top-k router, shared experts) | router logits = matmul; top-k proven by comparisons (range lookups) against the k-th score (attained gadget); expert matmuls as `MatmulW` with the routed subset of positions: `X_e = Sel_e·X` where `Sel_e` is the public-after-commitment 0/1 routing matrix (committed aux, verified against the top-k proof); stacked over `(ℓ, e)`; unused experts contribute no claims | one pass over touched experts only |
| 5 | MLA (DeepSeek) | latent `c_kv = X·W_dkv`, `K,V = c_kv·W_uk, c_kv·W_uv` as two extra `MatmulW`; decoupled RoPE key as a separate head | `O(n·d_latent)` |
| 6 | Sliding window / local-global / sinks | masks (public MLE); `N_attn = n·w·h·L` | lower |
| 7 | Logit softcap (Gemma) | `softcap_q` table before exp; LM-head softcap table | one lookup per score |
| 8 | Hidden architecture | shapes become private: wrapper-mode only, with `plan.json` as a committed witness and verifier-side structure checks in-circuit (research, RFC-0019 R-HIDE) | |
| 9 | Multi-turn, tool results, system prompts | the statement covers one token sequence; `session_id` chains proofs by committing the previous turn's `io_digest` inside the next public input | none |
| 10 | Tied embeddings, embedding scale (Gemma `√d`) | `W_lm = E`; scale folded into requant | none |
| 11 | GeLU/tanh-GeLU, SwiGLU, GeGLU | tables | none |
| 12 | Parallel attention/FFN blocks (GPT-J/NeoX) | claim-flow variant in `plan.json` (one fewer sequential stage) | none |
| 13 | Speculative decoding | verified tokens form the sequence; drafts are not part of the statement | none |
| 14 | Batch of sequences | block-diagonal mask, position index includes sequence id | none |
| 15 | Sampling (temperature/top-p/top-k, committed seed) | CQIS §7 | `O(n_gen·V)` |

Unsupported in v0.1 (fail loudly with this id): state-space layers (Mamba), convolutional stems, non-integer
positional schemes, dynamic shapes, ops with data-dependent control flow beyond routing/argmax/sampling.
