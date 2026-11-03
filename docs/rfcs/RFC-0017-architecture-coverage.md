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

## Amendment log

### A1 — Explicit GPT-2-small and Llama-3.1-8B roles

Status: Draft. Question Q26; task E5-03b. [RFC-0025](RFC-0025-full-model-cqis.md)
proposes complete numerical and configuration contracts for the original named
targets. GPT-2 requires mean-centering affine LayerNorm, learned position
embeddings, biased projections, tanh-GeLU and a tied token embedding/head;
those roles cannot be supplied by the existing RMSNorm/SwiGLU candidate.
Llama requires its actual GQA, scaled-RoPE, RMSNorm and SiLU-gated roles.
The original architecture feature table and other implementation targets remain.

Acceptance requires exact operation/source identities and the complete static
and decoding contract; source names or matching dimensions do not establish
architecture coverage. No accepted behavior, profile, new commitment or error
term changes. Source preparation and additional arithmetic are charged to
T_misc/T_witness/c_a without a benchmark claim. Full native inference and
fidelity retain their original gates; this Draft earns no model or NC coverage.

### A2 — Named-model authority and unchanged architecture coverage

Status: Draft. Question Q26; task E5-03b. Companion RFC-0004 A12.
Motivation: A1's required physical roles now have complete numerical and source
definitions, while the broader architecture feature table remains required.

For GPT-2-small and Llama-3.1-8B, use the complete RFC-0025 Model, SourceConfig,
physical role map and operation expansion. GPT-2 uses exact-mean affine
LayerNorm, learned positions, biased projections, tanh-GeLU and the identical
physical token/head source. Llama uses its declared GQA, RMSNorm, scaled RoPE,
SiLU/up product and distinct head. Complete dimensions, context, vocabulary and
source configuration must match each named target. Smaller fixtures prove no
named-model result. Explicit configuration replaces host defaults.

The existing feature table remains authoritative for its other families and
extensions. The closed RFC-0025 adapter must reject unsupported source features;
that rejection does not complete or cancel their E13 tasks. Top-k, chaining,
parallel blocks, hidden shapes and traffic interfaces retain their own contracts.
E5-04/05 retain full native parity and fidelity; E8 retains W8 and E9 retains
the complete 8B workload. NC-0110/0113..0121 cover the new family/source edges.
No challenge, profile, cut, measured constant or proof weight-pass change.
Preparation and additional arithmetic retain T_misc/T_witness/c_a costs.

### A3 — Accept both mandatory model contracts

Status: Accepted. Question Q26; task E5-03b.
Review: [coordinated skill sign-offs](../../agents/reviews/full-model-cqis-draft.md#coordinated-acceptance-sign-offs).

Motivation: both mandatory families now have complete numerical/source definitions.
Exact replacement for their architecture descriptions: adopt A2's complete
GPT-2-small and Llama-3.1-8B contract through
[RFC-0025](RFC-0025-full-model-cqis.md). A1/A2's partial proposals are superseded.
Every named dimension, physical role, configured norm/activation/position/
attention choice and original source join is mandatory; a smaller fixture
cannot claim either named result.

All other feature-table entries and E13 extensions remain required. Rejecting
unsupported features does not complete their tasks. Full native parity/fidelity,
W8, 8B, top-k/chaining and all original source controls remain. No new challenge,
profile, cut, loss, measured constant or online weight pass. Preparation and
arithmetic retain T_misc/T_witness/c_a costs. Affected tasks: E5-03b/03/04/05,
E6, E7, E8, E9 and E13.
