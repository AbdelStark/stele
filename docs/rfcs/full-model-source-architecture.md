# RFC-0025 source architecture and role binding

Status: Accepted. Part of [RFC-0025](RFC-0025-full-model-cqis.md), Q26/E5-03b.
This record joins original config bytes to Model's architecture, norm epsilon,
rotation and the complete source-role map. Tokenizer execution, generation
policy, outer authentication and actual proof consumers remain separate.

## 1. Explicit source layouts

The independently expected layout tag selects one closed adapter:

| Tag | Model family | Source names and rotary layout |
|---|---|---|
| 0 | GPT-2 | Bare Hugging Face transformer names, such as `wte.weight`. |
| 1 | GPT-2 | The same names with `transformer.` prepended. |
| 2 | Llama | Hugging Face `model.*` names, with an unprefixed `lm_head.weight` and split-half rotary channels. |

The reference definitions are pinned to Transformers commit
`174890280b340b89c5bfa092f6b4fb0e2dc2d7fc`:
[GPT-2 configuration](https://github.com/huggingface/transformers/blob/174890280b340b89c5bfa092f6b4fb0e2dc2d7fc/src/transformers/models/gpt2/configuration_gpt2.py),
[GPT-2 model](https://github.com/huggingface/transformers/blob/174890280b340b89c5bfa092f6b4fb0e2dc2d7fc/src/transformers/models/gpt2/modeling_gpt2.py),
[Llama configuration](https://github.com/huggingface/transformers/blob/174890280b340b89c5bfa092f6b4fb0e2dc2d7fc/src/transformers/models/llama/configuration_llama.py),
and [Llama model](https://github.com/huggingface/transformers/blob/174890280b340b89c5bfa092f6b4fb0e2dc2d7fc/src/transformers/models/llama/modeling_llama.py).
These establish field meanings, names and layout. They do not replace CQIS
arithmetic, certify a checkpoint publisher or authorize source-code execution.
Meta's original adjacent-pair layout is not tag 2. No tag is inferred from shape.

## 2. Original JSON and closed absence rules

Parse the authenticated config file as strict UTF-8 JSON with unique keys at
every depth, no nonfinite tokens and a top-level object. Reject unpaired
surrogates. The file is at most 1 MiB, with at most 65536 values/keys, depth 32
and 65535 UTF-8 bytes per string. Integer tokens retain signed magnitude at
most 2^64-1 and cannot stand for Boolean values. Decimal tokens have at most
64 characters and exponent magnitude 64; parse them exactly as reduced
rationals with numerator/denominator at most 256 bits. Never cast through a
host float. Dimensions and token ids require integer tokens, not `12.0` or
Booleans. Norm/rotation numeric fields accept integers or exact decimal values.

Both families require `architectures` to contain exactly their causal-LM class,
the exact `model_type`, all dimensions below, activation, norm epsilon,
`bos_token_id` and `eos_token_id`. EOS is one id or a nonempty list of distinct
ids, normalized into sorted order. BOS/EOS and an optional non-null
`pad_token_id` must lie inside the declared vocabulary. Absent/null padding
means no pad token; it does not insert padding into a request. No automatic BOS,
EOS, chat formatting or generation-policy choice follows from this record.

For GPT-2 require `GPT2LMHeadModel`, `gpt2`, `gelu_new`, and integer fields
`n_layer`, `n_embd`, `n_head`, `n_positions`, `vocab_size`. Width is divisible
by heads; groups equal heads and FFN width is four times residual width.
If `n_ctx` is present it equals `n_positions`. Absent/null `n_inner` resolves
explicitly to four times width; a supplied value must equal that width.
`layer_norm_epsilon` supplies the exact reduced positive u32 numerator/denominator.
The closed absent values are `scale_attn_weights=true`,
`scale_attn_by_inverse_layer_idx=false`, `reorder_and_upcast_attn=false`,
`add_cross_attention=false`, `is_encoder_decoder=false`,
`tie_word_embeddings=true`. A present value must be that exact Boolean.

For Llama require `LlamaForCausalLM`, `llama`, `silu`, and integer fields
`num_hidden_layers`, `hidden_size`, `num_attention_heads`, `intermediate_size`,
`max_position_embeddings`, `vocab_size`. Width is divisible by heads and full
head width is even. Absent/null `num_key_value_heads` resolves explicitly to
the query-head count; a supplied count divides it. A supplied `head_dim`
equals the derived head width. `rms_norm_eps` supplies exact reduced positive
u32 numerator/denominator. Closed absent values are `attention_bias=false`,
`mlp_bias=false`, `tie_word_embeddings=false`, `add_cross_attention=false`,
`is_encoder_decoder=false`, `pretraining_tp=1`. Supplied values must match.

Llama requires explicit `rope_theta`. Absent/null `rope_scaling` means base
rotation with factor one, zero thresholds and original length zero. Otherwise
the exact keys are `rope_type` (or legacy `type`) and `factor` for linear
rotation; llama3 also requires `low_freq_factor`, `high_freq_factor` and
`original_max_position_embeddings`. If both type spellings occur they agree.
Unknown modes/keys reject. Rational fields obey Rotation's full domains; its
width is the full head width, length is context capacity and layout is split.
The normalized shape and rotation retain the complete configured domains.

Only the following nonarchitectural fields are recognized:
`_name_or_path`, `_commit_hash`, `transformers_version`, `torch_dtype` as
strings/null; `return_dict`, `output_attentions`, `output_hidden_states`,
`use_cache` as Booleans; nonnegative numeric `initializer_range`; and bounded
object/null `task_specific_params`. GPT-2 also permits numeric
`resid_pdrop`, `embd_pdrop`, `attn_pdrop`, `summary_first_dropout` in [0,1],
string/null `summary_type`, `summary_activation`, and Boolean
`summary_use_proj`, `summary_proj_to_labels`. Llama permits `attention_dropout`
in [0,1]. These fields remain in Assets' exact file hash but never select CQIS
execution, casts, initialization, dropout, cache policy or generation defaults.
CQIS executes deterministic inference on complete token sequences; summary
heads are outside these causal-LM classes. Unknown fields reject rather than
selecting an unmodeled architecture, remote code or an inference backend.

## 3. Model and complete role-map joins

Require Model's exact Shape, every norm's epsilon and every Llama rotation to
equal the derived architecture. Model validates its complete physical formats,
norm/activation kinds and units independently. CQIS fractions, score multiplier,
table representations, accumulation and decoding remain explicit Model choices;
this adapter does not derive them from host defaults or claim float fidelity.
Context is the full source capacity, not a smaller request-dependent dimension.

For GPT-2 the chosen prefix applies to `wte.weight`, `wpe.weight`,
`ln_f.weight/bias`, and each `h.i.ln_1.weight/bias`, `h.i.ln_2.weight/bias`.
Q/K/V use the three prescribed parts of `h.i.attn.c_attn.weight/bias` with
fused-column/fused-bias transforms. O, up and down use transposes of
`h.i.attn.c_proj.weight`, `h.i.mlp.c_fc.weight`, `h.i.mlp.c_proj.weight`;
their corresponding biases use copy. Other listed roles use copy. The only
optional alias is unprefixed `lm_head.weight` targeting token record zero.
It cannot be ignored instead of checked for raw-byte equality.

For Llama, token/final/head use `model.embed_tokens.weight`, `model.norm.weight`,
`lm_head.weight`. Per layer, norm1/norm2 use
`model.layers.i.input_layernorm.weight` and `post_attention_layernorm.weight`;
Q/K/V/O use `self_attn.q_proj/k_proj/v_proj/o_proj.weight`, and up/gate/down use
`mlp.up_proj/gate_proj/down_proj.weight` under that same layer prefix. Every
transform is copy; no physical alias is permitted. Raw dtype remains explicit
in Map and is checked against the actual immutable source tensor.

The only permitted ignored names are GPT-2's prefixed `h.i.attn.bias` and
`h.i.attn.masked_bias`, or Llama's
`model.layers.i.self_attn.rotary_emb.inv_freq`, within the declared layers.
These legacy buffers are not loaded by this adapter. CQIS derives causal masks
from indices and rotary coefficients from the complete Rotation/Registry.
They still receive Source's whole-file and structural coverage checks; ignored
names cannot replace a required physical role or supply unchecked mask data.

## 4. Canonical binding and authority

Use the encoding appendix's little-endian integers, B framing and H:

    Architecture = ASCII("stele/v0.1/cqis/source-architecture") || u8(layout)
       || Shape[21] || u32(epsilon_num,epsilon_den) || B(Rotation_or_empty)
       || u32(bos) || u8(pad_present) || [u32(pad) iff present]
       || u32(eos_count) || u32(eos_ids in sorted order)
    SourceConfig = ASCII("stele/v0.1/cqis/source-config")
       || H(Model)[32] || H(Map)[32] || H(Assets)[32] || B(Architecture)

Derive Architecture from the same config bytes whose length/SHA-256 passed
Assets verification. Validate the exact auxiliary file set and every original
file before returning SourceConfig. The JSON value-count bound limits EOS
entries to 65536; complete Architecture/SourceConfig frames fit 1 MiB.
Verification derives and compares the entire expected frame, so supplied
counts or hashes cannot choose fields or bypass Model/Map/config checks.
Define source_config_id=H(SourceConfig).

The passport must authenticate this adapter choice and SourceConfig together
with the same Model, Preparation/Map, Source/Assets and converted Artifact.
Matching supplied hashes do not provide expected authority. Tokenizer vocabulary,
special-token insertion, generation/stop-policy joins, traffic commitments and
stored-source/proof consumers remain required. This record does not establish
tokenization, actual source payload conversion or a proof-admission handle.
Config parsing and role checks are preparation T_misc, with no new challenge,
cut, online weight pass, native control credit or measured constant.
