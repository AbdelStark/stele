# Q26: complete causal numerical model

Question: can the exact decoder blocks compose with embeddings, final norm,
vocabulary projection and greedy stopping, while preserving all row/channel
units and full/cache equality on both synthetic models and a pinned checkpoint?
Cost terms: T_witness/c_a/c_x/T_misc. Kill criteria: oracle disagreement, tied
weight reinterpretation, inconsistent layer units, a non-lowest argmax tie,
incorrect stopping or a partially advanced cache after failure. Research only;
native GPT-2/Llama parity, fidelity and the private proof remain required.

## Selected semantics and checks

`causal_model.py` gathers vocabulary-major embedding codes with their row scales
directly into the first residual units. Block output units must match the next
norm's input units, including the final norm. Final wide norm output converts
once to whole-row int8 before the vocabulary projection; all logits share an
explicit fractional exponent and must fit int16. A tied head reuses the identical
embedding matrix and per-vocabulary scales. Draft RFC-0004 A9 records these choices.

Every returned token, including a generated EOS, has a completed model state.
Greedy selection uses the lowest maximal vocabulary id; stop at generated EOS or
the requested new-token count. Prompt EOS is ordinary input. Failed layers or
head evaluation expose no new cache. `check_generation` performs full numerical
replay; it is not a private, succinct or production proof verifier. Cache scope
checks do not authenticate its values or associate them cryptographically with tokens.

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py`.
Seed 2631 checks 10,000 models: 9,412 accepted and 588 oracle-matched rejections.
All accepted cases compare every residual cut, final norm, head input and logit
against independent block/NumPy/Fraction arithmetic, then compare full/cached
execution. There are 94 greedy replay cases plus EOS, zero-limit, lowest-tie,
source-scope, coherent mixed-unit and late-failure controls. Shared certified
nonlinear primitives retain the earlier independent table evidence.
Corpus SHA-256: `9ecded18e4cd7a628de43625a31223356e594c67291c5ab2f6aa57e5e05dc4eb`.

## Pinned checkpoint

The [public test checkpoint](https://huggingface.co/trl-internal-testing/tiny-random-LlamaForCausalLM/tree/2c542e4731d42d3bb68324c4eca16df9f93b8b33)
supplies 1,032,272 parameters across 21 selected tensors. `causal_checkpoint.py`
checks the original config/weight SHA-256 values before preparation. Two named
stored frequency buffers are explicitly ignored; their original bytes remain
covered by the source hash. All learned tensors are converted, including both
vocabulary matrices and all five gains. This is a pinned fixture, not a general
HF lowerer. No downloaded code or pickle is executed.

Explicit choices are int8 weights, Q12 wide paths/logits, Q14 gains, exact
epsilon 1/1000000, nearest exp (B,F,E)=(15,7,12), score factor 1/2 and split/base
RoPE with theta=10000 over 2048 positions. The absent rotary settings are explicit
choices consistent with the [versioned architecture implementation](https://github.com/huggingface/transformers/blob/v4.28.0/src/transformers/models/llama/modeling_llama.py#L94),
not unspecified runtime defaults. No float-serving equivalence is claimed.
The exact model reproduces the oracle and full/cache paths for prompt ids
[0,42,1337,31999], generating [27247,12888] at limit 2. Source hashes, preparation
identities, choices and logit checksum are in [the fixture](causal-checkpoint.json).
The test model is randomly initialized; these results are correctness evidence,
not language quality, benchmark performance, calibration or §8 fidelity evidence.

Reproduce with `--checkpoint PREFIX`, where PREFIX-config.json and
PREFIX-model.safetensors contain the pinned files. CI downloads those exact
revisions and checks the fixture. `--write` creates a new fixture only after
oracle and full/cache comparisons; normal validation never regenerates it.

## Costs and remaining work

Embedding adds O(n*d), final norm O(n*d), vocabulary projection O(n*V*d) and
greedy selection O(V) per token to block witness work. No proof weight-pass or
cut changes; no measured cost constant. The candidate caps total matrix codes
and conservative retained payload cells at 2^22 each; Python overhead and block
scratch are additional. Immutable cache copying/validation scans prior rows.
These research limits and allocations are not full-model serving capacity claims.

Continue Q26: canonical model/quantiser/config/source-role bytes, complete static
schemas, native Rust/NumPy GPT-2-small and Llama-3.1-8B execution, sampled decoding,
fidelity, actual proof consumers and joint PCS/ZK remain required. All original
task criteria remain. No production NC-0107/0108, profile or inference-proof credit.
