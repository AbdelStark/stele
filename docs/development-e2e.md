# Running the development end-to-end prover

This page shows how to prove and verify one prefill window under the RFC-0026
development profile. The profile claims no security level: FS is unproven, the PCS is
conjectural, and the proof reveals the model and the activations (RFC-0026 §1.2).

## What runs

`stele_prover::development` takes canonical Model, Preparation, Scales and Artifact
bytes, a power-of-two token window `x_0..x_{T-1}`, a checked range `[r, e)` and, when
`e = T`, the next token `y`. It:

1. commits the weight matrices once, stacked into RFC-0010 Circle sources at rate 1/4
   under Policy 2 (the model commitment; RFC-0026 A11);
2. runs `Executor::capture` and declares every RFC-0026 §5 module in order;
3. assigns the witness, runs the plain checker, then the relation engine;
4. writes a `stele-dev-e2e-v1` container (`stele_proof::development`, RFC-0026 §4.1).

The verifier rebuilds the relation from the Model, Scales, Preparation, the public
1-D records (RFC-0026 A2) and the statement, verifies the model-commitment
certificates and replays the engine. It prints the RFC-0026 §6 ledger.

## Tests

```sh
export PATH="$HOME/.cargo/bin:$PATH"
# 1-layer windows (T = 16, plain and grouped rows), statement and container tampers.
cargo test -p stele-prover --test development
# The 8-layer acceptance window (T = 64), release build.
cargo test --release -p stele-prover --test development -- --ignored --nocapture
# RFC-0026 §9 controls NC-1300, 1301, 1304, 1305 and 1309 through the real verifier.
scripts/gates/negative-controls.sh --coverage
```

The synthetic models live in `crates/stele-prover/tests/fixtures/synthetic-e2e.{json,bin}`.
Regenerate them with:

```sh
cd research/cqis-model-contract
uv run --script synthetic_e2e.py ../../crates/stele-prover/tests/fixtures
```

The JSON pins each Artifact's BLAKE3 digest, and the tests check it.

## Command line

Extract one synthetic case into separate files, then prove and verify:

```sh
python3 research/cqis-model-contract/synthetic_extract.py \
  crates/stele-prover/tests/fixtures one-layer /tmp/dev-e2e
cargo build --release -p stele-cli
target/release/stele prove-dev \
  --model /tmp/dev-e2e/model.bin --preparation /tmp/dev-e2e/preparation.bin \
  --scales /tmp/dev-e2e/scales.bin --artifact /tmp/dev-e2e/artifact.bin \
  --tokens 1 --length 16 \
  --public /tmp/dev-e2e/public.bin --proof /tmp/dev-e2e/proof.bin
target/release/stele verify-dev --public /tmp/dev-e2e/public.bin --proof /tmp/dev-e2e/proof.bin
```

- `--length T` extends `--tokens` to `T` tokens by greedy decoding. `--checked R..E`
  defaults to the whole window. `--next Y` defaults to the
  executor's greedy choice when `E = T`.
- Every checked token must be the greedy choice, or the prover's plain checker rejects.
- `public.bin` (`stele-dev-public-v2`) holds everything the verifier reads besides
  the proof: Model, Scales, Preparation, 1-D records, model-commitment roots and
  certificates, and the statement. Its magic names the source set, which the public
  input binds (RFC-0026 A11): `v2` for Circle Policy 2 sources, which `prove-dev`
  writes, and `v1` for the pre-A11 v2-expander Policy 1 sources, which `verify-dev`
  still accepts. Both print `profile development` and a `sources` line.

`verify-dev` only shows that the model named in `public.bin` produced the statement
named in `public.bin`. A prover can write a self-consistent `public.bin` for a model of
its own choosing. Before trusting a `YES`, compare the lines printed above the verdict
with values you obtained independently:

- `cqis_id`: the numerical identity of the Model, Scales, Registry and Bounds;
- `model`: BLAKE3 of `stele/v0.1/dev-e2e/model`, the `cqis_id`, the weight roots and
  the 1-D records (the norm gains). `prove-dev` prints it for the model it committed;
- `T`, `tokens`, `checked R..E` and `next`: the window and the claimed greedy tokens.

Pass `--expect-model <64 hex digits>` to reject any other model:

```sh
target/release/stele verify-dev --public /tmp/dev-e2e/public.bin \
  --proof /tmp/dev-e2e/proof.bin --expect-model <model hex from a trusted source>
```

The last line of `verify-dev` is the verdict, `YES` or `NO: <reason>`. `prove-dev` ends
with `PROOF WRITTEN`, which is not a verdict. Exit codes are 0 for accepted or written,
1 for rejected and 2 for a usage or I/O error. An option given twice is a usage error.

## dev-zk (tasks E12-14b, E12-25, E12-27, E12-14)

dev-zk (RFC-0013 A5, RFC-0026 A9, profile byte 1) proves a window against one
published model commitment (RFC-0013 A6, task E12-25), with the weights and the
norm gains hidden (A7, task E12-27). It is admitted at the development tier
(RFC-0013 A5 **Admission**, ADR-109, task E12-14). There is no security level, and
zero knowledge is conditional and computational.
- `commit-model --zk` commits the weights once, for at most `--proofs` proofs. The
  model seed comes from `/dev/urandom`.
  - It writes the public `--commitment` file (`stele-dev-zk-model-v1`) and prints
    its model digest.
  - It writes the secret `--secret` file (`stele-dev-zk-model-secret-v1`, mode
    0600: seed, proof counter, earlier openings). Keep the secret file private
    and never restore an older copy. A reused index leaks linear equations on
    the weights (RFC-0013 A6 item 5).
  - Commit at the largest `T` you will prove: the per-proof mask blocks are
    counted on that window.
- `prove-dev --zk --commitment C --secret S` takes the next proof index and
  writes the advanced counter back before it proves. It refuses once the budget
  is spent. Each proof's own seed also comes from `/dev/urandom`.
- The public file is `stele-dev-zk-public-v1`. It carries the commitment and the
  proof index. `verify-dev` prints `profile dev-zk`, `proof index j of P` and the
  model digest of the commitment. `--expect-model` pins a proof to it.
- Public, not hidden: the Model, Scales and Preparation bytes, the 1-D records'
  lengths and formats (their values, the norm gains, are committed weights under
  RFC-0013 A7), the shapes, the plan, `T`, the tokens, `[r, e)` and `y`.
- `verify-dev` reports counts of instances, steps and batches, not a soundness
  ledger (task E12-26).

```sh
target/release/stele commit-model --zk \
  --model /tmp/dev-e2e/model.bin --preparation /tmp/dev-e2e/preparation.bin \
  --scales /tmp/dev-e2e/scales.bin --artifact /tmp/dev-e2e/artifact.bin \
  --length 16 --proofs 8 \
  --commitment /tmp/dev-e2e/zk-model.bin --secret /tmp/dev-e2e/zk-model.secret
target/release/stele prove-dev --zk \
  --model /tmp/dev-e2e/model.bin --preparation /tmp/dev-e2e/preparation.bin \
  --scales /tmp/dev-e2e/scales.bin --artifact /tmp/dev-e2e/artifact.bin \
  --tokens 1 --length 16 \
  --commitment /tmp/dev-e2e/zk-model.bin --secret /tmp/dev-e2e/zk-model.secret \
  --public /tmp/dev-e2e/zk-public.bin --proof /tmp/dev-e2e/zk-proof.bin
target/release/stele verify-dev --public /tmp/dev-e2e/zk-public.bin \
  --proof /tmp/dev-e2e/zk-proof.bin --expect-model <model digest from commit-model>
```

Eight-layer window, `T = 64`, one Apple laptop, one run each, back to back
(`bench/ledger/e12-14-synthetic-8layer-mac.json` and
`bench/ledger/e12-14-synthetic-8layer-zk-mac.json`):

| Profile | Prove | Verify | Proof bytes |
|---|---|---|---|
| development | 16.6 s | 3.0 s | 44,963,009 |
| dev-zk | 389.9 s | 56.3 s | 145,252,954 |

The admission record (`bench/ledger/e12-14-synthetic-8layer-zk-admission-mac.json`,
task E12-14) is for the same window against one published commitment with committed
gains (RFC-0013 A6, A7). Each process ran once, on a host shared with other builds.
- `commit-model --zk` (P = 8) took 100.4 s.
- Proof 0 proved in 420.1 s, with 10.9 GB peak RSS.
- It verified in 54.7 s with `--expect-model`. The proof is 141,745,010 bytes.
- Proof 1 verified too, and a pin to another model digest was refused.

`bench/dev_e2e.py --zk` writes the record from the directory of those runs:
`commit.out` and `commit.time`, `model.commit`, proof 0 under the names above,
`verify1.out` and `pin.out`.

## A real model: llama2.c `stories42M` (task E16-11)

[`stories42M`](https://huggingface.co/karpathy/tinyllamas) is Karpathy's llama2.c model
trained on TinyStories (MIT licence). It is a Llama: d = 512, 8 layers, 8 heads of
width 64 without GQA, SwiGLU hidden 1376, vocabulary 32000, RMSNorm ε = 1e-5, RoPE
θ = 10000. It fits the RFC-0026 §1.3 class with int8 weights and dynamic rows, grouped
(RFC-0004 A15, g = 128) on the norm-fed projections and the head. At T = 64 the head's
matmul has `log T + log V + log d = 6 + 15 + 9 = 30 = MAX_VARS`, so no row block is
needed. The hidden width pads to 2048 and the vocabulary to 32768.

`research/cqis-model-contract/stories42m.py` pins every input and output by SHA-256.
The conversion is exact. The fp32 values are copied unchanged. The Q and K rows are
permuted from llama2.c's interleaved RoPE pairs to the half-split layout (RoPE layout
1), and the shared classifier is written out as `lm_head.weight`, since RFC-0025 Llama
sources are untied. The script checks that the original and converted fp32 forwards
agree.

```sh
export PATH="$HOME/.cargo/bin:$PATH"
D=/tmp/stories42m; mkdir -p $D/in
curl -sL -o $D/in/stories42M.bin \
  https://huggingface.co/karpathy/tinyllamas/resolve/0bd21da7698eaf29a0d7de3992de8a46ef624add/stories42M.bin
curl -sL -o $D/in/tokenizer.model \
  https://raw.githubusercontent.com/karpathy/llama2.c/350e04fe35433e6d2941dce5a1f53308f87058eb/tokenizer.model
curl -sL -o $D/in/TinyStories-valid.txt \
  https://huggingface.co/datasets/roneneldan/TinyStories/resolve/f54c09fd23315a6f9c86f9dc80f725de7d8f9c64/TinyStories-valid.txt
S=research/cqis-model-contract/stories42m.py
uv run --script $S convert $D/in $D/source          # model.safetensors, config.json, tokenizer.model
uv run --script $S frames $D/source $D/frames       # Model, Preparation, Source, Assets frames
cargo build --release -p stele-cqis --example prepare_source -p stele-cli
target/release/examples/prepare_source $D/frames/model.bin $D/frames/preparation.bin \
  $D/frames/source.bin $D/frames/assets.bin 2 $D/source $D/prepared
uv run --script $S fidelity $D/source $D/prepared $D/in   # informative: fp32 vs CQIS
```

`fidelity` runs the fp32 reference and the exact CQIS executor
(`harness/eval/cqis_torch.py`, CPU) on a fixed prompt, greedily continued to 64
tokens, and on four 64-token TinyStories validation windows. Its output is
[`agents/reviews/e16-11-stories42m/fidelity.json`](../agents/reviews/e16-11-stories42m/fidelity.json).
Both continuations read "One day, she saw a big, red balloon in the sky. She wanted
it so much, but it was too high for her to reach. Lily asked her mommy," and agree on
all 40 generated tokens. Fidelity is informative, not a gate. The prompt is 24 tokens,
so the checked range is `23..64`: the 40 generated tokens and `y`.
`prove-dev --length 64` extends the prompt with the same 40 tokens and `y = 376`, so the
native executor agrees with the torch executor on this window.

```sh
P=$D/prepared
/usr/bin/time -v target/release/stele prove-dev --model $P/model.bin \
  --preparation $P/preparation.bin --scales $P/scales.bin --artifact $P/artifact.bin \
  --tokens 1,9038,2501,263,931,29892,727,471,263,2217,7826,4257,365,2354,29889,2296,18012,304,1708,5377,297,278,14089,29889 \
  --length 64 --checked 23..64 --public $P/public.bin --proof $P/proof.bin \
  > $P/prove.out 2> $P/prove.time
/usr/bin/time -v target/release/stele verify-dev --public $P/public.bin --proof $P/proof.bin \
  > $P/verify.out 2> $P/verify.time
# Wrong next token, wrong checked token, tampered weight root, tampered gain: all rejected.
STELE_DEV_PROOF=$P cargo test --release -p stele-prover --test development \
  rejects_tampers_on_a_supplied_proof -- --ignored --nocapture 2>&1 | tee $P/controls.log
# The model commitment alone (Artifact decode + commitment), checked against public.bin.
STELE_DEV_PROOF=$P cargo test --release -p stele-prover --test development \
  matches_reference_model_commitment_of_a_supplied_proof -- --ignored --nocapture 2>&1 | tee $P/commit.log
```

## A larger model: llama2.c `stories110M` (task E16-20)

[`stories110M`](https://huggingface.co/karpathy/tinyllamas) is the next llama2.c
TinyStories model (MIT licence): d = 768, 12 layers, 12 heads of width 64 without GQA,
SwiGLU hidden 2048, vocabulary 32000. The CQIS configuration is that of stories42M at
this shape. At T = 64 the head's matmul has `6 + 15 + 10 = 31` bits, one past
`MAX_VARS`. It is split into two row blocks of the head weight (RFC-0026 A6), and the
embedding gather into two blocks of 32 tokens (E16-04). The width pads to 1024, the head
count to 16 and the vocabulary to 32768.

`research/cqis-model-contract/stories110m.py` runs the stories42M pipeline at this shape
and pins its own inputs and outputs by SHA-256 (the `.bin` digest is Hugging Face's LFS
digest). The commands are those above, with `stories110M.bin` downloaded from the same
revision and `S=research/cqis-model-contract/stories110m.py`.

Fidelity ([`agents/reviews/e16-20-stories110m/fidelity.json`](../agents/reviews/e16-20-stories110m/fidelity.json),
informative only): the original and converted fp32 forwards agree to `7.6e-6` in the
logits. Over four 64-token TinyStories validation windows the perplexity is 2.124 in
fp32 and 2.130 under CQIS. On the prompt the greedy continuations agree on 7 tokens and
then diverge: fp32 continues "big, red balloon", CQIS "big tree with lots of leaves"
(both fluent). The proof is about the CQIS continuation:

```sh
/usr/bin/time -v target/release/stele prove-dev --model $P/model.bin \
  --preparation $P/preparation.bin --scales $P/scales.bin --artifact $P/artifact.bin \
  --tokens 1,9038,2501,263,931,29892,727,471,263,2217,7826,4257,365,2354,29889,2296,18012,304,1708,5377,297,278,14089,29889 \
  --length 64 --checked 23..64 --public $P/public.bin --proof $P/proof.bin
```

`prove-dev` extends the prompt with the CQIS continuation and `y = 940`, the same
tokens as the torch executor.

Measured once at `445c9b0` (the E16-19 branch head) on a rented AMD EPYC 7532 container
(64 effective vCPUs, 128 hardware threads visible). Ledger:
[e16-20-dev-stories110m](../bench/ledger/e16-20-dev-stories110m.json).

- Prove: 1979 s wall, of which the model commitment alone takes 42.7 s. Peak RSS is 109.7 GB.
- Verify: 69.4 s, with a peak RSS of 17.9 GB. The same proof also verifies on an arm64
  laptop in 25 s.
- Proof: 126.8 MB (SHA-256 `0cd59f67…6fbc`), with a 40.0 MB `public.bin`.
- The four statement tampers are rejected: wrong `y`, wrong checked token and tampered
  gain (`RoundSumMismatch`), and tampered weight root (`RootMismatch`).

The host differs from the E16-18 campaign, so the times are not comparable with the
stories42M row below.

## Benchmark ledger

Development-profile numbers are recorded under RFC-0018 A1 (`profile: "development"`,
workload `dev/<name>`, no Python verifier). `bench/dev_e2e.py` turns one run directory
from the commands above (GNU `time -v`; `commit.log` is optional) into a ledger and
validates it:

```sh
python3 bench/dev_e2e.py $P bench/ledger/<name>.json --workload dev/<name> \
  --commit <measured commit> --device "<cpu>" --toolchain "$(rustc -V)" \
  --prompt-tokens 24 --threads "$(nproc)" --model-config <model json> --host-context "<host>"
```

### Circle rate-1/4 sources under Policy 2 (task E16-30)

RFC-0026 A11 moves the stacked and model sources to the Circle code at rate
1/4 and every source to RFC-0010 A14 Policy 2. It claims no security level. Before is
`origin/main` `276b2c0` and after is `944a4fc`, on one Apple M4 Max laptop shared with
other workloads. The synthetic windows had five alternating runs of each, and each
ledger keeps the median run; stories42M had one run of each:

| Window | Proof before → after | `public.bin` | Prove (median) | Verify (median) | Ledgers |
|---|---|---|---|---|---|
| 1 layer, T 16 | 25.4 → 7.3 MB | 4.03 → 0.19 MB | 1.41 → 1.29 s | 0.67 → 0.35 s | [before](../bench/ledger/e16-30-dev-synthetic-1layer-mac-before.json), [after](../bench/ledger/e16-30-dev-synthetic-1layer-mac-after.json) |
| 8 layers, T 64 | 45.0 → 9.8 MB | 8.46 → 0.30 MB | 9.91 → 10.47 s | 2.01 → 0.90 s | [before](../bench/ledger/e16-30-dev-synthetic-8layer-mac-before.json), [after](../bench/ledger/e16-30-dev-synthetic-8layer-mac-after.json) |
| stories42M, T 64, one run each | 113.4 → 18.3 MB | 26.4 → 2.33 MB | 197.0 → 186.9 s | 11.06 → 6.57 s | [before](../bench/ledger/e16-30-dev-stories42m-mac-before.json), [after](../bench/ledger/e16-30-dev-stories42m-mac-after.json) |

The prove-time difference is within the noise of the shared host. The ledgers list every
run's wall time. On stories42M the model commitment takes 2.52 s against 2.12 s, and peak
prove RSS is 25.3 GB against 26.2 GB. The before proof is byte-identical to the E16-18
proof. The after proof confirms the Q12 projection of 18.3 MB to within 152 bytes, the
LU nonces that the projection counted and A11 does not use. With Policy 2 grinding, the tampered-root control is now rejected at the
certificate's column nonce (`GrindMismatch`) instead of at the Merkle path, because the
root is absorbed before the nonce is checked.

### Measured runs and the FlashProve small route

The current Stele rows come from one campaign at commit `e813ce1` (after E16-15, E16-16
and E16-17), on a rented Intel Core Ultra 9 285K container (24 hardware threads, 188 GB).
Each is one run of a release build (task E16-18). The four statement tampers were rejected
on both proofs: wrong `y` and wrong checked token (`RoundSumMismatch`), tampered weight
root (`RootMismatch`), tampered gain (`RoundSumMismatch`). The model commitment is also
timed alone (`matches_reference_model_commitment_of_a_supplied_proof`, stage
`model_commitment`). It is part of the prove time, and a model owner would compute it once
per model. The stories42M `proof.bin` (SHA-256 `507b52b3…5381`) is byte-identical at
`9d4c176`, `f6db15e` and `e813ce1` (INV-8).

| Run | Model | Prove (wall) | of which model commitment | Verify (wall) | Proof | Peak RSS prove / verify | Ledger |
|---|---|---|---|---|---|---|---|
| Stele dev, synthetic | 8 layers, d 64, V 256, T 64, checked 0..64 | 21.9 s | 0.19 s | 3.95 s | 45.0 MB | 3.0 / 0.30 GB | [e16-18-dev-synthetic-8layer](../bench/ledger/e16-18-dev-synthetic-8layer.json) |
| Stele dev, stories42M | 8 layers, d 512, V 32000, T 64, checked 23..64 | 474 s | 8.7 s | 24.3 s | 113.4 MB | 38.4 / 4.8 GB | [e16-18-dev-stories42m](../bench/ledger/e16-18-dev-stories42m.json) |
| Stele dev, stories110M (`445c9b0`, EPYC 7532 host) | 12 layers, d 768, V 32000, T 64, checked 23..64 | 1979 s | 42.7 s | 69.4 s | 126.8 MB | 109.7 / 17.9 GB | [e16-20-dev-stories110m](../bench/ledger/e16-20-dev-stories110m.json) |
| FlashProve route 3 "small model" | 8-layer synthetic model | 23–30 s run: commit, prove and verify (build excluded) | included | included in the run | not stated | 10 GB RAM needed | README at `9e2bdd8` |

The E16-11 entries at `f6db15e`, the same host type, are kept as history:
[e16-11-dev-synthetic-8layer](../bench/ledger/e16-11-dev-synthetic-8layer.json) and
[e16-11-dev-stories42m](../bench/ledger/e16-11-dev-stories42m.json).
Three records are from a 4-core host (Intel Xeon at 2.1 GHz), which is not a comparison
with the rows above. The synthetic model proves there in 55.7 s at `6441a90`, before
E16-17 ([e17-00-dev-synthetic-8layer-4core](../bench/ledger/e17-00-dev-synthetic-8layer-4core.json)),
in 59.8 s at `21710de` with four threads
([e17-00-dev-synthetic-8layer-4core-21710de](../bench/ledger/e17-00-dev-synthetic-8layer-4core-21710de.json))
and in 103.6 s with one thread
([e17-00-dev-synthetic-8layer-1thread-21710de](../bench/ledger/e17-00-dev-synthetic-8layer-1thread-21710de.json)).
All three have the synthetic row's proof bytes (INV-8).

Task E16-23 (ADR-105) moved the prover's sequential residual onto the work pool without
changing proof bytes. It measured before (`736aef5`) and after (`e855f74`) on one
16-thread Apple M4 Max. The rows are not comparable with the hosts above:

| Rung | Before | After | Ledgers |
|---|---|---|---|
| L1, 8 layers, T 64 | 16.31 s | 9.50 s | [before](../bench/ledger/e16-23-dev-synthetic-8layer-mac-before.json), [after](../bench/ledger/e16-23-dev-synthetic-8layer-mac-after.json) |
| L0, 1 layer, T 16 | 1.67 s | 1.36 s | [before](../bench/ledger/e16-23-dev-synthetic-1layer-mac-before.json), [after](../bench/ledger/e16-23-dev-synthetic-1layer-mac-after.json) |

`research/gpu-gating/sequential_residual.py` counts the samples of one profile in which
prover code ran on a single thread.

Task E16-24 (ADR-112) sped up the dev-zk prover without changing proof bytes for a fixed seed:
- mask assignment indexed by term;
- the masked rounds factored and spread over the work pool;
- Merkle levels, mask streams, sources and the LogUp tree built over the pool;
- `Field::mul_m31` in the Circle transform.

It measured the eight-layer window, `T = 64` and `P = 8`, before (`aa24529`) and after
(`ac2a9e3`) on the same Mac, three runs each; the medians are:

| Step | Before | After | Ledgers |
|---|---|---|---|
| `commit-model --zk` | 92.7 s | 3.4 s | [before](../bench/ledger/e16-24-dev-zk-synthetic-8layer-mac-before.json), [after](../bench/ledger/e16-24-dev-zk-synthetic-8layer-mac-after.json) |
| `prove-dev --zk` | 362.6 s | 30.7 s | same |
| `verify-dev` | 55.8 s | 4.4 s | same |

The prove time includes the producer's own verification of the proof, about 4 s after the
change. `research/gpu-gating/zk_stage_shares.py` splits a `sample` profile of the prove
by dev-zk component.

The FlashProve row is the figure that project reports in its
[README](https://github.com/anthropics/FlashProve/tree/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c)
for route 3 on one NVIDIA H100 80 GB. It covers commit, prove and verify together, and
the README does not give the model's width or vocabulary; RFC-0026 records the route
as 8 layers, T = 64, d = 512. The statements differ (RFC-0018 rule 3): FlashProve hides
the weights (zero-knowledge) and runs on a GPU. A Stele development proof reveals the
model and activations, claims no security level and runs on CPU threads. The Stele
prove time includes the model commitment, which `prove-dev` recomputes on every call. No GPU path is measured here (INV-3).

Where the time and the bytes go, and what the build program does about it, is in
[`docs/assessment.md`](assessment.md) §3 and [`docs/plan.md`](plan.md).
