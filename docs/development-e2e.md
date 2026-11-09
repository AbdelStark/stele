# Running the development end-to-end prover

This page shows how to prove and verify one prefill window under the RFC-0026
development profile. The profile claims no security level: FS is unproven, the PCS is
conjectural, and the proof reveals the model and the activations (RFC-0026 §1.2).

## What runs

`stele_prover::development` takes canonical Model, Preparation, Scales and Artifact
bytes, a power-of-two token window `x_0..x_{T-1}`, a checked range `[r, e)` and, when
`e = T`, the next token `y`. It:

1. commits each weight matrix once as an RFC-0010 v2 source (the model commitment);
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
- `public.bin` (`stele-dev-public-v1`) holds everything the verifier reads besides
  the proof: Model, Scales, Preparation, 1-D records, model-commitment roots and
  certificates, and the statement.

The last output line is the verdict, `YES` or `NO: <reason>`. Exit codes are 0 for
accepted, 1 for rejected and 2 for a usage or I/O error.
