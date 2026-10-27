# Benchmark ledgers (RFC-0018 §1, task E0-05)

Real measurements belong in `bench/ledger/<run>.json`. The value schema is
`crates/stele-bench/schema.json`. Validate without changing files:

```sh
cargo run -p stele-bench --locked --offline -- ledger validate path/to/run.json
scripts/gates/ledger-validate.sh
```

Every v1 record requires the fields in the schema. Times are unsigned integer
nanoseconds; counters and sizes are unsigned 64-bit integers. Decimal and exponent
number encodings, duplicate keys at any depth, unknown root fields, excessive nesting,
and records over 1 MiB are rejected. The JSON Schema describes values; the executable
also enforces encoding and cross-field consistency.

`commit` is the full lowercase Git SHA; `plan_digest` is a lowercase 256-bit digest of
canonical `plan.json`. Record the toolchain, device, driver (`not-applicable` on CPU),
nonempty model configuration, profile, workload, and a human note. Model configuration
is integer JSON: strings, signed/unsigned integers, booleans, nulls, arrays, and objects.
Do not place weights, activations, prompts, or credentials in metadata.

`batch_size` is positive. Prompt and generated token counts are **per sequence**;
the full-request position count is their sum times batch size. Overflow is rejected.
`prover_time_ns` includes witness recomputation, which is also reported separately as
`witness_recompute_ns`. Each stage duration is at most the inclusive total. Stage
sums need not equal the total because GPU work can overlap. Kernel counters are named
integer counts. All applicable bindings must be enabled; `bindings_all_on` must be true.
The controls summary requires `failed = 0` and `passed = total`.

An `inference` record uses workload W1–W8, nonzero positions and proof size, positive
Rust and Python verifier times, and at least one passing control. A `micro` record uses
a `micro/<operation>` workload, records operation/input configuration in `model_config`,
and hashes its canonical benchmark plan in `plan_digest`; its total time measures that
operation. Proof size, verifier times, and control counts must be zero in micro records,
so they cannot claim inference evidence. The future workload runner must enforce the
specific model shapes, control inventory, and soundness profile requirements.

Validation checks record structure and internal consistency; it does not authenticate
the measurement, establish coverage, or verify an inference proof. Fixtures under
`crates/stele-bench/tests/fixtures/` are synthetic and are never benchmark evidence.
No performance result is supplied by this task. Fitting constants remains E9-03.

## Scalar field multiplication (E1-02)

From a clean committed checkout, run:

```sh
python3 bench/field_mul.py bench/ledger/field-mul-<run>.json
```

The runner captures the source SHA, toolchain, CPU, OS and SHA-256 benchmark-plan
digest. It measures five alternating-order samples of one million chained products
per field after warmup. Each result passes through `black_box`. The ledger contains
all sample times and the exact QM31:M31 ratio as an integer numerator/denominator.
Existing ledgers are never overwritten. This is a scalar latency comparison with
harness overhead; it is not SIMD/GPU throughput, inference performance or a fit of
the cost model. No core proof binding applies to this microbenchmark.

Recorded sample: [E1-02 scalar field multiplication](ledger/e1-02-scalar-field-mul.json).

## Native SIMD throughput (E1-04)

From a clean committed checkout, run `python3 bench/simd_ops.py <new-ledger.json>`.
Native release parity runs before timing. Set `STELE_REQUIRE_SIMD=neon` locally or
`STELE_REQUIRE_SIMD=avx2,avx512` on x86 to require those backends rather than merely
recording available ones. CI requires AVX2 and tests/measures AVX-512 whenever the
assigned runner supports it. The executed-backend inventory is retained; a green
run alone does not establish AVX-512 coverage. CI preserves a ledger artifact for
the exact PR head or main commit; it does not commit measurements. E1-04 acceptance
uses the explicit all-backend record below, not inferred runner capabilities.

The ledger records scalar and native add/subtract/multiply over cache-resident
sixteen-lane blocks, with input black boxes preventing loop-invariant hoisting.
All samples, aggregate element counts and integer-floor rates are retained.
Logical byte rates count two input reads and one result write per operation;
they do not measure DRAM traffic. Dispatch and canonicalization are timed;
construction, warmup, parity and export are excluded. CPU/OS, toolchain and the
SHA-256 benchmark-plan digest are captured automatically. No CUDA performance,
proof speed, constant-time guarantee or cost-model fit follows from these records.

Recorded samples: [NEON](ledger/e1-04-neon-throughput.json) and
[AVX2/AVX-512](ledger/e1-04-x86-throughput.json). The x86 record was downloaded unchanged
from [CI run 40565652650](https://github.com/AbdelStark/stele/actions/runs/40565652650).

## Polynomial partial evaluation (E1-05)

On macOS, run `python3 bench/partial_eval.py <new-ledger.json>` from a clean,
committed checkout. The runner first tests the polynomial kernels, then measures
naive and bucketed evaluation on identical synthetic QM31 inputs for int4/int8/int16.
It reverses case order between samples and checks result bytes across strategies.
Timing includes eq construction, allocation and partial evaluation; it excludes
input construction, warmup and encoding. Source state is checked before and after.

Input payload bytes are measured from the actual packed/native storage; divide
by the recorded element denominator for bytes/element. Peak RSS comes from macOS
`time -l` in bytes, with a separate process for each case. It includes setup,
warmup, code and allocator memory, so it is not a scratch-buffer or DRAM-traffic
measurement. Ratios compare aggregate bucketed and naive times for the same width.
This measures the partial-evaluation work contributing to `c_w`; it does not fit
the full weight-pass constant or establish a bandwidth-bound inference prover.
