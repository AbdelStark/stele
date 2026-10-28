# Benchmark ledgers (RFC-0018 §1, task E0-05)

## Circle encoding (E4-02)

On macOS, from a clean committed checkout, run
`python3 bench/circle.py /tmp/circle-<run>.json`. This is the full A2 gate:
two actual rows of 2^29 M31 input symbols at rate 1/2 and four actual rows of
2^28 symbols at rate 1/4, each producing 2^30 outputs. Rows run sequentially
in separate native processes. It is a large-memory CPU job; ordinary CI runs
only the worker's small reference and rejection tests.

Each row evaluates a specified four-coefficient polynomial containing the
high basis term v_(m-1) and its product with y. Every returned symbol is checked
by independent integer circle arithmetic. The encoder executes its complete,
value-independent loops; this does not represent random dense coefficients.
Preparation, complete encoding, and exhaustive validation are timed separately
and included in the total. Encoding includes inverse normalization, allocation,
coefficient expansion, all domain/twiddle work and the forward transform.
No setup is amortized. Final deallocation, process launch and JSON serialization
are outside those timers.

Each distinct row has one sample; no row is rescaled or substituted for another.
The ledger retains every receipt, actual input/output capacities, and macOS
`time -l` resource reports. Peak RSS includes original input, internal capacities
and overlap, returned output, validation and runtime; it excludes the Python
controller and is not isolated scratch or live allocated bytes. No timing result,
statistical comparison, fitted constant, PCS admission or inference result is
supplied by this harness change. The schema's standard profile is a tag only.

Recorded [E4-02 circle ledger](ledger/e4-02-circle-code.json), measured from clean
commit `31e957a8f3f7c7e2ee4a5987a8f6e9e91ad4960a` on Apple M4 Max with Rust 1.90.0.
Both rates process exactly 1,073,741,824 input symbols. Every output was checked:
2,147,483,648 at rate 1/2 and 4,294,967,296 at rate 1/4. All six native row
processes completed; the imported ledger is byte-identical to the emitted file.

Times below are exact sums in nanoseconds across every required row. Peak RSS is
the maximum native row-process measurement in bytes, not the sum of sequential
process peaks. Per-row receipts and complete resource reports remain in the ledger.

| Rate | Rows × input symbols | Preparation ns | Encode ns | Validation ns | Peak RSS bytes |
|---|---:|---:|---:|---:|---:|
| 1/2 | 2 × 536,870,912 | 4,945,779,084 | 110,563,338,167 | 10,206,113,375 | 12,889,145,344 |
| 1/4 | 4 × 268,435,456 | 5,127,879,667 | 200,823,224,541 | 21,584,528,500 | 10,741,596,160 |

Complete totals, including preparation and validation, are 125,715,230,626 ns and
227,535,632,708 ns respectively. Every row returns 1,073,741,824 symbols and a
4,294,967,296-byte output capacity; input capacities are 2,147,483,648 and
1,073,741,824 bytes respectively. Internal capacities and overlap contribute to
process RSS but are not isolated measurements. These are one-sample, four-coefficient
fixture baselines, with no random dense-coefficient, statistical, GPU, inference,
profile-certification or fitted-cost claim. No per-proof weight pass changes.

## Ledger format

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

Recorded sample: [E1-05 partial evaluation](ledger/e1-05-partial-evaluation.json).
Its int4/int8 bucketed totals are lower than naive; int16 is higher on the recorded
row shape. Strategy selection remains explicit; this sample does not justify a
universal automatic threshold.

## Dense sumcheck (E3-01)

On macOS, run `python3 bench/sumcheck.py <new-ledger.json>` from a clean committed
checkout. Correctness/control gates run before the dense QM31 measurement. Every
warmup and timed proof is checked by the public-table consumer; verification is
outside prover timing. Timed work includes table cloning/allocation, transcript
initialization, rounds and Final absorption. Synthetic input construction is excluded.

The ledger retains every sample, exact aggregate nanoseconds per hypercube point,
logical dense-table payload and separate-process peak RSS. RSS also includes setup,
verification, code and allocator memory. It does not isolate prover scratch.
The [initial dense baseline](ledger/e3-01-dense-sumcheck.json) includes slower first
samples for degrees zero and one; no samples were discarded. It establishes a
naive c_sc(degree, small=false) baseline, not a fitted cost model or performance
improvement. GPU, OM31 timing, inference workloads and ZK remain unmeasured here.

## Batching (E3-02)

On macOS, run `python3 bench/batching.py QM31 <new-ledger.json>` and repeat with
`OM31`. Start from a clean committed checkout; use output paths outside the checkout
when measuring both fields before importing the ledgers. The runner never overwrites
an existing record and checks source state again after measurement.

Cases cover equal/unequal instance sizes at polynomial degrees 0, 2 and 4, and
virtual-tensor claims with disjoint, overlapping and arbitrary points. Unequal
constant instances have shared degree one because of the leading selectors.
Every warmup/measured proof passes the actual public-table verifier outside timing;
its SC/RLC records and deterministic proof bytes are checked. Prover timing includes
cloning, allocation, transcript setup, coefficient construction, rounds and BatchFinal.
All samples are retained; case order reverses between samples.

The exact time/point denominator is the sum of original member hypercube sizes in
mode 0, and the tensor size in mode 1. Different statements/shapes are not speedup
comparisons. Logical working-table payload includes prover-owned inputs and the
mode-1 coefficient table; it excludes caller originals, descriptors, temporary eq
tables, proof and allocator metadata. Separate-process peak RSS includes those
objects, setup, warmup, verification, code and allocator retention; it is not isolated
scratch or measured DRAM traffic. Profile names select the field only here. This is
CPU microbenchmark evidence, not inference, GPU, ZK or profile-security certification.

Recorded baselines: [QM31](ledger/e3-02-batching-qm31.json) and
[OM31](ledger/e3-02-batching-om31.json), measured from clean commit
`095cfa445f864c7ecd3ae7ccef72fbf5c6be463f` on the recorded Apple M4 Max. Each field
retains three samples for each of nine cases. These establish native c_sc and
process-memory baselines; they do not fit the cost model or establish a speedup.

## Zerocheck (E3-03)

On macOS, run `python3 bench/zerocheck.py QM31 <new-ledger.json>` and repeat for
`OM31`, from a clean committed checkout. Keep output outside the checkout while
measuring both fields. The runner freezes its plan, captures source/device/toolchain,
never overwrites a record and checks source state again after measurement.

Cases fix m=8 and cover degrees 0..4, eq-only and k=1/2/4 when eligible. Reference
and dense strategies must produce identical subproof values for each fixed
(descriptor,k). Different k selects a different A3 protocol for the same row-zero
assertion; claim count and SC losses change. The direct reference recomputes
original slice MLEs through exhaustive residual sums; it is not a tuned linear-time
baseline. Both strategies consume every timed proof with the actual public verifier.

The ledger retains separate prover/consumer times, complete-operation time per
original hypercube point, all samples and integer ratios. Allocation, descriptor
processing and transcript initialization are timed; synthetic input construction,
encoding and receipt/continuation assertions are outside timing. Case order reverses
between samples. Skip losses remain in the record; no plan's k is selected automatically.

Separate-process peak RSS includes setup, warmup, prover, public consumer, encoding,
code and allocator retention. Caller-owned input and returned-proof payloads are
reported separately. Scratch figures are conservative requested-payload bounds,
summing field-buffer maxima and descriptor/message framing from the implementation;
consumer bounds include returned claim values and points. They exclude Vec/allocator
headers and stack, and are not isolated measured scratch peaks or DRAM traffic.
The plan records each bound formula; changing allocation structure requires revisiting
those formulas. This is CPU microbenchmark evidence; profile names select the field,
not a security certificate. No cost-model fit, inference, GPU or ZK result follows.

Recorded E3-03 ledgers: [QM31](ledger/e3-03-zerocheck-qm31.json) and
[OM31](ledger/e3-03-zerocheck-om31.json), from clean commit
`4541fb8c77c3c99462a23999b09dfb85db07d98d` on the recorded Apple M4 Max.
Both retain all 34 strategy/degree/skip cases and three samples per case.
The table shows exact aggregate nanoseconds over nine measured proofs per cell;
divide prover columns by 2,304 original points for the observed c_sc ns/point.
These are measurements, not fitted constants.

| Field | Degree | k=0 prover | k=1 prover | k=0 prove+consume | k=1 prove+consume |
|---|---:|---:|---:|---:|---:|
| QM31 | 1 | 894,791 | 621,456 | 1,224,164 | 1,122,497 |
| QM31 | 2 | 1,249,876 | 960,211 | 1,622,374 | 1,500,835 |
| QM31 | 3 | 1,608,667 | 1,326,082 | 1,987,623 | 1,866,042 |
| QM31 | 4 | 2,008,292 | 1,793,832 | 2,389,710 | 2,356,248 |
| OM31 | 1 | 2,467,543 | 1,643,208 | 3,215,919 | 2,973,499 |
| OM31 | 2 | 3,395,752 | 2,647,374 | 4,188,128 | 4,043,000 |
| OM31 | 3 | 4,509,584 | 3,704,707 | 5,346,500 | 5,109,039 |
| OM31 | 4 | 5,901,250 | 5,169,917 | 6,834,544 | 6,672,293 |

In these aggregates, k=1 reduces prover and complete time for degrees 1..4 in both
fields; individual OM31 samples at degrees 2 and 4 do not all improve. No statistical
significance or universal threshold is claimed. Every measured k=2/k=4 complete
aggregate is slower than k=0 for the same degree/field; public claim expansion is
included. Dense beats the exhaustive reference in all 17 aggregate comparisons
per field, but that reference is not a tuned linear-time competitor. The ledger
also retains process RSS, actual input/proof payloads and separate conservative
prover/consumer scratch bounds. No samples were discarded and no k is auto-selected.

## Small-value pipeline (E3-04)

From a clean committed checkout:

```sh
python3 bench/small_value.py QM31 /tmp/small-value-qm31.json
python3 bench/small_value.py OM31 /tmp/small-value-om31.json
```

This A5 harness compares Dense with Small k=2/3/4 at m=8, degrees 0..4, plus
m=18 degree 1 for memory. All four original inputs survive, including unused
signed/unsigned tables. Each case has three samples, three measured operations
and one warmup; every produced proof is consumed by the real public verifier.
It records preparation/proving and original-table materialization/consumption
separately, exact proof/continuation parity, SC records and all raw samples.

The prover and consumer execute sequentially in separate native processes so
macOS `time -l` measures each peak RSS. The native pipeline peak is their maximum;
the Python controller is excluded. Peaks include setup, warmup, transition
overlap, allocation retention, serialized proof buffers and process overhead.
They are not isolated live allocations or scratch peaks. Consumer memory can
dominate the full operation even if prover memory falls; report both. Synthetic
fixture construction, proof transport/parsing, assertions and process launch
are excluded from operation timing and explicitly recorded in the plan.

No measurement is supplied by the harness change. Ledgers require clean-source
provenance, actual control/accounting gates and acceptance of all warmup/measured
proofs. These synthetic CPU cases do not certify inference, GPU, ZK or a profile.

Recorded E3-04 ledgers: [QM31](ledger/e3-04-small-value-qm31.json) and
[OM31](ledger/e3-04-small-value-om31.json), from clean commit
`3a77a9d5a5996df63025efb81dc1e082a49d028c` on the recorded Apple M4 Max.
Each retains all 24 cases and three samples; 288 proofs per field, including
warmups, passed the actual public consumer. Imports preserve every JSON value.

For m=8, these are exact aggregate nanoseconds across nine measured proofs per
cell. k=0 is Dense; k=2/3/4 is Small. Divide prover columns by 2,304 points for
the observed c_sc ns/point. These observations do not fit a global cost constant.

| Field | Degree | Dense prover | k=2 prover | k=3 prover | k=4 prover |
|---|---:|---:|---:|---:|---:|
| QM31 | 0 | 294,916 | 249,541 | 230,999 | 220,625 |
| QM31 | 1 | 515,167 | 431,792 | 377,919 | 560,125 |
| QM31 | 2 | 1,401,417 | 1,038,206 | 875,209 | 883,499 |
| QM31 | 3 | 1,968,043 | 1,354,501 | 772,667 | 1,352,541 |
| QM31 | 4 | 2,284,957 | 1,815,335 | 2,034,079 | 3,685,207 |
| OM31 | 0 | 738,457 | 669,583 | 624,290 | 555,874 |
| OM31 | 1 | 1,553,874 | 1,655,918 | 1,854,252 | 2,091,209 |
| OM31 | 2 | 7,503,958 | 4,108,289 | 3,178,457 | 3,123,042 |
| OM31 | 3 | 10,126,417 | 5,199,709 | 4,449,542 | 5,342,250 |
| OM31 | 4 | 12,264,957 | 5,265,081 | 6,014,041 | 5,497,334 |

| Field | Degree | Dense prove+consume | k=2 complete | k=3 complete | k=4 complete |
|---|---:|---:|---:|---:|---:|
| QM31 | 0 | 492,291 | 447,208 | 432,040 | 417,250 |
| QM31 | 1 | 727,376 | 712,502 | 593,169 | 920,916 |
| QM31 | 2 | 1,792,041 | 1,426,166 | 1,265,084 | 1,276,750 |
| QM31 | 3 | 2,415,251 | 1,621,251 | 1,076,210 | 1,716,543 |
| QM31 | 4 | 2,568,375 | 2,311,212 | 2,525,204 | 4,181,249 |
| OM31 | 0 | 1,167,375 | 1,091,874 | 1,078,416 | 1,052,208 |
| OM31 | 1 | 2,117,207 | 2,176,544 | 3,131,588 | 3,781,834 |
| OM31 | 2 | 9,325,374 | 5,935,789 | 5,004,957 | 4,949,875 |
| OM31 | 3 | 12,109,251 | 7,160,085 | 6,410,334 | 7,314,541 |
| OM31 | 4 | 14,461,082 | 6,911,664 | 7,282,332 | 6,695,082 |

For m=18, degree 1, the time columns again aggregate nine measured proofs; divide
prover time by 2,359,296 points for observed c_sc. RSS is the maximum measured
native process peak across the three samples, in exact KiB (1,024 bytes).

| Field | k | Prover ns | Complete ns | Prover KiB | Consumer KiB | Pipeline KiB |
|---|---:|---:|---:|---:|---:|---:|
| QM31 | 0 | 446,737,957 | 557,936,039 | 20,432 | 24,768 | 24,768 |
| QM31 | 2 | 289,875,169 | 399,971,544 | 14,288 | 24,768 | 24,768 |
| QM31 | 3 | 221,885,167 | 331,627,709 | 10,176 | 24,768 | 24,768 |
| QM31 | 4 | 184,935,709 | 296,020,960 | 9,376 | 24,768 | 24,768 |
| OM31 | 0 | 1,329,326,041 | 1,689,342,956 | 36,928 | 45,472 | 45,472 |
| OM31 | 2 | 821,020,250 | 1,179,428,207 | 14,176 | 45,472 | 45,472 |
| OM31 | 3 | 641,549,126 | 1,001,501,834 | 10,048 | 45,488 | 45,488 |
| OM31 | 4 | 544,147,626 | 901,837,210 | 8,016 | 45,488 | 45,488 |

In the large case, every tested Small prefix lowers prover peak RSS and aggregate
prover/complete time in both fields. The consumer dominates the native pipeline
peak: it is unchanged in QM31 and varies by one 16-KiB page in OM31. Thus the
measured memory improvement is in the prover, not the complete public-consumer
pipeline. Peaks include transition overlap and retained allocation capacity.

At m=8, complete aggregates improve in 13/15 Small cases for QM31 and 12/15 for
OM31. QM31 loses at (degree 1,k=4) and (degree 4,k=4); OM31 loses for every tested
prefix at degree 1. Individual samples also lose in some aggregate-winning cases.
No sample is discarded. No significance, universal size threshold or automatic
prefix choice follows from this single-host experiment. Both complete stage costs
and all process peaks remain in the ledgers; no GPU/inference/ZK/profile claim follows.
