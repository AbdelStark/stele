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
controller and is not isolated scratch or live allocated bytes. These row
measurements establish no statistical comparison, fitted constant, PCS admission
or inference result. The schema's standard profile is a tag only.

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

## Native test profile (E0-07)

The [paired ledger](ledger/e0-07-test-profile.json) measures the unchanged
`stele-cqis` `table_mle` integration test from clean commit
`b638390716ddce6cb2442a64ddb6cfd6da773845`. Both configurations retain debug
assertions and overflow checks. All four tests passed, including the 14
maximum-shape cases in QM31 and OM31 at two seeded points each.

| Test optimization | Clean compilation (s) | Test execution (s) | Complete command (s) |
|---|---:|---:|---:|
| 0 | 6.47 | 119.99 | 126.835 |
| 2 | 7.56 | 8.31 | 16.272 |

This is one sequential pair on a shared Apple M1 Max host with existing proof
workers retained. Each configuration used a new target directory. Cargo reports
compile/test times to hundredths of a second; complete command time includes
Cargo overhead. Command walls include the compile and execution components;
these ledger stages overlap and must not be summed. No repetition, warmup,
discarded sample or inference measurement
is implied, and these results do not establish full-CI wall time. The manifest
uses the measured opt2 settings; source tests and their independent oracle remain
unchanged. Default dev builds and release table parity keep their prior profiles.

To reproduce the commands, use a clean checkout of the measured commit and a
different empty `CARGO_TARGET_DIR` for each `LEVEL` (0, then 2):

```sh
CARGO_PROFILE_TEST_OPT_LEVEL="$LEVEL" \
CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true \
CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true \
cargo test -p stele-cqis --test table_mle --all-features --locked --offline --verbose
```

The ledger embeds the measurement and verification scripts, source hashes, raw
log hashes, exact commands, test names and binary hashes. A postprocessing check
initially confused Cargo's separate build-dependency profile with test artifacts;
both actual test commands had passed. The preserved verification corrected that
scope without rerunning either sample. Subsequent fresh `--no-run` JSON artifact
inspection confirmed both checks on the actual test, CQIS and field artifacts;
small runtime probes also rejected a false debug assertion and integer overflow.
These checks are outside the timed commands. The micro record's proof, verifier
and controls fields remain zero; no proof-system cost-model constant changes.

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


## Streaming pipeline (E3-05)

From a clean committed macOS checkout, run fields sequentially after validation
workers finish:

```sh
python3 bench/streaming.py QM31 /tmp/streaming-qm31.json
python3 bench/streaming.py OM31 /tmp/streaming-om31.json
```

The frozen plan compares Dense, tail materialization, one window and multiple
windows at m=8 for degrees 0..4, plus m=18 degree 1. It uses full-extension
synthetic inputs, including an unused input, and three fresh samples per case.
There is no warmup or cache flush. Budgets are explicit workspace cells fixed
before measurement; selected window cases use less workspace than dense inputs.

Separate native processes generate/write original files and prepare the layout,
prove, then consume every original claim from the preserved files. Operation times
include file I/O, allocation, window/tail transitions, transport encoding/decoding
and continuation checks. Argument parsing, launch/exit, result JSON formatting,
controller cleanup and small final-buffer destruction are excluded explicitly.
Every proof must verify, and all strategy proof/continuation bytes must agree.

Actual Vec/PathBuf capacities and compiled named state sizes are reported apart
from process RSS. The consumer's transient equality table is included in its RSS.
Native pipeline peak is the maximum of sequential preparation/prover/consumer
peaks, including allocation retention and transport overlap. Python/controller
and OS filesystem caches are excluded: this is not a total-host-memory bound.
External storage and successful logical I/O operations are recorded; no physical
storage traffic is inferred. All raw samples and losing schedules are retained.

Recorded [QM31](ledger/e3-05-streaming-qm31.json) and
[OM31](ledger/e3-05-streaming-om31.json) ledgers come from clean commit
`c9fd07538ff239462ac87225d4d3221c8ea3f983`, Apple M4 Max, Rust 1.90.0.
Each field completed 72 proofs with all original claims and continuation checked.
All four strategies produced identical bytes for each descriptor. Stored ledgers
preserve every exported JSON value; whitespace is compacted to one sample per line.

The table reports m=18, degree 1. Times are sums of three samples, including fixture
creation, layout preparation, proving and original consumption. RSS is the maximum
observed native process peak across those samples. Buffer capacity is the actual
retained prover allocation payload, including caller, descriptor, proof and source;
it excludes separately reported inline state and is not an RSS bound.

| Field | Strategy | Complete ns | Prover ns | Work cells | Prover buffers bytes | Prover RSS bytes | Pipeline RSS bytes |
|---|---|---:|---:|---:|---:|---:|---:|
| QM31 | dense | 3,945,533,750 | 788,487,750 | 0 | 12,584,854 | 14,417,920 | 18,628,608 |
| QM31 | tail | 7,625,567,001 | 847,268,584 | 786,435 | 12,584,839 | 14,401,536 | 18,628,608 |
| QM31 | one | 80,420,888,084 | 73,630,972,542 | 2,054 | 34,740 | 1,835,008 | 18,628,608 |
| QM31 | multi | 15,871,414,876 | 9,051,666,584 | 262 | 6,086 | 1,769,472 | 18,628,608 |
| OM31 | dense | 4,330,088,750 | 1,013,133,791 | 0 | 25,168,470 | 27,017,216 | 35,422,208 |
| OM31 | tail | 7,941,723,998 | 1,198,973,749 | 786,435 | 25,168,503 | 27,000,832 | 35,422,208 |
| OM31 | one | 198,110,167,333 | 191,399,867,250 | 2,054 | 68,308 | 1,884,160 | 35,422,208 |
| OM31 | multi | 27,494,733,083 | 20,876,796,334 | 262 | 10,982 | 1,818,624 | 35,422,208 |

Dense has no streaming arena; its three original tables contain 786,432 K cells.
The one-window schedule [9] uses 2,054 workspace cells and two source visits;
[6,6] uses 262 cells and three visits. Preparation and original consumption add
separate reads outside those visits. All supplied capacities and logical I/O counts
remain in the ledgers, including the tail-only path and external source storage.

These windows reduce prover memory, but the original consumer dominates every
m=18 pipeline peak. Total time increases for every tested streaming case: all
15 m=8 schedule/degree combinations per field and all three m=18 schedules.
The one-window complete totals are 20.38x Dense for QM31 and 45.75x for OM31;
multiple windows are 4.02x and 6.35x respectively (rounded ratios of summed times).
The simple direct grid algorithm trades computation and file access for workspace.
No winning sample is selected or losing schedule omitted; no significance or
universal planner threshold follows from this single-host experiment.

Inclusive micro-operation time includes original consumption; inference evidence
fields remain zero. Actual subproof results, stage costs and executed control
coverage are in model_config. There is no fitted constant, GPU, inference, ZK,
profile-certification or complete-host-memory claim, and no weight-pass change.

## Bounded native encoder (E4-08)

On arm64 macOS, from a clean committed checkout, run
`python3 bench/encoder.py /tmp/native-encoder.json`. All J=3..10 sizes in
M31/QM31/OM31 run in separate processes, three samples each. Every input limb
uses the documented fixed fixture; the existing full-byte corpus separately
covers randomized and boundary inputs. Every nonempty query regenerates and
encodes the whole row, while the first output remains live. There is no setup
amortization, retained graph or value-dependent edge omission.

Recorded [E4-08 ledger](ledger/e4-08-native-bounded-encoder.json), clean commit
`5573137a90379cdafda96dece05ed9f3d07e52e9`, Apple M1 Max, Rust 1.90.0.
All 72 samples and 25,165,440 independently checked output symbols remain in the
record. Imports preserve every JSON value. Each query's ordered values are also
checked. The oracle uses integer sparse arithmetic, separately assembled hash
frames and a dense Circle base regenerated by independent Python arithmetic.

The largest case has 1,048,576 input symbols. Times below sum three samples per
field, in exact nanoseconds. Factory/input preparation, every per-call hash and
sampling operation, initialization, copies, base/sparse arithmetic, observation
overhead and exhaustive validation are included in complete time. Generation
occurs inside encode and query; no isolated hashing time is inferred. Build,
launch, argument parsing, JSON serialization and final native drops are excluded.

| Field | Encode ns | Query ns | Validation ns | Complete ns |
|---|---:|---:|---:|---:|
| M31 | 7,378,201,418 | 7,371,750,584 | 10,515,272,457 | 25,267,979,542 |
| QM31 | 7,793,235,125 | 7,802,155,750 | 11,279,906,626 | 26,886,257,208 |
| OM31 | 8,508,079,917 | 8,536,992,084 | 12,179,367,292 | 29,246,344,250 |

These largest-case byte figures are maxima across the three samples. Owned
encoding payload includes actual output, scratch, temporary base word, twiddle
headers/elements and inverse-prefix overlap. Native live payload additionally
includes borrowed caller input, retained first output and selected values during
query re-encoding. Whole-worker RSS also includes the independent validator,
all stack/runtime memory and allocator retention; the controller is excluded.
None of these scopes is silently substituted for another.

| Field | Encode owned peak bytes | Native live peak bytes | Worker peak RSS bytes |
|---|---:|---:|---:|
| M31 | 9,787,812 | 22,370,740 | 180,715,520 |
| QM31 | 39,149,220 | 89,480,932 | 219,463,680 |
| OM31 | 78,297,764 | 178,961,188 | 270,909,440 |

Each largest-case encoding generates 2,097,024 rows using 12,583,018 hash blocks.
Sparse base-limb additions and products are each 36,725,760 for M31, 146,903,040
for QM31 and 293,806,080 for OM31. Divide by 1,048,576 for exact per-input ratios.
Each query repeats this work. Initialization counts 2,446,720 K slots; copies count
1,398,208 K slots, plus four for a query. The Circle base adds 1,280 K additions,
704 K products, 190 constructed twiddles and 63 inverse-prefix entries. These are
logical operations with distinct units, not hardware instructions, memory traffic
or a complete base-field equivalent for hashing/sorting/inversion.

The ledger also stores the measured executable's SHA-256, disassembly SHA-256,
compiler frame reservations and call targets. All three recursive specializations
reserve 208 bytes per frame; the largest measured case has eight recursive frames.
The hash and portable compression frames reserve 288 and 176 bytes respectively.
This is an exact inventory of emitted native/hash function frames, not a total
call-chain or process-stack bound. Inlined state belongs to its containing frame;
caller, allocator/runtime and other callees remain outside that inventory and
inside the measured process RSS. Inline object sizes are separately recorded.

No sample is discarded or extrapolated. This supplies CPU c_c/T_misc and memory
evidence for the bounded encoder. It makes no statistical comparison, fitted
constant, extra weight-pass, GPU, inference, PCS/profile or ZK claim.

## Conditional fraction primitives (E3-07a)

The [QM31](ledger/e3-07a-fraction-qm31.json) and
[OM31](ledger/e3-07a-fraction-om31.json) ledgers measure the complete
RFC-0008 A3 public primitive operation from clean commit
`8798d1ac60e67d1a6580339f3951427efd82cc05`. Each field has twenty cases
and three fresh native processes per case, with every proof consumed against
its original arrays. The profile field selects the challenge field only.

Reproduce on macOS from that clean source commit:

```sh
python3 bench/fraction.py QM31 /tmp/fraction-qm31.json
python3 bench/fraction.py OM31 /tmp/fraction-om31.json
```

Preparation constructs the fixed synthetic original arrays and descriptors.
Proving includes all retained tree levels, Dense/equality copies and transcripts;
consumption includes exact decoding and every original public claim, including
unused columns under beta=0. Complete time also charges encoding, receipt and
continuation checks, result construction and original-buffer cleanup. Process
launch/exit, argument parsing, JSON serialization/printing and final result-value
destruction are outside that timer. Their memory remains included in native RSS.

Times below are means over all three samples, in milliseconds. RSS is the
maximum native whole-operation peak across those samples, in MiB. The ledgers
retain every sample, exact stage times, source/encoding capacities, scoped SC/RLC
records and proof/continuation digests. Sample rows and aggregate maps are
compacted for review; every recorded JSON value is unchanged.

| Field | m | Mode | Preparation ms | Prove ms | Consume ms | Complete ms | Peak RSS MiB |
|---|---:|---|---:|---:|---:|---:|---:|
| QM31 | 0 | ordinary | 0.020 | 0.009 | 0.001 | 0.042 | 1.422 |
| QM31 | 0 | weighted | 0.007 | 0.003 | 0.001 | 0.020 | 1.422 |
| QM31 | 0 | selected1 | 0.008 | 0.009 | 0.004 | 0.035 | 1.469 |
| QM31 | 0 | selected3zero | 0.008 | 0.009 | 0.004 | 0.037 | 1.453 |
| QM31 | 1 | ordinary | 0.008 | 0.011 | 0.005 | 0.040 | 1.469 |
| QM31 | 1 | weighted | 0.009 | 0.010 | 0.005 | 0.039 | 1.484 |
| QM31 | 1 | selected1 | 0.009 | 0.017 | 0.010 | 0.057 | 1.469 |
| QM31 | 1 | selected3zero | 0.008 | 0.019 | 0.011 | 0.059 | 1.484 |
| QM31 | 8 | ordinary | 0.012 | 0.472 | 0.114 | 0.692 | 1.578 |
| QM31 | 8 | weighted | 0.015 | 0.475 | 0.114 | 0.697 | 1.578 |
| QM31 | 8 | selected1 | 0.026 | 0.662 | 0.161 | 0.960 | 1.594 |
| QM31 | 8 | selected3zero | 0.058 | 0.850 | 0.169 | 1.191 | 1.594 |
| QM31 | 12 | ordinary | 0.103 | 6.100 | 0.421 | 6.815 | 2.172 |
| QM31 | 12 | weighted | 0.102 | 5.945 | 0.405 | 6.634 | 2.172 |
| QM31 | 12 | selected1 | 0.323 | 8.730 | 0.844 | 10.111 | 2.297 |
| QM31 | 12 | selected3zero | 0.813 | 11.924 | 0.982 | 13.938 | 2.547 |
| QM31 | 16 | ordinary | 1.438 | 94.632 | 3.544 | 100.000 | 12.125 |
| QM31 | 16 | weighted | 1.452 | 94.617 | 3.531 | 99.985 | 10.750 |
| QM31 | 16 | selected1 | 5.095 | 136.942 | 9.842 | 152.416 | 12.766 |
| QM31 | 16 | selected3zero | 12.862 | 189.725 | 11.975 | 215.208 | 16.156 |
| OM31 | 0 | ordinary | 0.021 | 0.011 | 0.001 | 0.049 | 1.469 |
| OM31 | 0 | weighted | 0.008 | 0.004 | 0.002 | 0.027 | 1.469 |
| OM31 | 0 | selected1 | 0.008 | 0.010 | 0.006 | 0.041 | 1.484 |
| OM31 | 0 | selected3zero | 0.008 | 0.015 | 0.006 | 0.047 | 1.531 |
| OM31 | 1 | ordinary | 0.008 | 0.015 | 0.009 | 0.051 | 1.531 |
| OM31 | 1 | weighted | 0.010 | 0.016 | 0.008 | 0.055 | 1.547 |
| OM31 | 1 | selected1 | 0.009 | 0.029 | 0.014 | 0.081 | 1.547 |
| OM31 | 1 | selected3zero | 0.010 | 0.030 | 0.016 | 0.087 | 1.547 |
| OM31 | 8 | ordinary | 0.025 | 1.155 | 0.192 | 1.543 | 1.656 |
| OM31 | 8 | weighted | 0.025 | 1.147 | 0.192 | 1.542 | 1.656 |
| OM31 | 8 | selected1 | 0.068 | 1.649 | 0.308 | 2.236 | 1.672 |
| OM31 | 8 | selected3zero | 0.158 | 2.203 | 0.339 | 2.915 | 1.688 |
| OM31 | 12 | ordinary | 0.253 | 16.426 | 0.932 | 17.959 | 2.875 |
| OM31 | 12 | weighted | 0.259 | 16.468 | 0.941 | 18.019 | 2.875 |
| OM31 | 12 | selected1 | 0.969 | 24.080 | 2.249 | 27.708 | 3.125 |
| OM31 | 12 | selected3zero | 2.370 | 32.401 | 2.622 | 37.799 | 3.375 |
| OM31 | 16 | ordinary | 3.885 | 262.177 | 10.530 | 277.415 | 22.141 |
| OM31 | 16 | weighted | 3.874 | 261.912 | 10.639 | 277.240 | 19.812 |
| OM31 | 16 | selected1 | 15.416 | 385.043 | 31.058 | 432.688 | 32.438 |
| OM31 | 16 | selected3zero | 37.041 | 521.928 | 37.128 | 597.359 | 27.781 |

`ordinary` uses b=m; `weighted` uses b=floor(m/2). `selected1` uses
one original column; `selected3zero` uses three columns and beta=0, retaining
all three original obligations. Different modes are different conditional
operations, not speedup comparisons.

RSS includes all internal levels/copies, consumers, originals, proof objects,
encoded bytes, output and allocator retention. It is a whole-operation peak,
not an isolated prover peak or an attributed allocation/stack bound. Python
controller and total-host memory are excluded. Named capacity fields cover only
actual original/encoded Vec buffers. No warmup or cache flush was used; all
observations are retained without a fitted constant or statistical comparison.

These are c_sc/T_misc primitive observations. No c_lu, full lookup identity,
private source authentication, PCS, ZK, FS, GPU, inference or profile admission
follows. The separate root-equation predicate is outside this public reduction
operation. Inference proof/verifier/control fields stay zero; actual primitive
consumption and control coverage are recorded in model_config. No additional
weight pass or planning-constant change follows.

## Conditional field PCS resources (E4-03a)

From a clean committed checkout on arm64 macOS, run
`uv run --no-project --python 3.12 bench/field_pcs.py /tmp/new-field-pcs-ledger.json`.
The controller builds the native release worker and retains every raw receipt,
exit status and `time -l` report beside the new ledger. Existing output paths
reject. Source identity is checked before and after each sequential worker.

The declared matrix covers scalar, asymmetric, row-heavy and column-heavy PCS
operations in both fields and both supported rates. Each registration is followed
by two distinct openings against its genuine certificate. A separate bounded A1
case uses three original sources: one used, one unused and one with coefficient
zero. It runs the actual adapter once and retains all original obligations.
The point-acquisition replay is part of the measured producer work.

Native total time includes fixture construction, complete producers/consumers,
receipt hashes, validation and protocol-buffer cleanup. Named stages are disjoint;
the remainder retains other measured work. Launch, argument parsing and receipt
JSON serialization are outside that timer. Fresh-worker peak RSS includes those
operations, encoder scratch/twiddles, every retained source/proof, runtime, stack
and allocator retention. It is whole-pipeline memory, not isolated verifier RSS.
PreparationWork and input/proof capacities have their narrower reported scopes;
they do not establish a complete PCS or A1 owned-vector peak.

The example belongs to the unpublished control harness and imports production
APIs. Receipt hashes grant no protocol authority. Component proof sizes, actual
SC/certificate/opening records and cumulative usage snapshots live in
`model_config`; inference fields retain their schema-v1 micro values. Existing
independent byte parity, finite-policy and negative-control gates still apply.
These measurements do not establish profile admission, a fitted constant or an
inference/weight-pass result.

The [complete CPU ledger](ledger/e4-03a-field-pcs.json) records 60 samples from
clean producer commit `a4c4d628bc4aaf91c67f7110f4d3b7f60515ff0e` on Apple M1 Max.
The table shows mean inclusive time and maximum process RSS over three samples
per cell. Certificate/opening bytes are totals across the named operation:
one certificate and two openings for `primitive`, three of each for `a1`.
A1 message bytes exclude its separately recorded public bundle/instance framing.
Every JSON value is unchanged from the validated output; sample rows and large
maps are compacted for review. Original research workers remained active, so
these are bounded observations under shared host load, not speed comparisons.

| Mode | ell,m | Field | Rate | Complete ms | Peak RSS MiB | Certificate bytes | Opening bytes | A1 message bytes |
|---|---|---|---|---:|---:|---:|---:|---:|
| primitive | 0,0 | QM31 | 1/2 | 0.948 | 1.578 | 4697 | 106 | 0 |
| primitive | 0,0 | OM31 | 1/2 | 0.950 | 1.578 | 4713 | 138 | 0 |
| primitive | 0,0 | QM31 | 1/4 | 1.865 | 1.594 | 8857 | 8874 | 0 |
| primitive | 0,0 | OM31 | 1/4 | 1.942 | 1.594 | 8873 | 8906 | 0 |
| primitive | 2,1 | QM31 | 1/2 | 4.085 | 1.781 | 25153 | 20866 | 0 |
| primitive | 2,1 | OM31 | 1/2 | 4.138 | 1.734 | 25185 | 20930 | 0 |
| primitive | 2,1 | QM31 | 1/4 | 4.042 | 1.813 | 35201 | 20674 | 0 |
| primitive | 2,1 | OM31 | 1/4 | 4.324 | 1.781 | 35233 | 20738 | 0 |
| primitive | 4,12 | QM31 | 1/2 | 67.753 | 4.391 | 302657 | 345154 | 0 |
| primitive | 4,12 | OM31 | 1/2 | 129.709 | 4.766 | 368193 | 476226 | 0 |
| primitive | 4,12 | QM31 | 1/4 | 89.411 | 5.922 | 226305 | 264194 | 0 |
| primitive | 4,12 | OM31 | 1/4 | 170.243 | 7.375 | 291841 | 395266 | 0 |
| primitive | 12,4 | QM31 | 1/2 | 265.253 | 16.563 | 7180353 | 7081346 | 0 |
| primitive | 12,4 | OM31 | 1/2 | 668.585 | 17.141 | 7180609 | 7081858 | 0 |
| primitive | 12,4 | QM31 | 1/4 | 197.329 | 12.250 | 5205121 | 4144514 | 0 |
| primitive | 12,4 | OM31 | 1/4 | 458.913 | 12.719 | 5205377 | 4145026 | 0 |
| a1 | 2,1 | QM31 | 1/2 | 8.175 | 1.891 | 75459 | 31299 | 192 |
| a1 | 2,1 | OM31 | 1/2 | 9.139 | 2.000 | 75555 | 31395 | 336 |
| a1 | 2,1 | QM31 | 1/4 | 8.122 | 1.859 | 105603 | 31011 | 192 |
| a1 | 2,1 | OM31 | 1/4 | 10.003 | 2.188 | 105699 | 31107 | 336 |

## Complete conditional stacked resources

`stacked.py` measures actual public and certified stacked producers and consumers
under RFC-0006 A4 §6. Run it from clean committed source on arm64 macOS, with a
new destination outside the checkout:

```sh
uv run --no-project --python 3.12 python bench/stacked.py /tmp/stacked-run.json
```

The fixed campaign uses both fields, both elimination orders and both source
modes, with three fresh sequential workers per cell. All cells use axes
`(4,5,5)`, a public RopeTables coefficient selected on the layer axis, and
`P=3*f0^3+0*f2`. All three originals are consumed, including unused `f1` and
zero-coefficient `f2`. Certified sources retain their own `(4,10)`, `(7,7)` and
`(10,4)` splits, actual registration certificates and ordinary openings.

The native total includes fixture/claim construction, preparation, registration,
complete closed production/verification, receipt observations, continuation and
protocol-buffer cleanup. Named stages are disjoint; the remainder includes
cleanup and other work. Build, process launch, argument parsing and final JSON
serialization are excluded from that timer. Fresh-worker RSS covers the whole
process, including serialization and allocator retention. It is not verifier-only
memory. Expected frames are reconstructed during observation; proof bytes and
conditional records come from the actual producers and consumers.

`Work` reports capacities from the actual Dense used for production, without a
second strategy or transcript replay. Its partial/result maximum describes one
round's live scratch. Other retained proof storage, frames, A7/A9 temporaries and
caller storage remain outside that count. PreparationWork and caller/proof
capacities have their own scopes; their separate maxima must not be summed into
a pipeline peak. Source-specific point-weight entry counts are structural,
not allocator observations. Dense tables drop before certified opening work;
caller originals, prepared sources, certificates and proof remain live through
their actual consumers.

The controller retains every raw sample, exit status, resource report and build
log. It checks source/binary identity before and after each worker, complete case
coverage, actual records, bytes, usage, time arithmetic, continuation and repeated
proof identities before native ledger validation. Import the validated JSON into
`bench/ledger/` without changing its values. Measurements on a shared host support
only the declared relation; they do not establish a fitted constant, speedup,
all-kind scaling, inference/profile admission, zero knowledge or a weight-pass
result. The mandatory correctness/parity/control gates remain separate.

The [complete stacked ledger](ledger/e3-06-stacked.json) contains all 24 samples
from clean source `34072630ce9eaf6fd1379130cfe3f86de1ffd4c1` on Apple M1 Max.
The table reports mean native times truncated to microseconds and maximum RSS
over each three-sample cell. Total includes actual registration and cleanup;
producer and consumer columns are its included closed-call intervals. Proof bytes
include A1 messages and ordinary openings; registration certificates and public
frames are recorded separately. Original research workers remained active.
JSON values are unchanged from the validated output; sample rows are compacted.

| Mode | Field | Order | Total ms | Producer ms | Consumer ms | RSS KiB | Proof bytes |
|---|---|---|---:|---:|---:|---:|---:|
| public | QM31 | layer-first | 81.845 | 63.634 | 4.031 | 4560 | 1364 |
| public | QM31 | layer-last | 82.906 | 64.008 | 4.435 | 6128 | 1364 |
| public | OM31 | layer-first | 201.822 | 159.557 | 10.068 | 11552 | 2548 |
| public | OM31 | layer-last | 214.936 | 167.833 | 11.551 | 12816 | 2548 |
| certified | QM31 | layer-first | 169.328 | 69.976 | 19.907 | 7168 | 1193335 |
| certified | QM31 | layer-last | 166.141 | 68.841 | 19.654 | 7312 | 1193335 |
| certified | OM31 | layer-first | 349.504 | 167.389 | 44.436 | 9008 | 1213207 |
| certified | OM31 | layer-last | 338.029 | 161.472 | 43.965 | 7392 | 1213207 |


## Complete conditional lookup resources

`lookup.py` measures the actual conditional grouped lookup from RFC-0008 A5 §6.
Run it from clean committed source on arm64 macOS with a new external destination:

```sh
uv run --no-project --python 3.12 python bench/lookup.py /tmp/lookup-run.json
```

The [complete lookup ledger](ledger/e3-07b-lookup.json) contains all 24 samples
from clean source `0d07604cec88e55af697c036e3f2916e76e247f3` on Apple M1 Max.
Each cell has three fresh sequential release workers. Every sample prepares and
registers the original sources, produces one complete lookup proof, imports its
multiplicity certificates, and calls the actual closed verifier. Every original
and structural multiplicity piece is consumed, including zero-valued pieces and
all originals under the zero selector. Complete-proof digests, actual conditional records,
usage, continuations and observed capacities agree across repeats.

The fixed cases use genuine registered Tables:

- Scalar: range_8, one selected value 7, m=b=0, r=1, mu ell4/blowup1.
- Grouped: exp_q/hi parameters [7,0,0,6], three real rows padded to four,
  m12/b0/r2, original splits (4,8)/(8,4), mu ell1/blowup1 and ell0/blowup2.
- Signed: exp_q/direct parameters [7,0,0], 129 real rows padded to 256,
  m=b=12/r2, the same original splits, mu ell4/blowup1 and ell5/blowup2.
- Zero: the three-row Table, m8/b4/r1, original splits (2,6)/(6,2),
  mu ell2/blowup2, all original values 256 and every selector byte zero.

Selected non-scalar tuples use row `(37*i+11) mod t`, jointly across columns;
every fourth position is inactive. Inactive original values are 256. Fixed
source identities and the public prefix remain unchanged across repetitions of
a sample. The grouped layouts exercise both prefix pieces and the sole partial
piece; scalar/full and zero cases retain their required full piece.

The table reports mean native times truncated to microseconds and maximum RSS
within each three-sample cell. Original setup includes actual preparation,
certificate production and verification. Producer time includes its internal mu
preparation, certificate production and verification; no separate internal mu
timer is inferred. Import is the additional actual caller registration. Lookup
bytes include embedded mu certificates exactly once; standalone original
certificate bytes are separate. Public Table/selector/statement framing remains
in each receipt.

| Scenario | Field | Total ms | Original setup ms | Producer ms | Import ms | Verify ms | RSS KiB | Lookup bytes | Original certificate bytes |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| scalar | QM31 | 15.549 | 0.755 | 7.866 | 3.838 | 2.189 | 3072 | 206009 | 4697 |
| scalar | OM31 | 22.302 | 0.768 | 12.012 | 5.380 | 3.173 | 3152 | 241257 | 4713 |
| grouped | QM31 | 108.259 | 20.058 | 61.011 | 3.976 | 19.128 | 6768 | 882663 | 691042 |
| grouped | OM31 | 229.634 | 32.433 | 155.357 | 5.238 | 32.597 | 7728 | 955011 | 695394 |
| signed | QM31 | 124.076 | 20.927 | 68.125 | 7.026 | 22.599 | 6896 | 1159116 | 691042 |
| signed | OM31 | 260.161 | 32.513 | 168.750 | 9.379 | 43.662 | 8224 | 1251340 | 695394 |
| zero | QM31 | 22.291 | 9.136 | 5.747 | 1.796 | 4.331 | 3184 | 186246 | 226338 |
| zero | OM31 | 32.357 | 11.999 | 9.855 | 2.185 | 6.821 | 3264 | 206182 | 227426 |

The inclusive native total covers fixture/Table generation through protocol
cleanup, including all registrations, complete production/verification and
receipt observations. Named intervals are disjoint; the remainder includes
cleanup and bookkeeping. Build, launch, argument parsing and final JSON
serialization are outside that timer. Fresh-worker RSS covers the entire native
process, including serialization and allocator retention, and is not isolated
verifier memory. Original messages, prepared sources, certificates, proof and
imported handles remain live through verification.

ProverWork and its actual A3/preparation observations describe named buffer
capacities and their included live overlaps. They exclude vector headers,
record/descriptor metadata and unobserved internal scratch; they are not an
exact allocation peak or a sum of category maxima. Conservative admission
limits remain separate. The producer uses its actual captured points, with no
transcript replay or second tree. Diagnostic statement encoding, receipt
hashes and continuation deltas are charged separately from protocol hash scopes.

The controller preserves all raw outputs, exits, resource reports and source/
binary identities. The imported ledger is byte-identical to the validated
external output. Its root inference-summary fields are zero; component proof
sizes and verifier times live in `model_config.samples`. Original research
workers remained active on the shared host. These bounded c_lu/c_sc/c_c/T_misc
observations establish neither a fitted constant nor a comparative speed result.
The parent E3-07 private source/plan, c_lu and profile obligations remain;
Q12, joint ZK, inference admission and weight-pass claims are unchanged.

## Conditional matmul measurement workers

The native worker runs actual source preparation, certificate
production/import, matmul production and closed native verification. Arguments
select `scalar`, `single`, `stacked` or `zero`; field degree `4` or `8`; and
`smoke` or `full` geometry. The JSON includes the complete public request and
actual records, work, capacities and disjoint stage times through cleanup.
Logical and physical fixture storage are measured separately. Protocol Vec
peaks exclude stack, allocator/runtime, benchmark bookkeeping and the subsequent
diagnostic A1; they are not process RSS.

```sh
cargo run -p stele-negative-controls --example matmul_bench --release --locked --offline -- stacked 4 smoke
```

Save its `request` object as JSON, then run:

```sh
uv run --python 3.12 --locked --script tests/negative-controls/matmul_corpus.py --verify-native request.json
```

This mode receives no matrices, imports both
certificates, verifies the identical matmul wire and consumes the supplied
following public A1 proof. It reports actual records, usage, source/interpreter
provenance and separate decode/import/closed-verifier/continuation timings.
Startup, module imports and final serialization are outside its internal timer.
The existing full correctness corpus remains unchanged.

These workers provide observations for E7-01b. The strict campaign controller,
fresh-process RSS reports and imported complete resource ledger remain required;
this delivery reports no benchmark result or fitted cost-model constant.
