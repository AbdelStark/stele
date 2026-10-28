# RFC-0006 A6 / RFC-0018 streaming benchmark review

Reviewer: codex-root, also the author; benchmark-runner and soundness-auditor.
Not an independent audit. Scope: harness only; no measurement is published here.

- Public items/RFC: a std benchmark example and macOS controller implement A6's
  complete preparation/proving/consumer measurement contract. No core API change.
- Challenges/absorbs: the original A1 engine is unchanged. A separate deterministic
  transcript creates synthetic full-extension input coefficients; it is not a proof
  challenge. The post-proof challenge checks continuation against the actual verifier.
- Claims/consumer: all three original files are retained. Native verification reads
  their canonical values, consumes every claim and checks the continuation. Strategies
  must have identical complete benchmark transport bytes for the same descriptor.
- Bindings/controls: NC-0210 and all current gates remain required. Harness tests
  require ClaimMismatch for one altered unused final and reject truncated transport,
  changed continuation, bad plans and exceeded workspace budgets.
- Ledger: no soundness line changes. The controller validates SC fields and emits
  a micro ledger only after all proof/consumer and source-count checks succeed.
  Profile selects field only; Q12 and profile admission remain open.
  The micro schema keeps inference evidence fields zero; all subproof consumer
  times and actual control coverage remain in model_config/stage_times_ns.
  A consumer-dominated export regression validates both fields with the real
  ledger validator and requires the inclusive total to include consumption.
- Certificates: no integer-inference identity. Synthetic x^degree-y is computed in
  K with all original consumers enabled. Benchmark shapes are explicitly bounded.
- Padding/masks: none added; original/prepared layout and canonical proof fields
  use existing production operations. The transport is not an inference-proof codec.
- Determinism/parity: both fields and degrees 0..4 pass actual Dense/tail/one/multiple
  window pipeline tests. Fixed fixtures and complete binary parity retain all finals.
  No GPU implementation or parity claim.
- Cost model: records fixture generation, preparation, inclusive proving/transport
  and original consumption separately. c_sc observations are effective prover time
  per input point, not isolated field-kernel or fitted global constants. All schedules,
  samples and losses remain. No measured number is claimed until a ledger exists.
- Memory: reports actual retained buffers, path/descriptor/schedule/proof capacities
  and compiled named state sizes. Streaming owns its workspace and source handles;
  Dense counts table capacities before ownership transfer. These are payload/state
  quantities, not allocator/native-stack bounds. Separate native process RSS includes
  transitions, input materialization, transient verifier weights and transport.
  Python/controller and OS caches are excluded; sequential pipeline peak is max.
- Verifier: unchanged no_std production consumer, with checked benchmark transport
  size, canonical limbs and matching descriptor; no disabled binding or bypass.
- Glossary: no new cut, profile, authenticated source or total-host-memory claim.

I tried to break it by changing one unused final, and the benchmark consumer
rejected it with ClaimMismatch. Original consumption is mandatory for every sample.

Sign-off requires local and exact-head hosted gates. Freeze clean source before
measurement and run fields sequentially without competing validation workers.
