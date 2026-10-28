# Native code implementation review / PR record

## Task
E4-01, branch task/E4-01-native-encoder. Native encoder and all E4-01 acceptance evidence are implemented; task remains
in_progress pending merge. The distance witness script and clean-source
benchmark ledger are linked below. No PCS or end-to-end completion is asserted.

## RFC sections implemented
RFC-0010 A4 / RFC-0020 A4. Sealed typed encoder, closed identity resolution,
regenerated flat sparse graphs, explicit retained-graph budget, fixed setup block
framing, derived conditional metadata, and a fixed catalog export.

## Bindings and controls
No new proof binding or NC-06xx registration. All 72 identities resolve without
setup allocation. M31/QM31/OM31 linearity, systematic prefixes, ordered/duplicate
queries, checked shapes and budget rejection pass. Eighteen complete native
codewords and hash-block counts match independent dense matrix/base evaluation.
The setup tests cover exact framing, invalid coordinates, the 256-word cap,
last-word success, zero/duplicate coefficients and sampled-neighbor uniqueness.
The actual gate rejects a changed sparse map even though it remains linear,
and rejects a changed PCS proven flag. Dependency rejection tests pass.

## Soundness ledger and cost model
No proof challenge, registry label, certified profile, bound certificate or
weight pass changes. Setup metadata states the conditional all-seed bound
separately; full setup/PCS/FS/H composition remains open. Catalog proven flags
stay false and both profile requests return UnsupportedParameters.
Costs are sparse products/additions, fixed-domain setup hashing and complete
retained graph/recursive allocation in c_c/T_misc. The [native ledger and report](../../bench/README.md#native-expander-encoding-e4-01)
record all 27 samples, exact adds/products per input, complete setup/encode/query
costs, every-output integer validation, native live capacities and process RSS.
This establishes a CPU baseline; no fitted constant or performance improvement
is asserted. The independently checked distance witnesses are upper observations
only and are retained in the ledger.

## Gates
Passed fmt; workspace/all-target Clippy with warnings denied; workspace tests;
code all-target tests; no_std build; dependency bans and rejection tests; digest,
negative-controls, soundness-accounting, ledger validation, RFC status, docs links,
glossary and Rust policy. Targeted gate mutations pass. GPU unchanged; no GPU
parity claimed. Existing control coverage remains 3/17 bindings and 14/72 controls,
with one separate configuration control. Digest remains its E8-06 scaffold guard.

## Determinism / padding / masks
Fixed v2 identity, traversal, sorted neighbors, ordered coefficients and Circle
base. No padding, fallback, raw map constructor or caller-supplied authentication
flag. J bounds every recursion and integer shift. Checked graph capacity precedes
allocation; graph offsets are bounded by the regenerated private graph length.
Graph budget is not total memory: caller inputs, all recursive buffers, output,
base transforms and query buffers remain part of the benchmark obligation.

## Soundness-auditor review
Codex-root, also author; same-author skill review, not independent audit.
Checklist in native-code-a4.md applies; all public items cite A4, no challenge or
claim consumer added, no integer-inference certificate claimed, fixed iteration,
exact field parity, no GPU result, no_std/fallible allocations and glossary checked.
I tried to break it by negating every sparse coefficient (preserving linearity)
and flipping a registry proven flag, and the control
`test_rejects_native_code_map_and_registry_substitution` rejected it. The former
requires actual independent map parity, not just linearity or metadata agreement.


## Memory and measurement review

The production encoder has one arithmetic path with live capacity reporting;
ordinary encode/query methods discard the report, not an alternate result.
The report counts retained graph capacity, every recursive y/z/output overlap,
Circle level-vector headers and elements, inverse prefix buffers and selected
columns. The worker adds retained input, original output and identity capacities;
argument buffers are released before timing. OS process RSS additionally includes
the separate integer validator and allocator retention. The graph budget remains
a graph budget, never a total-memory limit.

All new report APIs implement RFC-0010 A4 delivery instrumentation. No challenge,
absorb, emitted claim, consumer, proof binding, ledger loss, integer certificate
or padding rule changes. Fixed traversal and field arithmetic preserve exact
outputs. The no_std library uses checked capacity additions and fallible vector
reservations. Removal follows an owned allocation; no exposed caller controls
these counters. Reports are measurement data, never verifier admission evidence.

Workspace tests, all-target Clippy, no_std, fmt, dependency bans and all applicable
repository gates passed. The code all-target tests, independent native map/base
fixture checks, distance witnesses and actual benchmark receipts passed. A gate
mutation omitting graph capacity failed; receipt mutations removing output checks,
validation time, live memory or arithmetic work failed. The independent map test
still rejects a changed linear map. No GPU code or end-to-end digest was added;
existing control coverage remains unchanged. Glossary and Rust policy passed.

I tried to break it by omitting retained graph memory and understating completed
work, and the control `test_rejects_omitted_native_graph_memory` and actual-receipt
rejection tests rejected it. These are measurement/gate tests, not additional
proof-statement controls. This remains a same-author soundness-auditor skill
review; no independent audit is claimed.
