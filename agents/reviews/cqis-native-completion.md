# E5-02 native delivery acceptance audit

Author/reviewer: codex-root; same-author cqis-numerics and soundness-auditor
passes, not independent audit. Scope is the complete native delivery in
[RFC-0021 §6](../../docs/rfcs/RFC-0021-cqis-functions-and-tables.md), under
RFC-0004 A4. Every implementation covered here is merged through
[PR #128](https://github.com/AbdelStark/stele/pull/128).
The task's three acceptance lines are satisfied by the evidence below.

## Stable identities and documented error

The [component tests](../../crates/stele-cqis/tests/table_descriptors.rs) compare
all thirteen committed descriptor/identity vectors; the
[function tests](../../crates/stele-cqis/tests/functions.rs) compare all committed
function/representation bytes and cover the eleven closed function names.
[Manifest tests](../../crates/stele-cqis/tests/manifest.rs) match the complete
Python manifest, sorting, shared-component union and duplicate rejection.
Version, parameter, representation and component-role changes cannot silently
reuse an expected definition. Identity does not authenticate model configuration.

RFC-0021 §5 states uniform error bounds, with derivations linked from §3:
product exp has absolute error strictly below two output integer units;
nearest exp and each activation have error at most one half unit relative to
their own real functions; correction is in {-1,0,1,2}; ranges are exact.
For RMSNorm the inverse error uses delta=49153/536870912; successful output
error is at most 2^E*(32768/2^G)*ceil(sqrt(d))*delta+1/2 integer units.
These are analytical bounds, not sampled maxima or model-fidelity measurements.

## RFC-0021 §6 requirement audit

| Requirement | Implementation and executable evidence |
|---|---|
| 1: complete closed schemas, generation and canonical validation | Private descriptors, representations, generated Table and Manifest cover every registered component/function/mode. `accepts_generation_dispatch_for_all_registered_components` exercises all thirteen generators. Full bytes include expected identities, shape, entries and padding; manifest validation compares the regenerated exact closure. [Descriptor](cqis-native-descriptors.md), [function](cqis-native-functions.md), [fixed-table](cqis-native-fixed-tables.md) and [manifest](cqis-native-manifest.md) reviews document authority and allocation checks. |
| 2: full representative tables and varied nonlinear inputs | The corpus inventory below covers every nonlinear function, full canonical table data and independent integer gathers. All committed descriptor, function, representation and manifest vectors match. Reference processes occur only in harness code. |
| 3: canonical QM31/OM31 public MLE | The mandatory [release harness](../../crates/stele-cqis/examples/table_mle_parity.rs) checks 10,000 points for each of fourteen configurations in each field: 280,000 total. Its independent Boolean-weight oracle covers every kind, maximum shapes, a two-row high table, signed lifts and padded zeros. [MLE review](cqis-native-mle.md) records dimension checks and the sealed field interface. |
| 4: mutations, resource failure and whole-table failure | Native descriptor/function tests reject malformed/trailing lengths, versions, parameters, identity and role/order substitutions. Fixed/activation tests reject changed entries, shapes, padding and field-congruent integer aliases. Manifest tests alter every byte and reject changed expected selections. Internal Natural, Table, Manifest and norm tests reject impossible capacities; activation/GeLU/manifest tests reject whole-table overflow. [RMSNorm tests](../../crates/stele-cqis/tests/rmsnorm.rs) also reject late output overflow without changing borrowed inputs. |
| 5: required gates | The exact tested implementation head and successful required jobs are recorded below. Dependency bans, no_std, fmt/clippy/workspace, digest, negative-control and soundness-accounting checks all passed. This delivery changes no GPU code and makes no performance claim. |

The exact generator uses bounded integers with fallible owned storage, without
floating point, unsafe code or a reference subprocess. Natural scratch has a
fixed 2^18-bit cap with derivations in its module; metadata limits precede
allocation. No raw-row constructor or external table-authority callback exists.
Production dependencies remain stele-field and pinned no_std BLAKE3 1.8.7;
serde_json is dev-only. Dependency and no_std gates cover the locked build.

## Numerical corpus inventory

Paths below are under `research/cqis-tables/`; each Python check regenerates its
committed fixture, which the required Rust tests compare against native results.
The [CI workflow](../../.github/workflows/ci.yml) runs these checks and the full
public MLE harness with no reduced-count option.

| Function or component | Required evidence |
|---|---|
| Product exp and nearest exp | `check_native_exp_functions.py`: 32 configurations per function, 10,000 inputs per function, 192 complete component-data digests and NumPy indexing/recombination. Independent positive-series reciprocal arithmetic checks native alternating-series generation. Direct and corrected nearest representations agree, including endpoints and split transitions. |
| Sigmoid, SiLU and softcap | `check_native_activations.py`: 10,000 varied entries plus 30 boundary cases per function, three full 65,536-row tables, 10,000 NumPy gathers per table and 10,000 integer endpoint-rounding cases. |
| Exact GeLU and tanh-GeLU | `check_native_exact_gelu.py` and `check_native_tanh_gelu.py`: each has 10,000 varied entries plus 30 boundary cases, every normalizer precision, a complete 65,536-row table and 10,000 NumPy gathers. Strict finite tails, exact zero and overflow are exercised. |
| Rsqrt and range_8/12/16 | `check_native_fixed_gathers.py`: full canonical data for all four tables and 10,000 NumPy gathers each. Every one of the 49,152 real rsqrt entries also passes an independent integer bisection check of its rounding cell. |
| RMSNorm | `check_native_rmsnorm.py` and `tests/rmsnorm_parity.rs`: 11,000 rows, including 10,000 constructed to fit; 10,889 accepted and 111 overflow decisions agree. Independent exact rational normalization/root arithmetic and NumPy int64 gathers/rounding cover full rows and retained intermediates. Direct tests include maximum d, epsilon boundaries, signed endpoints, normalization remainders and negative shifts. |

## Exact merged implementation evidence

Head `640a0d13753095b657ddde33370018e101daca82` passed
[CI run 40816647877](https://github.com/AbdelStark/stele/actions/runs/40816647877):
`gates` job 123259171589, `poseidon2-reference` job 123259171799 and
`simd-throughput` job 123317464143 all completed successfully. The gates job
includes every native Python check, workspace tests, the full 280,000-point
MLE comparison and the standalone CQIS no_std check. GPU/nightly jobs were
skipped by their configured conditions; this is not evidence of GPU parity.
Merge `5b43f760db46d48d26ff16f71dda95b8c82afc4e` has the same tree as that
tested head, checked before and after merging. This completion record changes
no native implementation, fixture, dependency or gate and requires its own
exact-head PR checks before merge.

## Preserved obligations and review checklist

No new public item, challenge, emitted claim, claim-graph edge, mask, soundness
line or bound-certificate instance is introduced by this status update.
The existing primitive algorithms are deterministic with canonical zero padding;
public MLE returns a separate validity polynomial, not lookup selector enforcement.
No cost-model constant, weight pass or committed intermediate changes. No
benchmark or CPU/GPU inference throughput follows from numerical parity.
Verifier no_std/resource checks are covered above; terminology follows the glossary.

I tried to break the audited boundaries with wrong versions, component roles,
canonical bytes, padding, field aliases and overflowing configurations, and the
control checks in the cited native tests rejected them. These are primitive
tests, not catalog negative controls. NC-0412/0413/0414 and the existing table,
recombination, norm, domain and passport controls still require actual consumers
under Workflow 08; this audit adds no control coverage.

Only E5-02 is completed. E3-08, E5-03/E5-04/E5-05, E7 norm reductions, E9/E10
and E12-05 retain their original requirements. The full quantiser, static
certificate consumers, authenticated source/operation plans, full CQIS forward
pass, fidelity evaluation, private PCS, ZK, lookup and end-to-end proof delivery
remain open. Generated tables and manifests do not accept an inference proof.
