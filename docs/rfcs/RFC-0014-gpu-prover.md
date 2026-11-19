# RFC-0014 — GPU prover architecture

Status: Accepted · Version: 0.1.0 · Depends: RFC-0006–0010

## 1. Principles
- The CPU/SIMD prover is the reference; CUDA produces byte-identical proofs (INV-3). Same algorithms, same variable
  orders, same reduction strategy ids; only the execution differs.
- No floating point. All kernels are integer (`u32`/`u64`) with M31 lazy reduction inside warps.
- The prover is a **streaming** pipeline over stages (RFC-0007 §4); device memory holds one layer's recompute window
  plus the stacked sumcheck state; weights stream from HBM/NVMe once.

## 2. Kernel inventory (generated from one op table shared with the CPU backend: `crates/stele-kernels/ops.toml`)
| Kernel | Work | Notes |
|---|---|---|
| `m31_ops`, `qm31_ops` | field arithmetic | lazy `[0,2p)`; QM31 Karatsuba; 64-bit delayed reduction |
| `partial_eval_bucketed_{w4,w8,i16}` | `f̃(r, ·)` for small-value tensors | one pass, bucket accumulate in shared memory, `eq` table in L2 |
| `sumcheck_round_deg{2,3,4}` | round polynomial + fold | warp-level reduction, base-field first rounds (BDT), eq-trick variant |
| `logup_leaf`, `logup_level` | fraction trees | fused: compute level `t+1` while emitting round data for level `t` |
| `zerocheck_eq` | `Σ eq(ρ,x)·C(x)` | Gruen split |
| `rs_encode_circle` | one-time weight encoding | circle FFT (registration only) |
| `raa_encode` | linear-time code for cuts | permutation + accumulate ×3, L2-resident |
| `blake3_merkle` | leaves + tree | 1 block per leaf, short columns |
| `recompute_layer_int8` | CQIS forward for one layer | reuses the serving int8 GEMM (CUTLASS) with exact int32 accumulation; `exp_q` etc. as table gathers |
| `attention_tile` | `S`, `P̂`, `Z`, partial evals per tile | flash-style tiling; tile consumed by `logup_leaf` and `partial_eval` in the same launch |
| `transcript_absorb` | host side | not a kernel |

## 3. Weight pass kernel
Input: packed int4/int8 `W_τ` fibre-major by `(ℓ,k)` (contiguous `j`), `eq_j ∈ K^{d_out}` (≤ 1 MB, L2). For each `(ℓ,k)`:
accumulate `eq_j` into `2^b` buckets (`b = 4` or `8`) in registers/shared memory, then `B[ℓ,k] = Σ_v v·bucket_v`.
Arithmetic ≈ 4 K-adds per weight; bytes ≈ 1 (int8) ⇒ bound by HBM (3.3 TB/s → 405 GB in ≈ 0.12 s) or NVMe (≈ 2–4 s at
100–200 GB/s per node; prefetch during earlier stages). Multi-GPU: `(ℓ,k)` ranges sharded (RFC-0015).

## 4. Memory plan and recompute
- Residual cuts: int16 `n·d·(L+1)`; 405B/4608 ⇒ 19 GB (host or HBM).
- Stage `s` needs, per layer, the virtual tensors of its reduction: recompute layer `ℓ` from `R_ℓ` (one int8 layer forward)
  immediately before the layer's contribution to the stacked sumcheck; discard after. Attention tiles are recomputed per
  reduction that needs them (3 sweeps: exp lookups, `P̂·V` partial eval, `Z`), or cached if memory allows (`plan.json` knob).
- Stacked sumcheck state: after the first `k` base-field rounds (small-value), the folded state is `K`-valued and `2^{−k}`
  of the original; the plan chooses `k` so that state ≤ 40% of device memory; otherwise two-pass streaming (RFC-0006 §5).
- The `n²·h` exp phase is tiled so that no `n²` object is ever resident.

## 5. Parity protocol (`scripts/gates/parity.sh`)
For each kernel: randomised inputs (seeded), CPU vs GPU outputs compared bit-exactly, 10³ cases. For the prover: 50 random
small-model proofs per PR, byte-identical digests. Any divergence blocks merge; no "approximately equal".

## 6. Instrumentation
Every kernel reports elements processed and elapsed cycles into the bench ledger; `c_w, c_a, c_x, c_c, R` are fitted from
these (RFC-0018). Roofline plots are produced by `stele-bench roofline`.

## 7. Negative controls
GPU-specific: NC-1000 lazy reduction leaking `p` as a value; NC-1001 bucket overflow for `b = 8` with `d_out > 2^23`
(must be rejected statically); NC-1002 tile boundary off-by-one in masks.

## 8. Amendment log

### A1 — Account for the streaming fallback's source and transition

Status: Accepted. Question Q22; paired with RFC-0006 A6. Review:
[A6/A1 skill passes](../../agents/reviews/streaming-a6.md).
Motivation: the original 40% rule counts only a folded-tail estimate and promises
an unspecified two-pass fallback. The complete CPU contract separates source
visits, preallocated work/proof buffers and actual process/device resources.

Exact replacement for §4's stacked-sumcheck-state bullet:

> Select a strategy whose complete planned device allocation peak fits the
> plan's budget. The 40% limit includes every device-resident source buffer,
> grid, tail, proof/descriptor buffer, scratch allocation and retained capacity;
> host/external source storage and total pipeline memory are reported separately.
> If a validated small-value configuration does not fit, use an explicit
> schedule under RFC-0006 A6 and its detailed buffer contract, or reject the
> unsupported plan. Two source visits are a feasible one-window specialization,
> not a universal fallback. Charge layout preparation, source replay, transfer
> bytes and any virtual-tensor recomputation to the plan. A replay cannot add
> a weight pass under RFC-0007.

The CPU source and arena contract does not approve a GPU implementation or
establish a device budget from host measurements. GPU delivery must measure
actual device allocation and transfer lifetimes, including host/device overlap,
then pass the unchanged CPU/CUDA byte-parity gate. A caller's workspace budget
alone cannot establish the 40% condition. No new GPU code is introduced here.
Soundness: no implemented challenge or ledger change; original consumers and
CQIS certificates remain. Cost: c_sc/T_misc, source/working memory and T_witness
when recomputation is actually integrated. No measured constant or pass count
changes. Affected tasks: E3-05 and downstream GPU planning/streaming work.

### A2 — Development-profile resident field backend

Status: Accepted (development-tier amendment under RFC-0027 §2). Task E20-10.
[Independent lane Z review](../../agents/reviews/e20-10-dev-zk-backend-contract.md)

**Motivation.** ADR-138 qualifies implementation on the measured E45 CPU
path. Any claim about its speed on different CPU code requires an equally
qualified reference. A complete device-produced proof requires independent
byte parity. [Calibrated projection](https://github.com/AbdelStark/stele/blob/b711bd764c294cea3ea3c98d1ef63f106fad3ca3/bench/ledger/e16-40ag-t32-resident-projection.json)

**Addition to §§1–2.** A caller may select an explicitly required CUDA
backend when proving a balanced development-ZK window (profile byte 4).
The default is the existing CPU path. Backend selection is local execution
configuration. A selected device operation must finish on that device or
return an error. The implementation declares which operations are selected.
The caller uses the ordinary lifetime-index reservation, persistence, proof
encoding and self-verification path. Masks, ordered Fiat–Shamir draws, aborts,
claimed-sum checks, routed claims, certificate verification and authenticated
openings keep their original authority and order.

The first interface in `stele-kernels` is the field-only backend for the
ordinary RFC-0013 A5 item-5 batches. Its CPU implementation defines the
reference for every operation. Its CUDA mirror implements the same operations.
The op table names source import, dense batch construction, round, fold and
final evaluation. For each proof attempt the caller starts a fresh backend session, which
may share its device context. Source import accepts the exact immutable
message associated by the caller with its authenticated source and binds
the owner to that session, identifier and physical dimensions. An identifier
can be imported only once per session. Every consumer checks the session,
identifier and dimensions. An owner from a different proof, retry or concurrent
session is rejected even if the identifier, dimensions and device are equal.
Certificate and root verification belong to the caller. For physical dimensions `2R × 2C`
the source contains exactly `4RC` base limbs. The data face uses the left
`C` columns of every physical row. The batch borrows the caller's ordered
claims and transcript-derived coefficients. A claim carries its ordered
`(position, weight)` pairs and claimed value. Multiple contributions to
one position are added in order, including repeated positions inside a claim.
Each data position must be below `RC`. The lower `RC` positions of the
weight table contain those sums and its upper `RC` positions are zero.
The caller checks the returned sum against the instance's claimed sum.
Construction yields an opaque two-factor state. Each round returns the
degree-two product's three evaluations in existing node order. Fold binds
one MSB-first coordinate at the supplied field point. Finals return the
weight and face evaluations in that order after the final fold. Every
operation checks its input extent and state transition. The reductions
adapter owns the instance check and calls the existing checked masked prover.
The backend has no transcript, proof, authentication or verifier interface.

**Addition to §§4–6.** Account for all allocations under A1, including live
owners, promotion, staging and retained device capacity. Charge host work,
copies, cold startup and externally retained storage separately. The hardware
gate runs 1,000 seeded byte comparisons per implemented operation, including
zero, one, `p−1`, `p` and lazy representatives. It fails if CUDA is unavailable
or a requested operation does no device work. For byte 4 it additionally
requires 50 complete random small-model inference proofs with distinct
weight artifacts and independently pinned CPU results. Use the identical
source, public inputs, seeds, index and lifetime geometry within each pair.
Compare canonical public and proof bytes, verify both normally and exercise
a changed expected model. Require positive device-call counts consistent
with every selected invocation in every candidate. Report the actual corpus
geometry. The separate stories42M T32 rung checks the full original workload
and memory budget. Other profiles, architecture coverage, kernel families and
complete-prover milestones retain their existing gates.

**Soundness, cost and controls.** No bound, parameter, round, error term,
ledger line, committed cell, lookup, public byte or honest proof byte changes.
The target cost terms are `c_sc` and `T_misc`. Preserve the ordinary NC-0915
weight-final rejection. Exercise a corrupted round, a wrong source owner,
a same-id/same-extent owner from another session, wrong source extent,
unavailable CUDA and malformed transition in the device
differential. NC-1000 covers canonical field output. This interface specifies
no new binding and confers no profile promotion. Affected tasks include
E20-03, E20-04, E20-10, E20-11 and E20-12.

### A3 — Live field execution of balanced dev-zk LogUp-GKR

Status: Accepted (development-tier amendment under RFC-0027 §2). Task E20-13.
[Independent lane Z review](../../agents/reviews/e20-13-live-gkr-contract.md)

**Addition to A2, §§2 and 5.** An explicitly selected balanced dev-zk backend
may produce each RFC-0008 A7 GKR step through the same proof-local field
interface. A combined implementation must execute every scheduled GKR step
and each selected ordinary batch. A backend error aborts the proof attempt.

The reduction derives the original instance, declared degree, variable order
and coefficients from the plan and transcript exactly as in the reference.
It passes the field backend the compact summand for a grouped leaf and the
ordinary summand for other steps. Its construction describes scaled equality
on an interval, the interpolated periodic block, projected original columns,
the selected numerator/denominator child at its side, Boolean padding, public
member selectors, the tuple-compressed table and a concatenation of projected
tuple members. Positions are MSB first. Columns and child layers are borrowed
from the caller's genuine step. Source-owner views, where used, must satisfy
A2's identity and lifetime checks. Masked factors retain their base polynomial,
the mask polynomial indexed by its original coordinates and the vanishing
coordinate. Their value is the base plus the mask times `v(1−v)`. The
authenticated mask source and shared seed stay in the original reduction.

For every coordinate the backend returns the declared degree plus one ordered
field evaluations. The ordinary checked masked prover adds its own mask
polynomial, checks the running sum and absorbs the resulting message before
drawing the next challenge. The backend folds every factor at that actual
challenge; when the vanishing coordinate is bound it incorporates its mask.
After the final fold the backend returns compact values in construction order.
The reduction uses the actual folded point and original borrowed columns and
mask blocks to expand all required original inputs in the existing A7 order.
The existing product, public-final, rank, vanishing, GKR continuation and
claim-routing checks remain in force. The backend can neither draw challenges
nor supply verifier decisions. The normal path does not first run an entire
CPU summand as an oracle.

Charge host packing, transfers, device execution, final expansion and remaining
CPU routing. Imported columns, masks, public tables and materialized layers each
count as real input or a checked borrowed view. The planned simultaneous
device allocation and measured high water, including the source and promotion
temporaries, obey A1. An unsupported geometry or insufficient memory returns
a checked error. A shared context alone never proves a source owner matches.

**Soundness and controls.** No round, degree, challenge order, error line,
commitment, column, lookup or honest proof byte changes. Preserve NC-0912,
NC-0915 and the existing compact-substitution controls NC-0930–0932. The
field differential exercises mismatched factor indices, round degree,
vanishing coordinate, span extent and premature finals. Require per-operation
1,000 seeded device/scalar comparisons, genuine compact and expanded GKR shapes,
and 50 complete CPU/CUDA proof pairs using the normal selected entry with
both GKR and batch device calls present in the actual candidate. The original
T32 reports all 385 GKR steps, ordinary verification and memory/transfer
charges. No profile promotion. Target cost terms are `c_lu`, `c_sc` and
`T_misc`. [Measured GKR operations](https://github.com/AbdelStark/stele/blob/ce366e0f/bench/ledger/e16-40af-t32-gkr-originals-h100.json)

### A4 — Live field execution of balanced development-ZK relation sumchecks

Status: Accepted (development-tier amendment under RFC-0027 §2). Task E20-15.
[Independent review](../../agents/reviews/e20-15-live-relation-contract.md)

**Addition to A2 and A3.** The balanced development prover may select a field
backend for every RFC-0013 A5 relation sumcheck alongside the ordinary batches
and LogUp-GKR steps. The reduction constructs the same instance and draws the
same combination coefficients and free coordinates in their original order.
It supplies the existing term coefficients, ordered factor indices, variable
count and declared degree. Factors appear in instance order: the optional
leading equality factor, each private occurrence, then each public input.

Each factor supplies a field table and ordered MSB-first domain coordinates.
The table has exactly one element per Boolean assignment of those coordinates;
its value repeats over omitted variables. The caller may borrow the original
column on a pure variable projection. It preserves the reference projection
for fixed or transcript-derived coordinates, including contraction and shared
free points. It may provide the resulting field table. A private occurrence
also carries its original M31 mask block, its ordered coordinate indices and
the vanishing variable. A public factor has no mask. The relation constructor
checks dimensions, positions, mask extents, term references and declared
degree before opening the state. It may share the A3 arithmetic for evaluating
and folding these factors, including repeated factors within a term.

The checked masked prover takes the device's ordered field evaluations,
adds its ordinary mask, checks the running sum, absorbs the message and
draws each challenge. The backend folds at that challenge and returns
one final field per original factor. The reduction keeps every public-final
check, vanishing and rank abort, occurrence claim, mask claim, ordered
batch and authenticated opening. A device error aborts the attempt through
the existing index reservation and restoration path. The complete driver
executes all selected relation, GKR and ordinary batch invocations; host work
on projection, masks, copies, elapsed time and peak allocation stays charged.
The CPU default follows its existing path.

**Soundness and controls.** No new round, degree, challenge, error line,
column, lookup, opening or proof byte. Preserve NC-0909 through NC-0912,
NC-0915 and NC-0916. Exercise one changed device round, malformed field
geometry, missing mask limbs and out-of-range term or coordinate references.
Require 1,000 seeded scalar/device comparisons per implemented operation,
50 complete distinct small-model CPU/CUDA proof pairs with all three stage
inventories, and a verified original stories42M T32 inference with actual
transfer and A1 memory charges. Measure `c_sc` and `T_misc` on the named rung.
The prior research measured the independently checked relation arithmetic.
[Research evidence](https://github.com/AbdelStark/stele/blob/817a5059ba0375d1ee4ae3ad427e033533b197d2/bench/ledger/e16-40aj-h100-complete-proof-parity.json)

### A5 — Prepare and open balanced hiding-source material on the selected device

Status: Accepted (development-tier amendment under RFC-0027 §2). Task E20-17.
[Independent review](../../agents/reviews/e20-17-hiding-source-contract.md)

**Addition to A2–A4.** For the byte-4 proof, the selected backend can prepare
the RFC-0010 A15 salted Circle columns and Merkle tree underlying each original
early, top and shared source. The host derives the source id, physical extent,
rate 1/4 Circle code, column descriptor and source-specific salt stream under
RFC-0013 A8. Import the exact immutable row-major M31 message once in this
proof session. The original outlives its certificate, ordinary batch consumers
and authenticated opening. Foreign owners, mismatched geometry and repeat
imports reject under A2.

One preparation visit binds that owner and the caller's salt seed to the A15
encoding. It performs the canonical Circle transform over each row and hashes
each salted leaf and every parent in its RFC-0012 A3 domain. Return the full
root and charge the work of the tree. For a transcript-selected index, return
the canonical column and its bottom-up Merkle siblings; the adapter may derive
the selected 32-byte salt with the same host MaskStream. Check the index,
payload width and path depth against the host source. Never coalesce or reorder
proof responses. The caller uses the ordinary RFC-0010 A16 certificate and
opening path. A producer result confers no verification authority.

The encoded columns and nodes may be released after the certificate visit.
If released, reconstruct them from the same original for the opening visit and
compare the reconstructed root with the first root before supplying responses.
Every visit keeps the source's original opening budget, seed, persisted history
and rank checks. Lifetime-model roots still must equal their published pin.
The verifier checks each actual certificate and opening under the expected
context. Keep host row combinations and all Fiat–Shamir and failure paths.
Account for each transform and tree, copied metadata and selected bytes, host
salt assembly, scratch, original owners, retained nodes, context and pool.
Peak across coexisting operations stays within A1.

The scalar reference is the established host Circle encoder, salted column
preparation and Merkle path. The buffer interface operates on words, roots
and sibling bytes. It has no entry point for authentication, transcripts,
opening records, rollbacks or lifetime reservations. The optional device
backend may hold the salt key only within the trusted proving computation;
public qualification artifacts contain outputs, sizes and counters.

**Soundness, cost and controls.** The same A9/A15 binding and soundness lines
apply. No new challenge, error, commitment, lookup or wire field. Targets are
Circle encoding, Merkle construction and host/device transfer. Compare device
roots and individual columns and paths against the scalar reference on 1,000
seeded cases, including repeated queries and both single- and multi-chunk
BLAKE3 leaves. Change a root on reconstruction and one selected sibling and
require the corresponding rejection. Keep NC-0601, NC-0602, NC-0606 and
NC-0607. The combined gate requires positive source, relation, GKR and batch
counts for all 50 pinned proof pairs and actual T32 CPU and H100 inference
with every selected visit, A1 memory accounting and independent verification.
[Source experiment and T32 visit evidence](https://github.com/AbdelStark/stele/pull/422)

### A6 — Produce balanced lookup tops and retain GKR child layers

Status: Accepted (development-tier amendment under RFC-0027 §2). Task E20-19.
[Independent review](../../agents/reviews/e20-19-lookup-tree-ownership.md)

For each balanced byte-4 lookup, a selected prover may construct the RFC-0008
A7 tree through the proof-local field backend. The reduction derives the lookup
ordinal, tree exponent n, top exponent k0, ordered members and the table from the
same validated statement as the scalar prover. After it absorbs the original
multiplicity sources and lookup messages it draws β and α from the transcript.
These exact values apply to both visits. The field backend receives the actual
member intervals, original ordered MSB-first projections, signed shifts, public
selectors, ordered table rows and valid extent. Every private column leg and
the multiplicity use the original A5 source owner. The reduction derives the
logical column offset and extent from the source layout; each access maps to
the data quadrant of the actual physical M31 message. Check the proof session,
source identity, row and column geometry and complete logical extent before
use. Equal field data does not establish provenance.

At the first visit, return exactly the ordered `2^k0` pairs (p,q). The host
computes h=p/q with the original inverse, aborts on a zero q, and supplies the
same three columns to the existing top-source commitment. At the next visit
that actually needs a child, reconstruct from the same inputs and retain an
opaque tree for this one lookup. A first-and-leaf step reads no child and
requires no reconstruction. For each nonleaf A7 step at level k, bind its four
original child factors to level k+1 with the specified polynomial, side and
mask in original instance order. The backend rejects foreign sessions, lookup
identities, levels, sides, components and extents. The caller must bind a tree
to its exact preparation, including its immutable inputs and challenges; a new
attempt or repeated lookup ordinal cannot reuse an old tree. A3's masked
rounds, finals, original claim routing and checked transcript remain in force.

At Boolean position x, let s be the selected row indicator, t the shifted
tuple compressed with the successive powers of β, m the multiplicity (zero
outside its extent), and qT the existing table branch (one outside its valid
extent). The first parent may be computed directly from the two A7 branches
`[s, α−s·t]` and `[−m,qT]`. It is `[s·qT−m·(α−s·t),(α−s·t)·qT]`.
The highest child level any nonleaf reads is n. A producer may omit the raw
branch level n+1. The final nonleaf may consume the tree after its child factor
reads complete and before the first fold. All tree-backed reads finish before
the allocation is released; an owner is never retained into the leaf step.

**Qualification.** Exercise at least 1,000 canonical and raw device inputs
against the original CPU tree, comparing each consumed child and top in
order. Require controls for closed and foreign same-geometry owners, changed
offset/side/multiplicity/selector/shift, invalid extents, and zero-denominator
rollback. Compare 50 pinned complete CPU and selected proof pairs with
source, relation, GKR, lookup and ordinary-batch calls; demonstrate a replay
and independent expected-model and wrong-model verification. On Stories42M
T32 report all top visits, retained rebuilds, all consumed child factors,
and every GKR step. Charge all visits, original and derived data movement,
scratch, flags and total live device memory under A1. Compare end-to-end wall
time with a same-host scalar proof. Existing research measured top and rebuild
visits and confirmed each consumed layer against the scalar tree.
[Component ledger](https://github.com/AbdelStark/stele/blob/ce366e0f/bench/ledger/e16-40af-t32-gkr-originals-h100.json)

The cost terms are lookup tree construction, GKR child construction and
transfers. This change adds no challenge, error term, source, proof byte or
verifier operation. E20-20 validates the combined normal path.
