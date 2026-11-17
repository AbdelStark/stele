# Genuine GKR device comparisons (E16-40m)

This research consumer uses the merged `GkrCase` interface from E16-40g. The
question is whether the resident CUDA rounds preserve genuine production GKR
factors, compact finals, expanded finals and routed claims. A mismatch ends the
candidate. Budget: one reviewed implementation and one bounded H100 campaign.
Hardware qualification is pending; no performance or integrated-proof claim.

`gkr::shape` checks the unfolded domain, mask-table dimensions and coordinates,
degree and term indices before packing. It preserves the original domain and
factor/term order. A table with only base-field values becomes a dense M31
upload; other tables remain dense QM31. These are CPU-built tables. The existing
device builder uploads them and copies extension tables into resident buffers;
this does not qualify device factor construction.

The comparison checks the initial tables, every round polynomial and every
folded table against the production `Masked` reference at the genuine transcript
challenges. Every compact final is compared before `expand_at`. The host control
changes each slot of a compact leaf, including slots whose change leaves the
expanded output unchanged. Such a change must fail with `compact finals`.
Expanded finals and all source, shared-block and child claims must then equal
the actual CPU step. Public-final checks and all ordinary aborts remain enabled.

The corpus reuses the existing seeded production lookup fixtures: tuple widths,
heterogeneous members, selected rows, shifts and padding vary. All GKR steps of
each of the 1,000 statements run, alternating narrow and balanced lifetime
geometry. Each proof has a fresh deterministic synthetic proof/model seed and
must verify through the ordinary CPU verifier. The required H100 test repeats
each step with canonical and raw lazy tables and coefficients. An absent device,
skipped case, incomplete proof or mismatch fails. This observer cannot replace
proof values; none of these CPU proofs count as integrated GPU proofs.

## Work and storage accounting

Host reference construction, packing, expansion and claim routing are separate
from resident round/fold work. In the H100 harness, one production reconstruction
classifies the step, one supplies the packed shape, and each representation
rebuilds a folding reference and an expansion reference. The converted shape is
held across the two representations. Expansion and routing happen on the host
once per representation. These are real costs for any later measured consumer;
the enclosing CPU proof and reference comparisons are qualification overhead.

Per representation the receipt records input payload and descriptor uploads,
round pointer/type uploads, round-polynomial and factor-table downloads, raw-test
transfers, and initial/maximum retained explicit device capacities. Table reads
include allocated capacity even after folds shorten the live prefix. Raw-test
transfers include both readback and upload for lazy injection and are separate
from candidate transfers. The helper's host clones and comparison vectors are
additional host storage. None of these counts includes allocator/driver retention,
cold context/module overhead or temporary staging/first-fold overlap in a complete
pipeline peak. Existing build phase timers remain available; whole-operation
measurements must also charge reconstruction, conversion, expansion, routing and
every transfer. Publish timing numbers only with validated ledgers.

This can retire the bounded production compact-final consumer risk in `c_sc` and
`T_misc`. It does not establish actual stories42M operation costs, a complete
device memory plan, backend integration, full CPU/GPU proof parity or ADR-127 GO.
