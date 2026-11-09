# RFC-0015 — Distributed proving

Status: Accepted · Version: 0.1.0 · Depends: RFC-0014

## 1. Topology = serving topology (ST-8)
Devices own layer ranges (pipeline shards) and, within a layer, `(ℓ,k)` ranges of weights (tensor shards). A stacked
sumcheck is executed by every device on its blocks; per round, the `δ+1` K-elements of each device's partial round
polynomial are all-reduced (NCCL/MPI); the challenge is derived by every device from the identical transcript.
Communication per proof ≈ `(#instances × rounds × (δ+1) × 16 B) × log(devices)` ≈ MBs. Determinism: the reduction order
of partial sums is fixed (tree order by device rank) so the transcript is bit-identical regardless of timing.

## 2. Weight pass
Shard `W_τ` by `(ℓ,k)` ranges; each device computes its slice of `B`; `B` is gathered (32 MB) for the sumcheck over
`(ℓ,k)`, which itself is sharded by the same ranges. Fused opening: the device owning the columns opens them.

## 3. Cuts and PCS
`R_stack` rows `(ℓ,i)` are sharded by layer; each device commits its shard (root of roots, RFC-0010 §9). Openings:
row functionals are per-device partial sums; column openings touch one device per column.

## 4. Fault model
Any device failure aborts the proof (no partial proofs); the orchestrator retries from the last stage checkpoint
(stage boundaries are natural checkpoints: the transcript state + stacked claims). Checkpoints are deterministic.

## 5. Multi-node
Nodes communicate only round polynomials and `B` gathers; weights never move. NVMe-resident weights per node.

## 6. Scaling targets (RFC-0018)
≥ 0.85 parallel efficiency from 1 → 8 GPUs on 405B; ≥ 0.7 from 8 → 32.

## 7. Negative controls
NC-1100 one device skipping its block (round sums must mismatch the claimed sum); NC-1101 non-deterministic reduction
order changing the transcript (digest gate).

## 8. Amendment log

### A1 — Plan-fixed cut shards and column-opening ownership (companion of RFC-0010 A13)

Status: Accepted. Question Q17. Review: [sharding Q17 acceptance](../../agents/reviews/sharding-q17-acceptance.md).
Motivation: §3 lets "each device commit its shard", which ties the commitment to
the device count, and says a column opening touches one device. Both conflict
with RFC-0010 A13. §2's last sentence reads as a protocol rule for weights.

Exact replacement for §3: "A sharded cut source is an RFC-0010 A13 source. Its
shard exponent s is fixed by the plan, independent of device count; a device owns
a contiguous range of shard indices in rank order and builds those child trees.
The root of roots and every proof byte are the same for 1 and N devices. Row
functionals are summed into one row (RFC-0010 A13 item 9); every column draw
collects one segment and path from every shard."

The plan format has no shard-exponent field today, so every R_stack source uses
s=0 until an Accepted plan amendment (RFC-0005) adds one and states how it is
derived from public plan data. E11-01 owns that amendment before it commits any
cut with s>=1. A device count larger than S leaves devices without a shard, and a
device count that does not divide S gives devices unequal shard ranges. Either
affects only scheduling, never s or any byte.

Clarification of §2's last sentence: weight sources are passport sources with
s=0 (RFC-0011); "the device owning the columns opens them" names which device
stores the encoded columns and tree nodes and answers a query. It is prover
storage, not a protocol message, and no root of roots is used for weights.

Soundness and cost impact are RFC-0010 A13's; no challenge, label or ledger line
is added here. Affected tasks: E11-01 (plan field and digest parity under s>=1),
E11-02 (no change).
