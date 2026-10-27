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
