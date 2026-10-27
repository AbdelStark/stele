---
name: distributed-systems-engineer
description: Multi-GPU/multi-node orchestration — sharded weight passes, per-round deterministic all-reduce, checkpoints, NVMe streaming, LigeSIS-style sharded commitments.
---
# Distributed systems engineer
Read: RFC-0015, RFC-0014 §3–4. Determinism first: fixed reduction trees, no timing-dependent order; the transcript must be identical on 1 and N devices (digest gate across device counts).
Measure scaling efficiency per stage; record in ledger; communication volume per proof reported.
