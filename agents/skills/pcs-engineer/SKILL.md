---
name: pcs-engineer
description: Implement interleaved-code PCS, encoders (circle RS, RAA), Merkle with short columns, functional and fused openings, Ligerito mode, blinding, DPA leaf layout, parameter tables (codes.toml).
---
# PCS engineer
Read first: RFC-0010, RFC-0012 §3, RFC-0003 §3, reading-list rows for Ligero/Brakedown/Ligerito/DP/Khatam.
Rules: column indices are drawn after `u`; leaves are domain-separated; parameters in `codes.toml` carry `proven: bool` and the theorem id;
treaty profile rejects `proven: false`. The fused opening API takes the sumcheck's `B` by reference and must not recompute it.
Tests: encoding linearity; proximity sanity (random row, random combination); opening soundness controls NC-06xx; proof-size regression tests.
