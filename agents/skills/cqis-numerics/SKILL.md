---
name: cqis-numerics
description: Define, implement and validate CQIS numerics — quantiser, tables, bound certificates, bit-exact reference forward pass, fidelity evaluation, architecture variants.
---
# CQIS numerics
Read first: RFC-0004, RFC-0017, RFC-0003 §4.
Rules: every op is defined as integers with explicit rounding; tables generated from closed forms with a stated error analysis;
reference forward pass in NumPy int64 (never float) and in Rust; both agree bit-exactly on 10⁴ random inputs per op.
Bound certificates are emitted by the quantiser and checked in tests against random shapes (property tests).
Fidelity: run the RFC-0004 §8 protocol; publish paired standard errors; any knob change is an ADR.
