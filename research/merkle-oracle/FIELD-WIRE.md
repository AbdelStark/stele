# Conditional field certificate and opening bytes

Question Q27: can the proposed native contract produce deterministic bytes
that an independent verifier consumes, including every original RFC-0006 A1
claim? The security property is consistency with the expected certified source.
Reject this candidate if source substitution, stale queries, noncanonical
authenticated fields or an ignored original can pass its actual consumer.

The Python oracle implements Draft RFC-0010 A9 source, certificate and opening
frames using the existing independent Circle, extension-field, Merkle and
RFC-0006 A1 references. Its transcript frame agrees with the existing byte
oracle; the new PCS labels are checked by operation kind. This is research
code. Python handle conventions do not prove Rust type opacity, and these
checks supply no native control or profile coverage.

Run `uv run --locked --script research/merkle-oracle/check_field_wire.py`.
The checked fixture contains six complete cases across QM31 and OM31, with
R=1/C=1 and both code rates represented. Every certificate uses the full fixed
query count. Repeated indices retain their complete responses in draw order.
The 333934 fixture bytes have SHA-256
`4e5327828a8fe47f4b44537278f550e6231da0415022474110b56d6113a8b7ed`.
This is a deterministic corpus size and digest, not a benchmark result.

Controls reject malformed proof lengths/versions, changed expected context,
changed paths, noncanonical row elements, authenticated noncanonical leaves,
incorrect encoded rows and exchanged responses. Transcript continuation states
match after full verification. A forced research candidate stream exhausts
the exact 64-attempt loop; it is not a native randomness-injection API.

For the unused-original control, the reference sumcheck accepts a changed
unused final value. The test regenerates the preceding used-source opening
under that changed transcript, then the unused source rejects ValueMismatch.
The first test version rejected at a stale path before reaching that source;
the corrected version isolates the terminal binding. Both challenge fields
exercise this control and source-roster reordering.

The tests-first run failed at the missing field_wire module. Continue with
the scoped RFC acceptance review and native verification of these same bytes.
Native parity, checked allocation, production accounting, zero knowledge,
packed model ownership, fused B and Q12 remain unfulfilled.
