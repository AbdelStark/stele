# Range capacity for full RMSNorm rows (Q26 / Q31)

Status: research under Draft RFC-0004 A3 and RFC-0008 A2. The required
RFC-0021 §2.3 norm domain includes d=16384. The current wide-range row cap
restricts the consumed xy relation to1024 and signed sources to2048.

Question before implementation: can the shared range adapter admit more narrow
words while preserving its existing maximum byte work and characteristic bound,
then consume one full16384-element xy row? Cost terms are c_a/c_lu/c_sc/T_misc.
Kill criterion: an admitted shape exceeds the existing131072 word-byte cells,
lookup dimension18 or262144 selected bytes; an old proof digest changes; a
large false source/cap/carry/padded value survives; or full maximum proofs lack
actual original/range/column consumers. No performance result is claimed.

Replace the uniform4096-word ceiling with len(caps)<=65536 and padded N*B<=131072,
where N and B are derived from expected count and cap widths. Check the count
before iterating caps and the cell bound before reading any proof/witness.
B remains a power of two in1..32. Thus2BN<=262144<p and m=a+b+1<=18, exactly
the existing maximum lookup domain. The wider count is not permission for
65536 independent160-bit words. Old accepted shapes, encodings, transcripts,
proofs and accounts must remain identical. No supplied resource parameter exists.

The unchanged conditional range argument still supplies bytes, Boolean carries,
cap addition, initial zero and terminal zero. A3 loss is9a+7b and each label
has4a+3b draws. The exact lookup identity/reduction stays parameterized by m;
its repetitions are unchanged. Metadata may have more cap records, bounded by
65536*20 bytes. The terminal A3 view can also grow from4096 to65536 entries.
Charge these increases in T_misc/c_sc; the word-byte cap does not bound them
to their old maxima.

Raise signed-source count to16384, covering every supported8/16/32-bit width.
Its raw/magnitude and combined sign/high7 ranges all fit the cell bound. Remove
xy's obsolete4N<=4096 gate; derive every child under the shared resource checks.
The norm schema already rejects d>16384. Other adapters retain their explicit
capacity guards, including statistic/limb-source and nonlinear/row consumers.
This change does not claim that those remaining consumers now support full rows.

Tests first: exhaust supported plane widths and count boundaries, including
power-of-two padding jumps, with malformed payloads rejected after metadata.
Compare independent maximum-shape byte/column arithmetic; run complete large
range, signed-int32 and16384-element xy proofs with exact accounts and original
consumer attacks. Rerun the affected existing range/signed/xy matrices and
controls to retain their frozen digests. Native/private/model/fidelity and the
rest of the norm output chain remain required. Full proofs must complete before
this capacity change can be published.

Recommendation: continue Q26/Q31 with the full-row consumed product. The fixed
maximum lookup domain is preserved; native stacking and physical source
ownership remain separate. Original task status and acceptance criteria remain.


## Current evidence

The tests-first shape run failed at the original4096-row Capacity guard.
After adding the separate padded byte-cell bound, all18 geometry/witness cases
passed across byte-plane counts1,2,4,8,16,32 and count/padding boundaries.
All source/complement byte arithmetic and terminal carries matched independent
integer encoding; oversized metadata rejected before missing payload access.
Frozen shape SHA-256:
`4151eb7c6dee3a07237457f1b324255930df6baacff7829b78efd7d4374a03f5`.

Reproduce with `uv run --locked --script research/cqis-bounds/check_range_capacity.py`.
The affected legacy regressions passed in full, including their controls and
the xy composition and boundary checks. The old proof hashes are unchanged:

- Wide range,20 proofs:
  `5899ef889669e2af476aaf025b21f8fa46fbda65121a5b8ab45b665f2b9c3eba`.
- Signed source,24 proofs:
  `1f13dcf0ecc3e56a4ecd7331f871a96f1cf3bde92d14840c2aac5076549e1bb2`.
- Norm xy,16 proofs:
  `4c3206c708d544df3e02f6b6a38e20680ad829263a6b5ff75eb0131ed7b46048`.

All required local repository gates passed. The full wide-range, signed32 and
16384-element xy proofs remain running. CI runs geometry in gates and the three
full proofs in separate mandatory matrix jobs; every mode retains its full
verifier. Final maximum-proof evidence remains pending. No maximum proof
success, independent audit or native/private inference is claimed yet.
