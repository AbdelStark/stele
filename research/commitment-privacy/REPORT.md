# Q29 — Complete commitment privacy and mask lifetime

Question: which joint algebraic view hides original sources under the actual
code, extension field and passport lifecycle? Kill criterion: distinguish views
beyond their allowed public outputs or silently reset a fixed oracle's privacy
budget. Cost terms: randomization, encoding, queries, row messages, state,
registration and per-proof source work. Run
`python3 research/commitment-privacy/check_privacy.py` (standard library).

The [formal derivation](../../formal/commitment-privacy.md) proves an exact
linear-view condition: im(A) is contained in im(B) for view A*x+B*r with uniform
field mask r. For allowed public linear outputs, restrict secret differences
to their kernel. The checker compares ranks with complete distributions in
8,346 F_3 matrix cases, including 7,488 conditioned-public-output cases.
Joint mask disclosures are included; uniform marginals alone do not suffice.

The literal appended-row mechanism leaves every original entry of a queried
column visible. Across 378 coordinates of the independent Python Circle map,
constant-zero and constant-one source rows are distinguished regardless of the
extra row. Shared additive pads reveal row differences. These are privacy
diagnostics, not a hash collision, a forgery or two witnesses for a fixed root.

A full F_9 distribution check exposes the base-field mask/extension-field shift
gap and zero-coefficient case. Two reused masked messages reveal each original
secret in 49 secret/mask cases although their illustrative digests differ.
Independent masks repair that limited linear example. Exact four-column/eight-draw
coverage counts match inclusion-exclusion (40,824 sequences) and the general
fixed-oracle lifetime union bound; fresh query draws do not refresh hidden data.
Masking also changes dot(u,b). In 600 masked cases the unchanged original-value
check accepts only 120 zero-correction cases; binding the shifted value back to
the original claim is a missing completeness/source obligation, not an optional
privacy improvement. Any revealed correction belongs in the joint view.

The ordinary randomized-polynomial example has 735 complete-distribution
comparisons across every two-element F_7 message and every one/two-query subset
of its disjoint query domain. Its original message evaluations remain exact.
Querying message positions or exceeding the retained mask's one-query budget
in the smaller example leaks. A distance-two code example shows why distance
does not establish privacy rank. This supplies no Circle/expander mask theorem.

The note checks the actual Ligero and Jolt documentation boundaries. No external
protocol is imported into core or treated as an instantiated Stele simulator.
All source/claim consumers, adaptive composition, FS, hash paths, seed lifecycle,
secret-field choices, canonical formats and native cost/privacy evidence remain
required. No measured constant, native performance result, admitted profile or
NC-0604/0900/0901 credit follows from the study.

Recommendation: replace the incomplete blinding claim through Draft RFC-0013 A1,
RFC-0010 A7 and RFC-0011 A1; keep E4-05/E12-01 blocked until the complete protocol
and simulator are accepted. Preserve the one-pass and <=5% overhead criteria.
