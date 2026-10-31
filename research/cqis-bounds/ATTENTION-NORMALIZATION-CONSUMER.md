# Complete conditional attention normalization (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can one verifier
compose the complete normalization proofs while forcing every shared source
to use the same expected root? Costs are c_a/c_sc/c_lu/T_misc. Kill the design
if any missing child, altered shared source, metadata replay or signed endpoint
violation is accepted, including substitutions that preserve a zero output.

Use the full expected attention_normalization_bounds.Spec. Exact accumulation
requires six children: global base H=S*Z, canonical raw sign from O-H, scaled
numerator U, positive denominator D, strict division and signed int16 output.
Block accumulation requires the last five children, using canonical total sign
from O-G instead of raw sign; it has no H child or H root. Expected metadata
chooses the mode. Block sign derives all absolute block ids from the configured
length, including the final short block. That metadata alone does not prove
ownership of actual blocks or keys.

Exact expected root roles are O,H,Z,M,b,U,D,q,Qp,W,D2,R,Y. Block mode omits H
entirely and requires a canonical zero base-role sentinel in the expected Spec.
Every other role is distinct and outside the parent's reserved namespace.
No extra H payload or ignored branch is permitted in block mode. External
layouts are O8N, H8, Z8, M8N, bN, U16N, D16, q2N, Qp16N, W16N, D2_16,
R16N and Y2N, where N is the padded channel count and scalar layouts are
listed without N. Every child verifies its complete proof independently.

Route the same expected Z to global base and positive denominator; the same H
to global base and raw sign; M to canonical sign and numerator; b to canonical
sign and signed output; U to numerator and division; D to positive denominator
and division; q to division and signed output. Strict division retains its
own Qp/W/D2/R bindings and all ten originals. The producer's root assembler
must reject conflicting shared roots, but verifier admission must not rely
on that assembler or a supplied receipt. A valid child with another source
must reject even when its final output happens to match.

Reserve identity<2^32 with base=2^63+2^30*identity. Canonical sign, numerator
and signed output use identities 65536*identity+1,+2,+3, each with span 2^14.
Positive denominator and exact global base use 4096*identity+1,+2, each with
span 2^18. Strict division uses 64*identity+1 with span 2^24. These proposed
namespaces must be checked at the maximum parent identity, including every
nested child and scalar reduction id, before implementation.

No wrapper challenge, identity loss or reduction is added. The final context
state binds full schema/role bytes, ordered expected roots and every verified
child state. Add all child lookup identities, unsquared lookup reductions and
range/A3 numerators unchanged. Keep each polynomial identity numerator
separate: two from positive denominator, one from division's doubled
denominator and one from exact global base. Block mode has three. Sum their
A1 reductions without adding a wrapper A1. Assert each complete child receipt
and the aggregate; wrapper draws must be empty. Binding/FS/H remain additional.

Tests first: 10000 independent integer normalization cases across both modes,
legal unit shifts, all probability exponents and value policies. Include ties,
negative inputs rounded to zero and int16 overflow rejection without clipping.
Check actual byte roots and ragged padding, plus full-width metadata/layouts.
Reject every altered expected root, missing/extra child, invalid block H role,
mode swap and separately valid replacement of each child, including zero-hidden
M/U/D/q/sign changes. Both fields/repetitions retain every original consumer.
Require complete 16384-channel exact and block proofs: the exact schema reaches
Dmax=2^64 with grouped ranges; the block case must include Y=-32768 with
q=32768 and canonical input sign. Positive 32768 must reject. Full proof
runners must wait for the existing signed-output full proof and global-base
validation; do not duplicate or restart those prerequisites.

The source statement remains conditional on expected O and Z. Exact weighted
offset aggregation and actual global probability ownership must still share
the same attention row, keys, mask and value sources. Block aggregation must
consume all actual rounded blocks. Global attainment, configured output-row
conversion, full model/checkpoint/context/cache/decode ownership, native/private
PCS/ZK/FS, GPU parity, fidelity and independent audit remain required. No new
cut, weight pass, benchmark or production coverage is claimed. Original task
criteria stay blocked and Draft amendments remain unaccepted.

The namespace design passed all child derivations at parent identity 2^32-1,
width 16384 and length 1048576 in both modes and challenge fields. Child
spans are disjoint and contained in the parent's reserved span; strict
division retains G=2 in the exact boundary and G=1 in the block boundary.
This check used the existing complete child implementations. Permanent
tests-first coverage and the composition implementation remain required.

Equivalent arithmetic metadata may permit valid child proof reuse. The
returned context state must change with expected schema/roles; a caller
must bind that state. Controls must reject replay as the original context,
without requiring rejection of a mathematically valid alternate statement.

The tests-first run rejected the missing module. The complete consumer is
implemented with no wrapper challenge or plaintext verifier division. Focused
context-encoding controls passed for each child state, expected schema and
role across both modes/fields/repetition counts. The independent corpus and
complete proof suites are running. Both full-width proofs and repository
gates are queued behind the existing prerequisite processes.
