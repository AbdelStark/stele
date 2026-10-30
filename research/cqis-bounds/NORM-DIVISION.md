# RMSNorm output division and strict remainder (Q26 / Q31)

Revealing research under Draft RFC-0004 A3 for RFC-0022 §§2.1,2.3,5.
The question is whether complete quotient-product and biased-sum consumers
can share their actual bytes with qd+r=U and r+gap+1=B over16384 rows,
without enlarging a lookup or replacing a child with a supplied receipt.
Costs are c_a/c_sc/c_lu/T_misc. Kill this design if independent source
substitution passes, equality alone admits r>=B, a padded row receives the
scalar B or one, or any original child/parent claim loses its consumer.

Retain complete quotient-product and biased-sum proofs. Their expected roots
bind q/B/qd and t/h/U respectively; seven external ids also include r.
No quotient/result/factor source is selected by a supplied flag. Authentication
of configured B/h from one verified factor bundle remains a separate join,
as do t's product source, the signed q source and selected output branch.

Range r and gap independently in[0,Bmax-1]. Since Bmax is a power of two,
low cap min(Bmax-1,2^64-1) and optional high cap floor((Bmax-1)/2^64)
give the exact whole bound. Unlike power-of-two product bounds, these split
caps cannot admit an extra low part at the maximum high part. Each actual
verified part is zero-extended to eight byte planes, yielding16 planes total.
The external remainder root uses those actual bytes.

Use two degree-one A3 relations over16N entries. Equality has five original
views qd,r,Cin,U,Cout. Strict remainder has r,gap,Cin,masked_B,Cout, where
Cin's first byte is one on real rows and zero on padding. Thus its equation
is r+gap+1=B. Both instances consume all original views independently at
their emitted points. Scalar B is read from the complete verified positive
divisor child and masked by the expected real-row count. No supplied mask
or certificate is accepted. All roots and verified child states precede
parent weights, rounds and finals.

For equality, retain the closed division-role carry caps and append zero
planes through C16. Actual qd<=32768*Bmax and r<=Bmax-1 justify those caps.
For strict remainder, derive cap0=1 and
cap(k+1)=floor((2*min(255,(Bmax-1)>>(8k))+capk)/256) for16 columns.
All later caps are Boolean, with cap16=0. Partition each relation's C1..C16
into four families of four N-element planes. Range only families with a
nonzero static cap, retaining zero caps on padded rows and endpoints.
Unused family ids remain reserved. Each family fits65536 bytes.

The local integer-lifting certificate uses actual byte bounds<=255 and
Boolean carries, so each side is<=511<p/2. At the strict relation's first
column, Cin=1 replaces the usual zero; it is not an extra summand above511.
This local bound does not assert tighter closed-role last-digit caps for U.
Faithful equality itself implies U=qd+r<=2*(32768*Bmax). Strict remainder
then gives0<=r<B, and positive B plus equality uniquely determines q.
No whole multiplication, sum or division is recomputed by the verifier to
grant acceptance. Padded rows and all high/terminal zeros remain consumed.

Namespace: identity<2^40, base=2^63+2^22*identity. Quotient-product and bias
child identities are16*identity+1 and16*identity+2. Parent range ids reserve
65536*identity+1..12 for r-low/high, gap-low/high, four equality carries and
four strict carries; sources use base+1..12. Parent A3 ids are
262144*identity+65536 and the next id; original views use base+32..41.
Seven distinct external ids stay outside the whole parent span. Every child
A3 id precedes the two parent instances; source namespaces are disjoint.

Account before implementation: inherit both complete child accounts. Let
bl/bh be low/high remainder byte-width exponents, H indicate the high part,
and g count all active equality/strict carry families. Additional A3 numerator
is(22+18H+9g)*a+14*(bl+H*bh)+18g+16. Each additional nonlookup label has
(10+8H+4g)*a+6*(bl+H*bh)+8g+8 draws. Additional lookup dimensions are
a+bl+1 twice, optional a+bh+1 twice, and g copies of a+3. Each retains
its separate identity((2^m+255)/|K|)^r and reduction
r*[F(m)+F(8)+3m]/|K|, F(m)=3m(m-1)/2+2m.
At full a14, bl3/bh2, H1/g7: additional A3=1654 and draws738 per label;
including both children, A3=3690 and draws1636 per label across26 lookup
units. These are static counts, not performance measurements. Runtime
receipts must agree for both fields and repetition counts.

Tests first:10000 NumPy byte additions with exact wide division as an
independent witness oracle; zero quotients, B=1, r=0, r=B-1, ragged rows,
wide halves and all metadata transitions. Forge valid range proofs with
r=B and equality intact, invalid gaps, carries and original finals. Retain
source substitution, zero-hidden child controls, both endpoints, canonical
shape checks and actual factor composition. Require a full16384-row proof
before publication. Continue Q26/Q31; selected left/right branches, signed
output, native/model/private inference, fidelity and original task criteria
remain open. No new Accepted cut, control credit or benchmark is claimed.

The tests-first run rejected the missing module. Seed2720 then passed10000
cases and13534880 independent NumPy byte-column cells. Frozen corpus hash:
`3edca88f2b7d996e38f91dddb1bcfc89ea62883d549c23c3ec41795e68e1f291`.
Full geometry and namespace checks passed. All core adversarial and boundary
controls passed, including r=B with equality intact. All75 split-bound
transitions passed, and an r+p/gap-p forgery preserving strict remainder
rejected at equality. Actual B/h from one verified factor source composed;
a valid divisor substitution rejected even at zero quotient. The16-proof
matrix is running, with initial exact accounting checks passed.
The full maximum is running. All required local repository gates passed,
including fmt/clippy/workspace tests, no_std CQIS, digest, negative controls
and soundness accounting. Hosted CI remains pending.
These results do not grant native or private inference admission. Reproduce
the separate alias/transition controls with `--aliases` in addition to the
normal corpus/control/boundary/composition/honest modes.
