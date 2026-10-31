# Signed attention normalization output (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can the actual
rounded magnitude q and canonical input sign b bind the int16 output across
all 16384 channels, including negative inputs rounded to zero? Costs are
c_a/c_sc/c_lu/T_misc. Kill the design if a wrong output sign, positive 32768,
source substitution, missing original or noncanonical signed representation
is accepted, or the supported domain is narrowed.

Reuse the complete signed_source consumer at bits=16. Its raw two-byte root
is Y and its magnitude two-byte root is the actual q root. A complete wide
range proves the input sign flags are Boolean and fixes their N-byte root.
One degree-two A3 over N entries consumes three actual originals: q rebuilt
from both verified magnitude byte planes, b and the canonical output sign s.
The relation q*b=q*s has independent sides at most 32768<p/2. Signed-source
relations already establish |Y|=q and canonical int16 raw bytes.

Thus nonzero Y has the input sign; q=0 permits b=1 while signed_source fixes
Y=0 and s=0. The signed consumer admits -32768 but cannot label its magnitude
positive. Keep every child and original consumer at zero. No plaintext
verifier multiplication, absolute value or sign choice grants acceptance.

The standalone Boolean source is conditional. Canonical raw-sum or block-
total sign proofs must supply the same b and magnitude M; attention_numerator
must map that M to the U consumed by strict division, whose q root is reused
here. Test this complete chain for both accumulation modes, including a
negative input rounded to zero. Upstream weighted/global source ownership,
full normalization composition and configured output conversion remain open.

Full expected normalization schema, role ids, field/repetition bytes, three
external roots and both verified child states precede the parent. Identity
<2^48 reserves base=2^63+2^14*identity. The Boolean range id is
256*identity+1, with its internal span at base+64 and external b source.
The signed-source id is 32*identity+1, occupying base+512 through base+1024;
its wide ranges use ids 256*identity+9..11. Parent originals are base+16..18,
and parent A3 id is 1024*identity+128. All external roles are distinct and
outside the full reserved span. Check every nested limit and ragged padding.

Let a=log2(N). Independent lookup dimensions are a+1 for b and three copies
of a+2 for signed_source. Each identity is ((2^m+255)/|K|)^r, with unsquared
reduction r*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m. Full range/A3 numerator
is 55a+35, including parent3a and signed-source43a+35. Parent draws a per
ZeroWeight/Sumcheck label; full nonlookup draws are 23a+14 per label. No A1
or new label. All sixteen signed-source originals and inherited range/lookup
claims remain mandatory. Binding/FS/H and complete provenance proofs are
additional; confirm exact runtime receipts before admission.

Tests first: 10000 independent NumPy signed int16 outputs and byte roots,
all endpoints and negative-input zero, plus capacity cases at 8193/16384.
Reject positive 32768 and q=32769 through actual complete proof paths. Attack
every root, Boolean and magnitude caps, padding, high byte planes, metadata,
fresh valid source substitutions and all three compensated or zero-hidden
original claims. Both fields/repetitions must match exact receipts; require
a complete 16384-channel proof and all repository gates. Queue the full proof
behind strict division's two full cases without restarting live work.

Continue Q26/Q31. Exact global offset/base aggregation must preserve eight-
byte global Z; the earlier four-byte local base alone does not establish it.
Full key/block/model ownership, global attainment, native/private inference,
PCS/ZK/FS, GPU parity/scale, fidelity and independent audit remain required.
No benchmark, new cut, capacity increase or extra weight pass is claimed.
Draft amendments remain unaccepted; original task criteria remain unchanged.
