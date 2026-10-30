# Exact wide-word ranges — Q26 / Q31

Status: research for Draft RFC-0004 A3, RFC-0008 A2 and RFC-0012 A8;
reuse Accepted RFC-0006 A3 and RFC-0021 range_8. E5-03 remains blocked
with its original criteria. Full reveals are not private PCS/ZK or an admitted
inference commitment format.

Question: can an exact unsigned cap below 2^160 be enforced on an original
byte-word source through real lookup and consumed zerocheck claims? Coordinate
caps are insufficient: cap 257 gives byte caps (255,1), which also permit 511.
The security properties are original-source equality, byte membership, bounded
column addition and zero carry endpoints. Cost terms are c_a/c_lu/T_misc;
there is no proposed measured constant or inference weight-pass change.

Kill criterion, stated before implementation: stop if a cap violation, different
original source, nonbit carry, nonzero final carry or nonbyte can pass; if any
claim lacks an actual consumer; or if the complete draw/phase accounting differs
from the descriptors. Do not use a verifier plaintext whole-word range scan.

Candidate: verifier-owned caps determine a power-of-two byte-plane count B<=32
and padded row count N<=4096. An expected source root binds B*N canonical M31
entries, interpreted as byte planes only after equality to the range-proven
lookup source. The lookup covers both the word and its nonnegative complement,
2*B*N selected bytes, strictly fewer than p. Four k=0 A3 relations enforce
SourceCopy, byte-column addition to the cap, carry Booleanity and zero final
carry. Initial carry is the zero public view. All padded rows have cap zero;
all high byte planes remain checked. No whole-word integer is embedded in F_p.

Each column's nonnegative sides are at most 511 after byte/bit enforcement,
so 2*511<p gives integer faithfulness. Telescoping the column equalities with
zero endpoints yields W+S=cap over integers and hence W<=cap. Every A3 claim
uses the actual opened source or exact public/virtual view. The research roots
reveal originals, lookup bytes, carries and multiplicities; they add no production
cut. Connecting that byte-word source to the real numerical operand, signed
representations, nibble packing, multiplication relations and joint privacy remain
separate mandatory obligations.

Let a=log2(N), b=log2(B), m=a+b+1. Lookup uses one ordinary characteristic-safe
unit with its existing identity term (2*B*N+255)/|K| raised to r and separate
reduction r*[F(m)+F(8)+3m]/|K|, F(n)=3n(n-1)/2+2n. The four A3 relations
have (dimension,degree) (a+b,1),(a+b,1),(a+b,2),(a,1), adding
(9a+7b)/|K|, not squared. They draw 4a+3b weights and 4a+3b tails, with
no skip draw. Nine A3 claims and 2r lookup claims must be consumed.
Binding, FS/H, private source composition and joint ZK remain additional.
