# Capped scalar range consumers — Q26 / Q31

Status: research for Draft RFC-0004 A3, RFC-0008 A2 and RFC-0012 A8,
reusing Accepted RFC-0006 A3 zerocheck and RFC-0021 range_8 semantics.
E5-03 remains blocked with its original criteria. This is a revealing research
adapter, not private PCS/ZK, native plan admission or an inference proof.

Question: can exact static caps on canonical M31 source values be enforced by
actual byte lookups and consumed zerocheck claims, instead of a plaintext range
comparison? Security properties are original-source reconstruction, nonnegative
bounded complement, carry Booleanity and final carry. Costs are c_a/c_lu/T_misc;
no performance measurement or inference weight-pass change is proposed.

Kill criterion, stated before implementation: drop the construction if a range
claim can be discharged against different source bytes, an x+p decomposition
can pass, nonboolean carries or a nonzero terminal carry can evade rejection,
any generated claim remains unconsumed, or the actual challenge accounting differs
from its descriptors. Do not replace the existing lookup protocol with a verifier
membership scan. Retain all Q31 pole, multiplicity, table and source consumers.

The candidate uses per-row verifier-owned caps in [0,p-1], a canonical M31 source
vector and four little-endian byte planes each for the source and its complement.
One range_8 lookup covers all eight planes. Four no-skip zerochecks enforce source
reconstruction, byte-column addition to the static cap, carry Booleanity and zero
terminal carry. Padding rows have expected cap zero and are subject to every check.
The byte-column sides are at most 511 once bytes and carries are enforced, so
field equality is integer equality. The terminal condition gives word+slack=cap;
cap<p then excludes x+p aliases in source reconstruction.

The existing revealing Merkle lookup adapter binds original byte and multiplicity
vectors. A separate fixed source root and carry root close the zerocheck views
by full-vector openings and exact MLE evaluation. These research commitments do
not add a production cut or choose an admitted intermediate commitment format.
Private/virtual source consumers and joint masking remain mandatory.

For a row dimension a, the lookup has m=a+3, b=3, one column and 256 table rows.
Its existing identity and reduction losses remain unchanged. The four zerochecks
have (dimension,degree) (a,1),(a+2,1),(a+2,2),(a,1), totaling (9a+10)/|K|.
They add 4a+4 ZeroWeight and 4a+4 Sumcheck draws, with no skip draw. Bind the
expected statement, all relevant roots and the completed lookup state before the
zerocheck transcript. This is conditional interactive accounting; hash binding,
FS/H, profile admission and private source composition remain unresolved.
