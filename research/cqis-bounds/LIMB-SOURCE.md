# Limb input source consumers — Q26 / Q31

Status: research for Draft RFC-0004 A3, RFC-0008 A2 and RFC-0012 A8; reuse
Accepted RFC-0006 A3 and RFC-0021 range_8. E5-03 retains its blocked status
and original acceptance criteria. Revealing roots are not production cuts.

Question: can the exact whole-input ranges required by the existing limb
arithmetic be proven against its actual byte/nibble operand vectors, without
the verifier's plaintext inputs/SourceDigits checks? A wide-word proof alone
does not connect those operands to its byte-word source. The security properties
are original-source equality, canonical digit ranges, exact packing and whole
input maxima. Symbolic costs are c_a/c_lu/T_misc; no measured constant or
inference weight-pass change is proposed.

Kill criterion, stated before implementation: stop if a different original
operand, a noncanonical nibble, a wrong high plane/padded row or a whole-word
cap violation can pass; if any claim lacks its actual consumer; or if complete
draw/phase accounting differs from descriptors. Do not replace lookup, packing
or the exact whole-word comparator with a verifier plaintext range scan.

Candidate: expected limbs.Spec determines count, left/right maxima and radix
4 or 8. Let N=nextpow2(count), a=log2(N), and B=2^b be the wide comparator's
byte-plane count. The 2N word rows are left inputs/padding then right inputs/
padding. Their exact caps are the respective maxima or zero for padded rows.
The original operand vector has B planes for bytes and 2B for nibbles, in
least-significant-first plane order across those same rows. A separate A3
relation consumes byte equality or byte=low+16*high against the actual original
root and the bound whole-word source. Nibbles additionally use the actual wide
consumer with one byte plane and cap15 on every original digit; byte equality
inherits byte membership directly. No range_4 table is invented.

All expected capacities precede witness work: whole rows <=4096, and nibble
cells <=4096 for the current comparator. No silent truncation or partitioning.
The source adapter maps exact existing left/right digit tuples into this layout;
result/carry/multiplication relations remain separate. Full reveals and actual
point evaluation close research claims, not model/private PCS/ZK obligations.

Whole-word A3 contributes 9(a+1)+7b; packing has dimension a+1+b, degree1,
and contributes 2(a+1+b). A nibble proof adds 9(a+b+2), with its own complete
Q31 lookup terms. Thus A3 totals are 11a+11+9b for bytes or 20a+18b+29 for
nibbles. Keep each lookup identity term and reduction term separately; do not
square any A3 error. Source/word roots and all completed nested states precede
packing challenges. Hash binding, FS/H and joint private composition remain open.
