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

## Exact statement, layout and execution

Spec contains an independently expected limbs.Spec, identity in [0,2^54),
source u64 >=2 and repetitions 1 or 2. The field degree is 4 or 8. Recompute
the existing static limb certificate, including its field-bound rejection.
Let rows=2N and planes=B for bytes or 2B for nibbles. The expected original
source commits rows*planes canonical M31 entries, plane-major with the low
digit plane first. Each plane contains count left digits, N-count zero rows,
count right digits and N-count zero rows. Source construction accepts exact
existing left/right tuple shapes and zero-extends missing high digit planes.
The verifier does not assume those supplied digits have their intended ranges.

The expected wide-word caps are left_max repeated count times, zero repeated
N-count times, right_max repeated count times, and zero repeated N-count times.
Their byte-plane width B is derived solely from max(left_max,right_max), with
the existing power-of-two extension up to 32. Original byte operands inherit
range from equality to those proven bytes. Nibble operands additionally require
the existing wide consumer with cap15 and one byte plane on each of the 4BN
original digits. Its expected source root is the same original operand root.
Both consumers use actual range_8 lookups; there is no range_4 descriptor.

Reserve base=2^63+256*identity through base+255; the original source id must
be outside this span. The whole-word source tree has id base. Whole-word and
nibble range invocations have identities 4*identity+1 and 4*identity+2, with
their unchanged derived tree/view ids in base+64..127 and base+128..191.
The original/word source trees use kind0, width4 and canonical little-endian
u32 fields, with counts rows*planes and rows*B. These full reveals are research
bindings, not an inference commitment format. No additional root binds a view.

Verify the optional nibble proof first, then the whole-word proof. Their existing
verifiers authenticate all original/byte/carry/multiplicity roots and consume all
claims. Only then run packing invocation 16*identity+12 with dimension a+b+1,
degree1 and k=0. Byte mode has inputs (source,base) and polynomial source-word.
Nibble mode has inputs (base+8,base+9,base) and polynomial low+16*high-word.
Low/high are exact even/odd digit-plane views of the original root, consumed
at the actual returned point; they are not independently supplied tensors.
The word input is exactly the original vector accepted by the whole-word proof.

Before packing, the context is domain `stele/research/q26/limb-source/v1\0`,
u8 version=1, u8 field degree, u8 repetitions, u8 radix_bits, u64 identity,
u64 source, u32 count, 20-byte left_max and 20-byte right_max. Integers are
little-endian. Append the expected original root, word root, optional completed
nibble state and completed whole-word state, each 32 bytes. The expected radix
determines whether that optional state exists; no proof flag selects the mode.
All source and nested states precede packing weights; all finals are absorbed.
These are composed research transcripts, not an admitted native wire codec.

In byte mode, field equality between a canonical original and a proven byte
gives the same canonical integer. In nibble mode, the independent ranges give
low,high in [0,15], so low+16*high<=255; the word byte is also <=255. Both
sides have strict half-field bounds and field equality is integer equality.
Summing those byte identities with weights 256^j gives exactly the original
base16/base256 operand. The consumed whole-word proof therefore establishes
the correct left/right maximum. Zero whole-word caps and nonnegative canonical
digits also force every padded row and all excess high planes to zero.
No verifier plaintext reconstruction/comparison asserts these facts.

The whole bound also implies the exact coordinate caps used by the existing
limb certificate: nonnegative digit D_j satisfies D_j*radix^j<=word<=limit,
so D_j<=min(radix-1, floor(limit/radix^j)). Thus the actual original operands
meet those static caps, including zero high planes, without another plaintext
scan. This supplies an input premise of the multiplication-column argument;
the multiplication, output digits and carry identities still require consumers.

## Evidence and remaining work

Run `uv run --locked --script research/cqis-bounds/check_limb_source.py`.
The tests first failed because limb_source did not exist. Seed2669 checks
10000 expected schemas, byte/nibble layouts and exact integer reconstruction,
including 0..160-bit caps and ragged counts. Full proofs consume actual left/
right vectors from the existing limb witness generator in both challenge fields
and repetition counts. Separate controls alter original/word openings, finals,
whole caps, nibble ranges, padded rows and the highest planes. Malformed lengths,
noncanonical fields, id collisions and capacities reject before unsafe access.
The 4096-word byte and 4096-digit nibble boundaries are metadata/witness-layout
checks, not maximum-size proofs. Research controls receive no native NC credit.

The layout corpus contains 2904862 digit cells and has frozen checksum
`e1c7b7e67d8d95cc8d9997119f1f72a397cf1cfe834eeb71c4570ab20e141704`.
Twenty-four complete proofs cover byte/nibble modes, QM31/OM31, one/two
lookup repetitions, zero caps, ragged count3 with maxima257/31, and a 160-bit
left operand. Their complete final-state checksum is
`e74f376c32e0e05d07fb2338aff13a6ec2c4714a06bb0fd1f3ac6556de902620`.
Tests compare all composed loss terms, lookup and A3 draw counts, packing
phase records/claims and nested claim counts. The small packing proof objects
also equal the naive A3 oracle. Shared arithmetic/lookup engines are disclosed.

The packing proof adds one linear no-skip A3 relation and exact original/view
consumption to the complete nested range work. Its work is O(BN), with another
whole range proof on 4BN digits for nibble mode, plus table/multiplicity/hash/
transcript work. Full reveals duplicate originals across these consumers.
The maximum allocation is static and checked before witness payload inspection;
larger shapes need an explicit supported contract rather than truncation.
These are symbolic c_a/c_lu/T_misc costs, not a benchmark, RSS guarantee, fitted
constant, native full-model result or inference weight-pass change.

Continue Q26/Q31 with actual multiplication and result/carry consumers using
these same original operands. This study does not identify them with a signed
scalar, checkpoint tensor or numerical model node; those source relationships
remain mandatory. Complete plan/range dominance, native parity, fidelity and
private PCS/ZK/FS are still open. The existing plaintext limbs checker remains
an oracle, not a production verifier, and E5-03 retains all original criteria.
