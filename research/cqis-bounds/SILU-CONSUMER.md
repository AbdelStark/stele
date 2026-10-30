# Consumed SiLU membership — Q26 / Q31

Status: preimplementation research using RFC-0021 §§2.2–4 and RFC-0008 A4,
under Draft RFC-0004 A3/A8 and RFC-0008 A2. Original tasks remain blocked/open;
no production cut, private proof, native control credit or independent audit.

Question: can the complete configured SiLU table consume actual signed input
and output sources, then feed its verified output root into gated multiplication?
Security properties: function/representation authority, full-table validity,
signed-byte association, selector and every original lookup claim. Cost terms:
c_a/c_lu/c_sc/T_misc including all65536 table rows and their fraction tree.
Kill criterion: an altered table, partial table, swapped source, inactive final
or modular alias passes; only queried rows determine table admission; or the
research adapter is presented as a private/native source consumer.

Expected metadata selects Function(silu_q,1,bytes[F,E]) with direct mode0 and
empty representation parameters. F0..30, E0..14. Count1..2048 is this adapter's
signed-source capacity; original model dimensions remain unchanged. External
raw16 input/output ids are distinct u64>=2 outside the parent's reserved span.
No supplied table, table digest, function id or representation authorizes itself.
Regenerate the complete canonical component from the expected descriptor; lift
each signed integer as v mod p. Preserve all65536 input/output pairs and their
canonical input order. Immutable definition caches are not proof authority.

Static totality lemma, to check before implementation: E<=F guarantees output
int16 representability for every input. Positive scaled values are<32767 and
negative magnitudes<16384 (zero exact). If E>F, then F<=13 and t=32767 gives
x>1, exp(x)>2 and scaled output>2*32767*(2/3)>32767.5, so the whole table
overflows. This permits early rejection, not early acceptance: the full canonical
generator and its precision schedule still run for E<=F. In particular, t=0
cannot admit an otherwise overflowing table.

Consume two actual signed16 proofs. From their verified raw byte planes and
sign bits derive lookup columns (lo+256*hi-65536*sign) mod p; no supplied field
view replaces them. Both original raw sources remain independently expected.
The existing full lookup verifies those two exact derived columns and its
committed multiplicities against the complete expected table. The selector is
one on real rows, zero on padding; actual signed-source padding is canonical0.
Original claims remain consumed even when their factor/selector is zero.

Use existing ordinary bounded-count lookup with m=b=a=log2(N), N padded rows,
two tuple columns and r1/2 independent repetitions. No Unit draws. Multiplicity
roots precede every beta/alpha; all fraction/leaf Finals and original consumers
remain. The wrapper adds no challenge or parent A3: exact full-byte/field-view
joins add no algebraic loss conditional on binding. A final transcript seed
binds expected function/representation bytes, six roots and three verified child
states. Canonical-u32 byte-slot roots are not physical packed roots or new cuts.

Account: two signed sources contribute A3 numerator86a+70 and36a+28 draws of
each A3 label. Keep six range lookup identities at dimension a+2, each
[(2^(a+2)+255)/|K|]^r and r[F(a+2)+F(8)+3(a+2)]/|K|, F(m)=3m(m-1)/2+2m.
Functional tuple membership contributes[(2^a+131071)/|K|]^r and
r[F(a)+F(16)+3a]/|K|, F(16)=392. Do not use the one-column table numerator
or square any reduction. Functional gamma/fold draws each r(a+16), Sumcheck
draws r[a(a-1)/2+120+a], beta/alpha each r. Preserve binding, FS/H, model
ownership and private composition losses separately; no profile is admitted.

Namespace: identity<2^44, base=2^63+2^18*identity. Magnitudes base+1/+2,
lookup columns base+3/+4, multiplicities base+5/+6; signed ids512*identity+1/+2,
functional lookup id4096*identity+65. Context prefix
stele/research/q26/silu-consumer/v1 plus NUL then version/field/repetitions,
identity/input/output u64 ids, count u32 and complete function/representation
encodings. Metadata/capacity checks precede payloads or table generation.

Tests first: exhaustive signed16 lift against independent byte decoding, whole
table overflow before a zero query, complete F0/E0 ReLU and F30/E14 zero-table
oracles, varied fractional parameters and integer gathers. Full65536-row proofs
cover both fields/repetition counts, ragged endpoints, zero and negative values;
never replace the table by a smaller test table. Check exact accounts/events,
actual source/multiplicity joins, malformed metadata/shapes/fields and padding.
At a zero query, changing leaf claims by (+beta,-1) preserves tuple compression;
the actual original consumer must still reject. Include a genuinely produced
proof under a one-entry-corrupted table and verify it under the expected table.
Compose a genuine SiLU output root into the gated consumer and reject a valid
product proof using a substituted factor. Native/private/model ownership and
original larger-shape criteria remain independent obligations.
