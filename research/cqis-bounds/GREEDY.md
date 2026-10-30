# Q26: static first-maximum and greedy stopping bounds

Question: can signed int16 logits establish the selected first maximum with
closed static M31 relations, while explicitly checking prefix, generated EOS,
length and previous-position associations? INV-5 and decoding/source bindings
are at stake; the cost terms are T_misc/c_a/T_witness. Kill criteria: an accepted
nonmaximum or later tie, substituted selected source, incorrect stop/prefix/row
position, oracle mismatch or bound computed from observed logits.
Research under RFC-0004 §7 and Draft A3/A9; no proof consumer or NC-0107/0108 admission.

## Scope and fixed ranges

Spec fixes vocabulary V in 1..2^20, common logit fraction F in 0..30 and
position length L in 1..2^20. Parameters, positions and tokens are strictly typed;
bool is not an integer. A row has exactly V signed int16 logits, all in units
2^-F. There are no padding entries in this domain. The expected source position
is in [0,L-1], and the separately expected selected token t is in [0,V-1].
The fraction cancels from comparisons but remains part of the record identity.

The row witness has position, selected token, signed int16 maximum M and V
entries, each containing nonnegative difference delta and gap g in [0,65535].
Neither t nor position is accepted solely because it appears in the witness.
Enforce the following field equations after all whole-value ranges:

- M=logits[t], establishing attainment from the separately expected source;
- delta_j=M-logits[j] for every real vocabulary entry;
- delta_j=g_j+[j<t].

The prefix bit is derived from the actual canonical index and expected selected
token, never supplied as a free witness. Every earlier index must have strictly
smaller logit; later indices may tie. The selected entry has zero self difference.
Thus §7's tie restriction concerns competing entries: j<t is strict, j=t is
the attained entry, and j>t permits equality. This states the intended first
maximum explicitly without changing Accepted text in place.

Both sides of attainment have magnitude at most 32768. A signed logit difference
has magnitude at most 65535, while delta is in [0,65535]. The final right side
g+[j<t] is at most 65536. All sides have strict p/2 bounds for p=2147483647,
so every modular equality implies its integer equality. No limb decomposition,
inverse, runtime-selected bound, random challenge or new probabilistic loss is
needed. The source selection and whole ranges still need actual proof consumers;
plaintext indexing/comparisons are not a succinct proof of them.

## Generation boundary

The generation checker takes an expected nonempty prompt, maximum_new, EOS,
returned sequence and stop reason, along with exactly one logit row/witness per
generated token. It checks these public boundary conditions before row relations:

- maximum_new is in [0,L-prompt_length]; every token, including EOS, is in [0,V);
- the returned sequence begins with the exact prompt and adds 0..maximum_new tokens;
- a generated EOS may appear only at the end, and then the stop reason is eos;
- without generated EOS, the stop reason is limit and exactly maximum_new tokens
  were added;
- the i-th generated token is checked against row position prompt_length-1+i.

Prompt EOS does not itself stop generation. At maximum_new=0 the result is the
prompt with limit reason and no decision rows. A generated EOS takes priority
even on the configured final new token. The helper allows at most 2^22 decision
logit entries, matching the existing research model's materialized capacity;
it checks that cap before constructing relation witnesses. This is a research
resource limit, not a newly admitted inference-plan capacity.

These checks do not authenticate a row's model or position ownership. Reordering
rows with different selected tokens rejects; replacing rows with different
values but the same first maxima can satisfy the conditional arithmetic contract.
A positive control demonstrates this limit. Actual row claims must come from
the committed model's LM head at the named preceding position. Nor does this
checker establish full evaluation of the returned EOS token or cache parity;
those are separate numerical/model and eventual proof-consumer obligations.
Sampled decoding is outside this greedy schema and remains required by E7-08.

## Candidate bytes and model role

Accepted RFC-0022 v1 is unchanged. The separate research frame is exactly 86
bytes, within capacity 128, using unsigned little-endian integers and no padding:

1. Literal `stele/research/q26/greedy-bounds/v1\0` (36 bytes).
2. u32 vocabulary, u8 fraction, u32 length (nine bytes).
3. u32 p, u8 scalar count=9, then nine u32 scalars in order: logit_max,
   logit_high, selected_max, position_max, difference_max, gap_max,
   prefix_bit_max, strict_rhs_max, entry_capacity.

The scalar values are 32768,32767,V-1,L-1,65535,65535,1,65536,2^22.
Exact regeneration from separately expected Spec rejects altered fields/bytes,
truncation and suffixes. Supplied fields never choose vocabulary, units or bounds.

The model compiler emits one decoding.greedy record using vocabulary size,
logits_fraction and common configured context length. It never scans learned
values or observed maxima. Its helper checks numerical generation against rows
from the separately expected replay. The fixture checksum hashes literal
`stele/research/q26/greedy-bounds-checksum/v1\0`, u32 record count, then each
u16 ASCII name length/name and u32 record length/bytes. This is test evidence,
not a complete certificate-set identity, model authentication or cqis_id.

## Evidence and remaining work

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py --greedy-bounds`.
Seed 2641 checks 10000 rows against independent NumPy first-argmax/differences,
including 2565 tied-maximum rows, and 10000 synthetic generation boundaries with
independent selected-token sequences. Numeric constants and struct framing are
independent. Frozen SHA256:
`a7e0094c7b10873822664c15fc8be8bfbca50e35ea0137d14094b366903f8172`.
The tests-first run rejected the absent implementation.

Controls reject nonmaxima, later ties, fabricated selected maxima, modified
differences/gaps, field aliases, extra padding entries, padded selected ids,
wrong expected tokens/positions, altered prompts, premature limits, tokens after
EOS, absent decision rows, oversized row sets and every byte mutation/truncation
of representative records. They cover int16 endpoints, all-negative rows,
all-tied rows, vocabulary one, maximum metadata shapes and a 16384-entry tie.
Seed 2642 exercises thirty complete model configurations with varied logit units,
checking all non-overflow cases against independent prefix replay and stopping.
Shared inner model primitives are disclosed; this is not native Rust/GPU parity.

The pinned checkpoint adds one record, 86 bytes and checksum
`da66d6f167c496b54d388d4d8e502572fba738b356b7053f9ebf6a3ba8d688e5`.
The checkpoint command now checks the greedy relations on both generated decisions
using the independent full replay's preceding-position logits. Previous numerical
fixture fields are preserved. Serialized byte counts are not performance results.

Recommendation: continue Q26/A3 with attention/score schemas and the complete
canonical certificate set, then amend RFC-0022 before native graduation.
Actual LM-head/source/selection/range/PCS consumers, sampled decoding, native
forward, fidelity and NC-0107/0108/0109 remain open. E5-03/04 and E7-08 retain
all original criteria. Record derivation has fixed work; row witness/checking
uses O(V) work/data and n generated decisions use O(n*V). These contribute to
T_misc/c_a/T_witness without a measured constant, new cut or proof weight pass.
