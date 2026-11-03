# RFC-0025 request, stopping and token-I/O contract

Status: Accepted. Part of [RFC-0025](RFC-0025-full-model-cqis.md), Q26/E5-03b.
This closes the request boundary and stop arithmetic. The complete passport,
public statement, private-token commitments and actual hash/source consumers
remain required; these frames alone cannot admit an inference proof.

## 1. Request boundary

The independently authenticated Model supplies vocabulary v, capacity n and
the complete [Decoding descriptor](full-model-decoding.md). Both v,n are in
1..2^20. Request data cannot change them or substitute another descriptor.
Let q be prompt length, a be maximum_new, and S the EOS token-id set. Require
1<=q<=n, 0<=a<=n-q and 1<=|S|<=v. S is strictly increasing, has no duplicates,
and contains only ids in [0,v). Empty/disabled EOS, inferred defaults, negative
ids and ignored unknown fields are not defined by this version.

The exact bytes, using the [encoding appendix](full-model-encoding.md), are

    RequestBoundary = ASCII("stele/v0.1/cqis/request-boundary")
       || u8(mode) || u32(q,a,|S|) || u32(S_j) for each j
       || [seed_commitment[32] exactly when mode=1].

mode 0/1 must equal Model's greedy/sampled mode. Greedy has no seed bytes.
Sampled requires the original [seed commitment and draw relations](full-model-decoding.md),
even when a=0; no random seed or all-zero digest is interpreted as an absent
field. The public policy subrecord is `B(Decoding) || B(RequestBoundary)`.
Decoding must byte-equal the complete validated Model descriptor, including its
temperature/top-p/function/representation; its independent public copy cannot
select another policy. The eventual public-input frame includes this subrecord
with the same cqis_id/passport/profile and I/O authority. It is not an opaque
policy hash or a request-supplied numerical configuration.

The generic contract supports multiple terminal tokens because Meta's pinned
[tokenizer](https://github.com/meta-llama/llama-models/blob/0e0b8c519242d5833d8c11bffc1232b77ad7f301/models/llama3/tokenizer.py)
lists end-of-text, end-of-message and end-of-turn as stop tokens. With the named
128256 vocabulary and 256 reserved tokens these are 128001,128008,128009.
Its [generation implementation](https://github.com/meta-llama/llama-models/blob/0e0b8c519242d5833d8c11bffc1232b77ad7f301/models/llama3/generation.py)
checks generated-token membership while excluding prompt positions. GPT-2's
[pinned configuration](https://huggingface.co/openai-community/gpt2/blob/607a30d783dfa663caf39e06633721c8d4cfcd7e/config.json)
names EOS 50256. Named adapters must authenticate their original tokenizer and
request policy; dimensions or these constants alone cannot grant a named identity.
The CQIS zero-limit, context admission and complete returned-token evaluation
rules below are explicit. They do not inherit host-library defaults, truncation,
temperature-zero aliases or text presentation behavior from those references.

## 2. Complete sequence and exact stop cause

Let P be the original q prompt tokens and T the full returned sequence. Every
token is in [0,v), T[0..q]=P exactly, and T has N=q+g entries with 0<=g<=a.
Generated token i is T[q+i], for i=0..g-1. Its decoding consumes the full
previous-position logits at q+i-1; its sampled draw uses absolute position q+i.
Neither index is generation-local. The full causal evaluation covers all N
tokens, including any final EOS. Full/cache equivalence retains every complete
row, original K/V scale, absolute position and configured block identity.

There are exactly two stop reasons: u8(0) for limit and u8(1) for eos.
No generated token before the final generated token belongs to S. If g>0 and
T[N-1] belongs to S, reason is eos. Otherwise g=a and reason is limit. Thus EOS
takes precedence when the final permitted token belongs to S; g=0 always has
limit reason and requires a=0. An EOS in P never terminates generation. There is
no early partial result for a domain, range, capacity or evaluation failure:
it rejects execution and cannot be relabelled as either successful stop reason.

The original research single-EOS contract is the |S|=1 instance of this rule.
Its `causal_model.generate` evaluates a chosen token before testing EOS, and
`greedy_bounds.check_generation` requires eos reason even at the limit. This
draft retains those choices without inheriting its 2^22 entry-product cap.
The numerical boundary checker is not a model evaluation or proof verifier.

## 3. Token-I/O bytes and source authority

The canonical digest-mode preimage is

    TokenIO = ASCII("stele/v0.1/cqis/token-io") || u32(q,g) || u8(reason)
       || u32(T_t) for t=0..q+g-1,
    io_digest = BLAKE3-256(TokenIO).

Lengths and reason are part of the hashed boundary. A different q splitting the
same token sequence changes the preimage. The whole public statement separately
binds the original RequestBoundary; identical tokens under different permitted
limits/EOS sets do not imply identical public statements. The prefix and every
token byte must reach the same original prompt/output source and embedding/
decoding consumers. A supplied matching digest is not proof of those joins.

TokenIO describes bytes, not a requirement to publish private tokens. In digest
mode it may be a private hash preimage. RFC-0011 §5's input/output commitments
remain available and mandatory where that statement requests them: the actual
wrapper must establish that their same original token sources satisfy these
boundaries and the inference relations. No plaintext replay substitutes for
private proof, and no new intermediate commitment is authorized. Complete typed
commitment/opening contracts and native validators remain required; the
[public-input appendix](full-model-public-input.md) fixes the complete outer frame.
Text encoding, special-token insertion, conversation formatting and traffic
ownership require their separately authenticated tokenizer/adapter sources;
numeric token ids alone make no such claims. E13-05 chaining remains required.

Define rh=45 and ih=33, the respective prefix/header lengths above. Exact request
length is rh+4|S|+32mode, bounded by rh+4v+32mode. Exact TokenIO length is
ih+4(q+g), bounded by ih+4n. At full domain the maxima are 4194381/4194337 bytes.
These are separate from Model's 1 MiB cap. Check mode, count domains, total length
and all u64 arithmetic before loops/access/allocation; validate every id and
strict order. Reject truncation, suffixes, unknown reason/mode and inactive seed
bytes. Re-encoding valid decoded data must recover every byte. Native readers
must stream or use fallible bounded allocation; research tuples do not prove it.

## 4. Stop membership and schema 18

The public EOS mask is E[j]=[j in S] on v real vocabulary entries, zero on padded
entries through V=2^ceil(log2 v). For a point r of ell=log2 V coordinates,
least-significant index bit first, its exact multilinear extension is
`sum_(j in S) product_(b=0..ell-1) (r_b if bit_b(j)=1 else 1-r_b)`.
At v=1 the empty product is one. A private selected token must consume this
same verifier-derived mask by its actual range/index/source relation; an
unbound membership bit or positive-membership-only test is insufficient.
Native E6 public-MLE evaluation, padding and field/profile parity remain gates.

Schema 18 parameters are `u32(v,n) || u8(mode)` with these domains. Its fixed
radix-256 [arithmetic frame](full-model-bounds.md) contains ordered scalars
`n,n-1,v-1,Npad,2Npad-1,V,2V-1,log2(Npad),ell,rh,ih,rh+4v+32mode,ih+4n,2^32-1`,
where Npad=2^ceil(log2 n), and no shifts. Request values never tighten the record.
Let remaining=a-g, has=[g>0], last=g-1 when has=1 and zero otherwise. All index,
Boolean, canonical zero and whole-word predicates are enforced as defined in
the shared appendix. In particular has is derived from the original g.

For absolute t in 0..n-1, beta_t=[q<=t<N-1]; it is zero on prompt, final and
padding positions. Let e_t=E[T_t] for real tokens, zero outside N. Require
sum_t beta_t*e_t=0. Let e_last=E[T[N-1]] when has=1 and zero otherwise;
reason=has*e_last, and remaining*(1-reason)=0. Together with the length/source
relations these enforce the exact stop rule, including negative membership
before the final token. Padded layouts gate whole equations, including constants.

| Role | Ordered terms (count,A,C); omitted count is one | Required side |
|---|---|---|
| 1 | (n,1),(n,1),(n,1) | q+a+capacity_gap=n |
| 2 | (n,1),(n,1) | q+g=N |
| 3 | (n,1),(n,1) | g+remaining=a |
| 4 | (n,1),(n-1,1) | q+i=t for every generated i |
| 5 | (n-1,1),(1,1) | previous_position+1=t |
| 6 | (n-1,1),(1,1) | has*last+has=g |
| 7 | (n-1,1) | (1-has)*last=0 |
| 8 | (count=n,1,1) | sum beta_t*e_t=0 |
| 9 | (1,1) | has*e_last=reason |
| 10 | (n,1) | remaining*(1-reason)=0 |
| 11 | (n-1,4) | token byte offset 4t |
| 12 | (4(n-1),1),(3,1),(ih,1) | ih+4t+lane |
| 13 | (v-1,4) | EOS list byte offset 4j |
| 14 | (4(v-1),1),(3,1),(rh,1) | rh+4j+lane |
| 15 | (255,1),(255,256),(255,65536),(255,2^24) | original u32 token/EOS bytes |
| 16 | (v-1,1),(v-1,1),(1,1) | previous EOS id+gap+1=next id |

All tokens/EOS ids still satisfy the tighter semantic bound v-1. Whole words
and high zeros, not just an M31 residue, bind each canonical u32. Every original
byte, hash preimage field and selector retains its source; zero factors do not
erase joins. Global g/N/request counts determine the same decode and causal rows.

There are 14 scalars, 16 roles and 32 terms. All word values fit u32 and K<=4.
Role 8 has raw column<=n and carry<=floor(n/255), so either side<=2n+255<p/2.
Other roles have at most four count-one terms: raw<=4*4*255^2, carry<=4*4*255,
either side<=1044735<p/2. Using at most four cap bytes per operand, each term
uses <=592 bytes and each role's nonterm portion <=348; the record is <40000
bytes, within 128 KiB. Capacities are analytic bounds, not measured performance.

Full native E7-08/E6/E8 consumers must close prompt/output/token/logit/position/
mask joins; E8/E14 hash/wrapper consumers close TokenIO and the sampled seed/draw
relations with global H/query accounting. NC-0001/0005/0107/0108 remain actual
consumer gates. E13-04 top-k and E13-05 chaining are preserved. Preparation and
public-mask work cost O(v+|S|), sparse MLE evaluation O(|S| log v), and boundary/
hash-source checks O(n+|S|); charge T_misc/T_witness/c_a/c_lu as applicable.
No new challenge, probabilistic loss, cut, weight pass or profile is admitted.

The [public-input appendix](full-model-public-input.md) exposes the same g/reason
as explicit public geometry and binds the complete policy with either TokenIO's
digest or distinct prompt/output commitment references. The actual source and
stop consumers must establish those fields; parsing the envelope cannot do so.
