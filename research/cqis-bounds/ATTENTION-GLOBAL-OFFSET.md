# Complete global attention offset aggregation (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can all configured
block offsets bind the global normalization offset without lifting their
whole sum into M31 or retaining a field table for every block and channel?
Costs are c_a/c_sc/c_lu/T_misc and retained source storage. Kill the design if
an omitted block, substituted source, modular alias, unchecked carry or
unconsumed projected source can produce acceptance under expected roots.

Preserve length L<=1048576 and width w<=16384 simultaneously. Let
B=ceil(L/1024), N=next_power_of_two(w), a=log2(N), bb=ceil(log2(B)).
All B blocks occur exactly once, in order. Exact-mode block offset X_bc is
sum_j Phat_j*(S+V_jc), with cap C_b=2*min(1024,L-1024b)*Q*S.
Block-mode X_bc=Rmax+rounded_block_bc has cap C_b=2*Rmax, where
Rmax=round(1024*Q*S/2^drop) from the normalization schema. Then O_c=sum_b X_bc.
Exact normalization uses T=O-S*Z; block normalization uses T=O-B*Rmax.
The global output cap sum_b C_b equals twice the existing total bound.

Every expected block and output root binds exactly 8N bytes in byte-plane,
then channel order. Complete wide ranges verify each real channel against
its static whole cap, with zero padding and zero extension to eight planes.
Each block is verified before its bytes enter a private temporary spool.
The output has a complete wide range. Two complete carry ranges each hold
four N-channel planes, including zero caps on padded channels. They fit the
existing 65536-word and 131072-byte limits, without changing those limits.

For byte k and channel c, prove sum_b X[b,k,c]+Cin[k,c]=O[k,c]+256*Cout[k,c],
with Cin[0,c]=0 and Cin[k,c]=Cout[k-1,c]. Derive carry caps recursively from
static source caps: incoming=0, then cap[k]=floor((incoming+
sum_b min(255,C_b >> (8k)))/256), incoming=cap[k]. Require cap[7]=0.
Each carry is at most B-1. Each side is at most 256B-1<p/2, so field
equality implies integer equality. All eight planes remain present even
when upper caps or every source value are zero. No observed-value bound.

Fix all expected roots, internal range roots and verified child states
before drawing a+3 Sumcheck challenges u. For lambda=eq(u,(byte,channel)),
project each block to s_b=sum lambda*X_b. Project the actual verified output
and carries to target=sum lambda*(O+256*Cout-Cin). An ordinary degree-one
A1 over the padded block domain proves sum_b s_b=target. Its only original
is the actual projected block vector, with zero padding. The verifier
reconstructs that vector by reading the spool and rehashing each block
against its pinned expected root, then calls the complete original consumer.
A supplied projection, proof receipt or plaintext whole-input sum cannot
replace that consumer. Projection and A1 losses remain separate.

The stream contains exactly B records with strict integer block indices and
one complete range proof each, followed by one tail containing the output
range, two carry ranges and A1 proof. Require EOF; reject missing, reordered,
extra or malformed records. The producer and verifier own their temporary
spools and close them on failure. Recheck each stored block's root on replay;
reject truncated, appended or changed bytes. Canonical spool size is B*8N,
at most 2^27 bytes. Retained parent data is O(N*d+B) plus one block proof;
child range peaks, caller-held inputs/proofs and codec storage are separate.
The small A1 has at most 1024 entries. No process-memory or speed result is
claimed without complete measurement and a benchmark ledger entry.

Reserve identity<2^42, base=2^63+2^20*identity. Block b uses wide-range
identity 16384*identity+1+b; output uses +1025, carry groups +1026/+1027.
Internal source roots are base+2^18+b for blocks, followed by +1024 for
output and +1025/+1026 for carries. The projected original is base+2^19+1;
parent A1 id is 65536*identity+8192. External block/output ids are distinct
and outside the parent span. All child spans and reduction ids must be
checked at maximum identity before implementation. Full expected schema,
ordered role ids, field, repetitions, roots and child states bind context.

Tests first: 10000 independent integer sums, byte columns and carry bounds;
B=1, ragged last blocks, zero bounds and maximum geometry in both modes.
Complete proofs cover both fields/repetitions and every expected source.
Attack record order/count/types, padding, high planes, internal carry roots,
valid source replacements that preserve the output, and a fresh valid
output range for O-p. With nonzero static caps and zero sources, attack a
fresh valid nonzero carry range. A forged projected vector with +1/-1 must
pass standalone A1 reduction yet fail the actual original consumer.
Corrupted, truncated and extended spools must reject. Context, static account
and original-source receipts must match. Require genuine streamed maximum
B=1024,w=16384 proofs and complete resource evidence before claiming that
full configuration validated; do not substitute a smaller source domain.

Actual per-block weighted sums or signed rounded-block offsets must still
join these source roots. Existing tile consumers do not prove full global
key/value ownership. Complete key/mask/cache/GQA/model provenance, native
linear-view reductions/PCS/ZK/FS, GPU parity, fidelity and independent audit
remain required. No production binding/control credit, new cut, benchmark
or extra weight pass is claimed. Original tasks remain blocked; Accepted
semantics are unchanged.

Twelve pre-implementation namespace checks passed at maximum parent identity,
covering both fields/modes and singleton, ragged and full configured domains.
All complete child ranges fit unchanged limits; final carry caps are zero.
The test-first control invocation then failed on the missing implementation
module, as expected. Neither check establishes proof admission.

The streamed consumer is implemented. Full geometry and context checks
passed. The first complete control run rejected a changed padded source
word through the actual source-copy claim; its test expected an earlier
commitment diagnostic. Only that assertion changed. The failed log remains
recorded and the original corpus continues; corrected complete controls,
proof matrices, full-size proofs and repository gates remain required.
