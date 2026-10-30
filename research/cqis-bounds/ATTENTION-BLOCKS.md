# Q26: static attention block rounding and summation

Question: can signed raw block sums be rounded once at their absolute block
boundaries, then summed with the corresponding probability sums under static
integer-faithfulness bounds? INV-5 and source/block/divisor/rounding bindings are
at stake; cost terms are T_misc/c_a/c_x/T_witness. Kill criteria: accepted source
or rounding alias, changed/missing block, divisor mismatch, oracle disagreement,
runtime-selected cap or work proportional to unoccupied blocks. Research under
Draft RFC-0004 A3/A6 and RFC-0009 A2; actual source/mask/position/function/range
consumers and complete attention-proof admission remain required.

## Static domain and expected block sources

Spec fixes absolute span L in 1..2^20, head width W in 1..16384, value fraction
fv in 0..30, probability exponent E in 0..14, dynamic/static V policy and drop
c in 0..62. This schema is only for block1024 mode. Dynamic scale metadata is
inactive zero; static scale s is in 1..65535. The policy's restored cap is
S=127*259 for dynamic mode or s*min(127,floor((65536+s)/(2*s))) for static mode.
Set P0=2^E, H=1024*P0*S, D=2^c and bias=floor(D/2). Define Qmax=floor((H+bias)/D)
and reject the configuration unless Qmax<=32767, even for a sole actual zero input.
This keeps the full-block requirement when L<1024. No observed value chooses c.

The static block count is C=ceil(L/1024), with total cap T=C*Qmax<2^25,
per-block probability cap Zblock=1024*P0<=2^24 and total cap Zmax=L*P0<=2^34.
Expected block IDs are a nonempty strictly increasing tuple in [0,C), with
actual count k<=C and k*W<=2^20. No unoccupied block is materialized. This entry
cap is a research resource limit, not a newly admitted inference-plan capacity.
Each ID has a separately expected probability sum in [0,Zblock] and exactly
W signed raw sums x in [-H,H]. Bool is not an integer. The total probability
sum must fit Zmax; a partial final block cannot enlarge the full-row divisor cap.

These are conditional source values. The primitive does not itself prove that
raw sums and probabilities came from the same keys, or that masks, scales,
head/GQA views and absolute membership are authentic. The preceding raw-sum
consumer must establish those associations, including zero contributions from
masked keys. Empty blocks are absent; an occupied all-masked block remains an
expected row. Omitting that row rejects even when its numerical contribution is zero.

## Rounding and aggregation relations

For each raw x, witness sign b in {0,1}, magnitude a and sign gap g in [0,H].
Enforce canonical byte-column equalities for:

- (x+H)+2*b*a=H+a and g+b=a, excluding negative source zero;
- a+bias=qd+r and qd=q*D, with q in [0,Qmax] and r in [0,D-1].

The source offset x+H is derived from the separately expected source. Bind the
quotient product to qd through exact result digits. Each output y is in
[-Qmax,Qmax] and satisfies y=(1-2*b)*q directly in M31. This is signed nearest
rounding with ties away. Negative inputs may round to integer zero. At large
drops Qmax=0, nonzero raw inputs remain valid and every rounded output is zero.

The six per-entry roles use (count,left maximum,right maximum), radix 256:

| Role | Parameters |
|---|---|
| sign_lhs | (2,2H,2) |
| sign_rhs | (2,H,1) |
| sign_gap | (2,H,1) |
| bias | (2,max(H,bias),1) |
| quotient_product | (1,Qmax,D) |
| division | (2,max(Qmax*D,D-1),1) |

All source whole ranges, canonical source digits, result/carry ranges and zero
initial/final carries are checked. Wide equality uses a fixed ten-byte width
with canonical zero extension. Since H<2^40, Qmax<=32767 and D<=2^62, every
role result cap is below 2^78. At most two products and ten digits per operand
give raw coefficient<=1300500, carry<=5100, LHS<=1305600 and RHS<=1305855,
strictly below p/2 for p=2147483647. Whole source bounds justify the final zero
carry; digit caps alone are insufficient.

The aggregate rounded total t_c is in [-T,T] and satisfies sum_b y_bc=t_c
directly in M31. Both sides have magnitude at most T<2^25, establishing integer
faithfulness. The combined probability sum z can exceed p, so it uses a shared
capacity-based byte-column role (C,Zblock,1). Actual source digit rows cover only
the expected k probabilities. Its raw coefficients are at most 261120, carries
at most 1024 and both sides at most 262399, also below p/2. The canonical result
is bound to z in [0,Zmax]. Zero z is allowed here; complete normalization still
requires an attained unmasked maximum and a positive divisor.

## Candidate bytes and model roles

Accepted RFC-0022 remains unchanged. The research frame uses unsigned
little-endian integers without padding, in this order:

1. Literal `stele/research/q26/attention-block-bounds/v1\0` (45 bytes).
2. u32 L, u16 W, u8 fv, u8 E, u8 value mode (dynamic=0, static=1), u16 scale, u8 c.
3. u32 p, u8 radix bits=8, u8 scalar count=16, then sixteen u160 scalars:
   probability_max, restored_max, block_count_max, block_id_max, raw_max,
   source_offset_max, divisor, bias, rounded_max, scaled_quotient_max,
   remainder_max, total_max, sum_side_max, block_z_max, z_max, entry_capacity.
   sum_side_max equals total_max, the centered aggregate side bound.
4. Shared then entry groups with u8 counts 1 and 6. Each role has a u8 id starting
   at one within its group, u32 capacity/count, three u160 left/right/result
   maxima, three u8 digit lengths, left/right/result digit-cap bytes, then
   carry/LHS/RHS u32 arrays. Result length K fixes carry length K+1 and side
   lengths K. The shared role has capacity semantics; entry roles have exact arity.

Left/right/result lengths are at most 10/8/10 bytes. The fixed portion is 385
bytes and each role needs at most 220, giving 1925 bytes within capacity 2048.
Exact regeneration rejects every altered field, byte mutation, truncation and suffix.
The model compiler emits layer.i.attention_block only for configured block-mode
layers. Its checksum hashes literal
`stele/research/q26/attention-block-bounds-checksum/v1\0`, u32 record count, then
u16 ASCII role-name length/name and u32 record length/bytes. This is correctness
metadata, not a complete certificate-set identity or authenticated source consumer.

## Composition and evidence

The model checks feed the raw-sum checker's returned block sums and probabilities
into this checker, then its returned total/divisor into normalization. Whole
projection conversion precedes head/GQA slicing. A three-block case at positions
1023,1024,2048 retains a masked middle block and partial final block: separate
rounding gives [2,-2], while compaction before rounding would give [1,-1].
Actual proof source/selection/range/function consumers remain required; this
plaintext composition does not authenticate a claim graph.

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py --attention-blocks`.
The tests-first run rejected the absent implementation. Seed 2647 covers 10000
configurations and raw inputs against independent Fraction rounding, NumPy int64
rounding/sums, packed-column caps, digit convolution and struct framing. Seed
2648 checks thirty model configurations with mixed units, policies and modes:
28 accept and two reject arithmetic overflow. Block-mode cases compose the
three checkers; exact-mode cases verify that no block record is emitted.
Shared inner numerical primitives are disclosed; this is not native/GPU parity.
The frozen corpus SHA256 is
`c55dd0056ebf2ec462131547b4010307bc2296335d1f8dea73e484face206ec4`.

Controls rebuild every local column witness for an incorrect zero-to-32 rounded
output whose biased division differs by exactly p. Another starts from two
static codes -1 at scale 65535 and probabilities 16384: the true raw sum
-(2^31-32768) rounds to -32, while its positive alias 32767 rounds to zero.
Both reject with IntegerRelation. Other controls alter source/probability sums,
IDs, omit an all-zero block, change signs/gaps/quotients/remainders/outputs,
forge aggregate totals, exceed global divisor capacity and mutate certificates.
They cover signed ties, large-drop zero outputs, sparse storage and all 1024
blocks at their extrema: probability sum 2^34 and rounded total 33553408.

The pinned exact-mode checkpoint correctly emits zero block records. A separate
numerical variant sets each layer to block mode with its static minimum drop,
retaining all policies and other parameters. Full/reference/cache replay uses
the same six fixed tokens and composes all three arithmetic checkers. Its drops
are [23,23], its two records occupy 2740 bytes, and its record checksum is
`da0b3f30e43e4de6c176bea03b612edf73806d4fa9b0c3ad0a6eb4dda628adbb`.
Its logit checksum is
`b28d55706da75542feafa7a6bd6d184fef8dee324dbdfd4f9eb8d49f1ebbb3e0`.
The variant has different semantics: these fixed tokens are not asserted to be
its generated continuation, and the baseline config/instance identity does not
identify it. The original fixture remains unchanged apart from additive evidence.
Serialized byte counts are not performance results or fidelity approval.

Recommendation: continue Q26 with score/max schemas and the complete certificate
set, then amend RFC-0022 before native graduation. Native forward, fidelity,
actual consumers and NC-0100/0101/0109/0500..0506 remain open; E5-03/04 and
E7-06/07 retain original criteria. Derivation is fixed work; witness/checking
uses O(k*W) work/data for actual occupied blocks, independent of unused capacity.
Charge eventual work to T_misc/c_a/c_x/T_witness; no measured constant, new cut,
proof weight-pass change or inference-proof admission is claimed.
