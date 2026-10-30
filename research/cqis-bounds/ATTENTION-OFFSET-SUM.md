# Consumed weighted attention offsets (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can complete
probability and restored-offset sources prove O_c=sum_j P_j*U_jc across all
channels, with exact integer columns and no proof loop over channels?
Costs are c_a/c_x/c_sc/c_lu/T_misc. Kill the design if an M31 whole-sum alias,
a changed source, a compensating channel error, an unchecked carry boundary
or a zero-hidden original is accepted. Keep the existing production criteria.

The expected Spec contains the attention-sum schema, increasing absolute
positions, Boolean allowed mask, block id, identity, probability/value/output
source ids and repetitions. Exact mode requires block zero. Block mode fixes
absolute positions to one configured block. The expected mask may be entirely
false: an empty contribution still consumes every real value source. Neither
mask nor positions come from the proof. Full query/key/mask ownership remains
a composition obligation. Limit actual positions times width to16384 entries;
the configured capacity C is still length, or min(length,1024) for block mode.
No allocation depends on unused configured keys.

Write Q=2^E and S for the existing static restored-value bound. Consume a
complete whole probability range0..Q (zero on masked/padded keys), a complete
whole offset range0..2S for every real value entry, and complete output ranges
0..2*C*Q*S for each channel. Probabilities retain the one/two byte-plane root
used by the probability-sum consumer. The external U root retains four byte
planes in flattened row-major order, exactly as the restored-value consumer;
its compact range root is separately bound. The external O root retains eight
byte planes over independently padded channels, including exact zero extension.

These ranges do not prove U=S+s*V or P=exp_q(score-max). Actual prepared-value
and probability/maximum/exponential compositions must use these exact roots.
This consumer only establishes the unsigned offset sum. Base S*Z, canonical
signed magnitude O-S*Z, block rounding and output normalization remain separate.
A zero probability never removes a value's source/range obligation.

Use the existing radix-16 offset-sum column certificate with capacity C,
left cap Q and right cap2S. It has K<=13 result columns and K+1 carry entries.
Whole ranges justify the individual nibble caps; each integer column equates
sum_j convolution_k(P_j,U_jc)+carry_k to O_kc+16*carry_(k+1).
The existing full-capacity certificate has maximum LHS/RHS816840960/816840975
and carry51052560, all below p/2. This is a static derivation, not a benchmark.
Both boundary carries and every unused carry slot are forced to zero.

Let R=2^ar pad positions and H=2^ac pad channels. Preserve16 carry planes,
each of length H. Let wc be the power-of-two byte width from the maximum
static carry cap. Each complete carry-range group contains
G=min(16,65536/H,131072/(H*wc)) consecutive planes; G is a power of two.
There are16/G groups in fixed order, retaining all zero planes. Every group
stays within65536 values and131072 byte leaves, including width16384.
The output range also fits H*8<=131072. Padded channels have zero O/carries.

All expected metadata, external roots, compact/auxiliary roots and complete
verified range states precede parent challenges. Draw rho, then ac channel
coordinates, through the existing Sumcheck label. Let lambda_c be the exact
MSB-first equality weights of that channel point. Form verifier-owned linear
views from the actual verified byte sources:

    A_j = sum_i nibble_i(P_j)*rho^i
    B_j = sum_c lambda_c * sum_l nibble_l(U_jc)*rho^l
    T   = sum_c lambda_c * sum_k rho^k*(O_kc+16*C_(k+1,c)-C_(k,c)).

One degree-two A1 over R proves sum_j A_j*B_j=T. Both final original views
have independent full-hypercube consumers at the actual emitted point,
including when either factor is zero. No supplied projected table, point,
receipt or plaintext weighted-sum result can authorize acceptance. The verifier
forms only source projections and the bounded output/carry target; it does
not recompute the weighted products. Dimension zero retains both final checks.

For fixed ranged sources, a false integer column is nonzero in M31 by the
static side bounds. Before sampling, its channel/column polynomial has total
degree at most ac+K-1. The multivariate Schwartz-Zippel bound contributes
(ac+K-1)/|Kfield|. The separate A1 contributes2*ar/|Kfield|. Binding and FS/H
remain additional. This argument is conditional on the full range/original
consumers; it does not establish Fiat-Shamir security or a private PCS.

Before implementation reserve identity<2^44 and base=2^63+2^18*identity.
Wide range ids4096*identity+1..11 cover probability, value, output and up to
eight carry groups. Compact value/output roots use base+1/+2, carry roots
base+3..10 and the compact probability root uses base+11. Parent views use base+16/+17 and A1 id
16384*identity+512, above all descendant range invocations. All three distinct
external ids stay outside the entire span. Expected metadata retains fixed
roles, configured capacity, absolute positions, mask and block.

For each complete range with dimension a_i and byte-width exponent b_i,
retain its separate lookup dimension m_i=a_i+b_i+1, identity
((2^m_i+255)/|Kfield|)^r and unsquared reduction
r*(F(m_i)+F(8)+3*m_i)/|Kfield|, F(m)=3*m*(m-1)/2+2*m.
The range/A3 numerator is sum_i(9*a_i+7*b_i). Each range contributes
4*a_i+3*b_i draws per nonlookup label. The parent adds1+ac+ar Sumcheck draws
and no ZeroWeight draws. Keep the polynomial identity and A1 numerators
separate from the range/A3 and lookup accounts. Verify these with receipts.

Write tests first:10000 independent NumPy/Python weighted sums and exact
nibble/carry/source encodings; full configured-capacity metadata with sparse
actual keys; exact and block modes; all-zero/masked contributions; both value
policies and exponent endpoints. Both fields/repetitions must cover ragged
positions/channels, dimension zero, high result nibbles and carry groups.
Attack all roots, individually valid substituted sources, false bounded output,
whole-output M31 aliases, compensating channel errors, zero-hidden originals,
noncanonical fields, mask/padding, carry boundaries and zero extension.
Compose actual restored-value and probability-sum proofs on the same roots.
Require full16384-entry proofs with128x128,16384x1 and1x16384 geometry and all
repository gates. The two extreme geometries exercise different capacity limits.

The tests-first run rejected the missing module. During implementation, the
independent corpus caught an all-masked probability encoding error: the compact
range needs one byte, while E>=8 requires two external planes. Bind its compact
root separately and zero-extend to the configured external width. This preserves
the fixed probability source representation even when every cap is zero. No
complete matrix has passed yet. The initial complete proof and account passed.
All external roots, valid substituted sources, bounded false sums, compensating
channel errors and M31 aliases rejected. Both zero-hidden original factors
rejected at their actual consumers. Seed2735 passed all10000 independent
cases over226920 value cells, including2838 zero-output cases. Frozen corpus
hash: `e1ae0608e74c877ac2e15a0b543bbb527cfd8a0dd85da3c07445aa69164340bb`.
Masked/padded source, output, carry boundary/tail and zero-extension controls
passed, including all-masked zero contributions. Actual probability-sum and
restored-value proofs composed for both value policies; a valid alternate value
source rejected. The field/shape matrix continues; three full geometries and
required local gates are queued.
Continue Q26/Q31 with signed weighted sums and output normalization. Full
projection-row/GQA/cache ownership, sequence completeness, native/private
PCS/ZK/FS, fidelity, GPU/scale and original task criteria remain open.
