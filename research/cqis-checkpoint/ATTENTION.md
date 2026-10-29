# Q26: attention value units and output normalization

Question: how do quantised value rows, their scales and block shifts determine
one exact attention output, with the same result in a full causal pass and a
cached prefix? This is research for Draft RFC-0004 A6 / RFC-0009 A2, not an
admitted kernel. No Accepted text or native inference behavior changes.

Security properties: source/scale association, signed rounding, positive divisor,
canonical masks and block units. Kill criteria: an exact-oracle mismatch, ignored
scale, lost shift, inconsistent cached-prefix result or runtime data used as a
static field certificate. No challenge, commitment, proof or production negative
control is supplied. Same-author review: [record](../../agents/reviews/attention-units-draft.md).

## Candidate and counterexamples

`attention.py` prepares signed int16 value rows with the existing candidate
`quantiser.py` dynamic/static conversion. Codes are symmetric int8; restore each
code with its row scale before multiplying by the unnormalized probability.
The cache carries the source unit fv and conversion policy. Legal cache syntax
is not source authentication: changing scales (1,2) to (1,1) on codes (127,127)
changes the equal-weight output from 191 to 127 and is syntactically accepted.
Future source/scale consumers must reject that substitution.

The selected Accepted exponential function uses the maximum over allowed keys,
lowest-index tie witness, exact score differences, inclusive domain and P(0)=2^E.
Masked keys have zero probability; real all-masked rows reject. No score rescale,
clamp or tail replacement occurs. Scores are supplied int32, not proven QK/RoPE
outputs. The script handles one query and one value row scope, without a full
multihead projection/assembly or GQA contract.
The original corpus uses prefixes starting at zero. The [composition study](PROJECTED-ATTENTION.md)
adds explicit absolute positions and a separate static position span for bounds.

Exact mode sums P*s*v. Block1024 mode groups by absolute key position, rounds
only complete/terminal block sums by public 2^c, then sums the rounded results T.
The output is R(T*2^(fo-fv+c)/Z), where R is signed nearest with ties away.
Check the entire wide row fits int16 before applying output int8 conversion;
reject overflow without saturation or fallback. Examples:

- The Accepted A*Z=O+rho, 0<=rho<Z relation defines ceiling. At O=-3,Z=2 it
  gives -1; candidate nearest gives -2. This is an explicit semantic change.
- With 1024 equal weights, v=64, scale=1 and c=2, T=16384,Z=1024. Restoring
  the shift gives 64; omitting it gives 16.
- Two allowed values 2 at positions 0 and 1024 with c=2 produce 4. Compacting
  allowed keys into the same block produces 2. Absolute positions matter.
- Selecting block mode from allocated length gives 4 for a length-1025 causal
  row containing only its first key, but exact mode gives 2 for that prefix.
  The proposed mode is fixed in configuration. Large c can destroy fidelity.

## Static bounds and numerical error

The candidate supports 1<=n<=2^20, width<=16384, fv/fo in [0,30], E<=14 and
c<=62. Prototype preparation additionally caps n*width at 2^20 cells. This cap
is an allocation guard, not an inference/profile limit. For dynamic conversion,
S=127*259 bounds abs(s*v). Static s in [1,65535] uses
S=s*min(127,floor((65536+s)/(2*s)))<=65535; all scales are checked in the corpus.

Thus each block's raw magnitude is at most 1024*2^E*S<2^40 and the full raw sum
is <2^50. Admit block c only when R(1024*2^E*S/2^c)<=32767, from parameters,
never observed values. Then abs(T)<=ceil(n/1024)*32767<2^25. With e=fo-fv+c,
normalization uses U=abs(T)*2^max(e,0) and D=Z*2^max(-e,0). Across both modes
U<2^118 and D<=2^64 (the endpoint needs 65 bits). Exact mode has c=0.
These Python-integer bounds do not authorize field equalities: complete signed
limb schemas, both sides of division/comparison and actual consumers are open.

Relative to the restored-value weighted mean, exact mode has at most 1/2 output
unit final rounding error. Block mode adds at most
ceil(n/1024)*2^(c-1+fo-fv)/Z output units before that rounding. Value conversion
and final int8 conversion have their own scale-dependent errors. Neither bound
is model fidelity evidence; score quantisation and exp approximation are separate.

## Evidence and cost

Run `uv run --locked --script research/cqis-checkpoint/check_attention.py`.
Seed 2627 gives 10,000 exact/NumPy decisions: 5,999 accepted, 4,001 rejected;
16 full/prefix comparisons cover both modes, dynamic scales and the block edge.
Another 24 exact-oracle cases cross block boundaries in both modes with three
value policies. The 2^64 divisor bound endpoint is checked without allocation.
Decision/output SHA-256:
`a4f4935706fd362168eeb68ef5d17c6d88f2ae8862ca4fa08b03f7c3ab696769`.
Signed ties, int16 endpoints, unit shifts, masked maximum, empty/domain/type,
cache scope, zero scale and insufficient block shift have explicit checks.
The oracle uses independent Fraction nearest selection and NumPy int64 products;
wide shifts use exact integers. Both reuse the Accepted certified-exp primitive:
this is independent attention arithmetic evidence, not a new exp proof.

Work is O(n*d) for one row, with O(n*d) prepared cache, O(n) probabilities and
O(d) accumulators; no n-by-n matrix is allocated. The bounded exp memo has at
most 8192 entries. Scale multiplication/reads, variable division and block
rounding affect c_a/c_x/T_misc; actual reduction and proof costs are not measured.
No bench ledger, performance number, weight-pass change or native memory claim.
Full QK/RoPE units, config bytes, complete static schemas, source/range/lookup/PCS
consumers, native Rust/NumPy parity, joint ZK and full-model fidelity remain open.
