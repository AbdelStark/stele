# RFC-0025 sampled decoding appendix

Status: Draft. Part of [RFC-0025](RFC-0025-full-model-cqis.md), Q26/E5-03b.
This defines deterministic numerical choices; no sample proof or hash-opening
consumer is implemented by the numerical prototype.

## Exact policy

Let the previous position's int16 logits be L_j in common units 2^-fl, for the
entire vocabulary j=0..v-1. Temperature is the positive reduced rational tn/td,
1<=tn,td<2^32. Top-p is the reduced pn/pd, 1<=pn<=pd<2^32. Both are explicit;
zero temperature is not a hidden greedy mode. Select an RFC-0021 exp Function
and Representation, including its B,F,E and any split. Let m=max_j L_j and

    z_j=R((L_j-m)*td*2^F / (tn*2^fl)), w_j=exp_q(z_j), W=sum_j w_j.

All arithmetic before R is exact. Require every z in the selected inclusive
domain [-2^B,0], never clip. At least one z is zero, so W>=2^E>0. The first
attained logit maximum and its source relation remain proof obligations.
Temperature rounding occurs once, after subtracting the exact maximum. It is
not a separate per-logit rounding followed by an integer maximum.

Sort every vocabulary id by decreasing integer w_j, breaking ties by increasing
id. Retain this entire permutation pi; no token is dropped before selection.
This uses the actual integer weights because product exp need not be monotone.
Let P_r=sum_(i=0..r) w_pi[i]. Select the least k in 1..v with
`pd*P_(k-1) >= pn*W`. The preceding prefix is strictly below that threshold
(use prefix zero for k=1). This is the exact inclusive top-p boundary. The last
retained weight is positive, even at top_p=1; zero weights form a suffix.

Write Z=P_(k-1). On the retained order define C_-1=0 and
`C_r=floor(2^32*P_r/Z)` for r=0..k-1. C_(k-1)=2^32, with no special rounding
or final corrective mass. Equal adjacent CDF values are valid empty buckets.
For u in [0,2^32), select the unique r satisfying C_(r-1)<=u<C_r and return
pi[r]. Every selected weight is positive. Rounding CDF endpoints can eliminate
a small positive bucket; this is part of CQIS, not an implementation fallback.
Relative to the exact retained integer-weight distribution, each bucket's mass
error is less than 1/2^32 and total variation is less than k/(2*2^32).
This bound concerns fixed-point CDF rounding only; exp approximation, temperature
rounding, quantisation and model fidelity are separate.

Seed is exactly 32 bytes. With unkeyed BLAKE3-256 H, define

    seed_commitment=H(ASCII("stele/v0.1/cqis/sample-seed") || seed),
    h_t=H(ASCII("stele/v0.1/cqis/sample-draw") || seed || u32(t)),
    u_t=little_endian_integer(h_t[0..4]).

t is the absolute position of the token being generated, starting at prompt
length, not a generation-local counter. Length<=2^20 makes its u32 encoding
unambiguous. This is reduction modulo 2^32 of the little-endian hash integer;
there is no modulo bias for a uniform 256-bit string. A chosen/committed seed
does not establish fairness or independence. These are deterministic decoding
inputs, never Fiat–Shamir challenges. Protocol challenges still come exclusively
from Transcript under their own registered schedule.

The authenticated request contains the seed commitment for sampled mode. Seed
may remain a witness; the actual proof/wrapper must then verify its hash relation
and every h_t relation. Disclosing seed allows recomputation but cannot silently
replace a statement requiring its confidentiality. A supplied u_t, seed digest
or matching self-selected commitment never authorizes a token. The same seed,
prefix, configuration and absolute positions yield identical full/cache decoding.

## Bytes and configuration

The encoding appendix's B frame and integer conventions apply. Decoding is
`u8(mode)`: 0 for greedy with no additional bytes, or 1 for sampled followed by
`u32(tn,td,pn,pd) || B(exp Function descriptor) || B(exp Representation)`.
Unknown tags, nonreduced rationals, nonpositive values, out-of-range top-p,
conflicting function representations, inactive bytes and trailing data reject.
Sample exp is part of Model's exact ordered function references and unique
manifest. A different policy changes the model/CQIS identity, even if a specific
request happens to generate the same tokens. Seed, prompt, maximum_new and EOS
are separately authenticated request data; their complete public-statement frame
remains RFC-0025's outer-contract acceptance work.

## Static obligations and cost

For valid formats, 0<=m-L_j<=65535. The temperature numerator is bounded by
65535*td*2^F and denominator by tn*2^fl; the bound is static, not an observed
logit spread. Enforce the actual quotient/remainder, sign and exp domain. A
configuration may reject a request on domain failure; it must not claim universal
successful generation from sampled logits or omit that failure in fidelity.
Each weight is in [0,2^E]; W<=v*2^E<=2^34. Every prefix lies in [0,W]. Threshold
products are strictly below 2^66. CDF numerators are at most 2^66, divisors in
[1,2^34], quotients in [0,2^32], remainders strictly below their divisor.
One M31 equality cannot represent these full integers. The
[decoding-bound records](full-model-decoding-bounds.md) specify the complete
logit, temperature and selection words/roles. Static byte/sign/carry/high-plane
checks and final zero carry remain required at actual consumers.

The consumer inventory includes the original previous-position logits, attained
maximum and ties, temperature relation, exp representation/membership, complete
permutation and order, every prefix, minimal top-p boundary, exact division and
strict CDF bucket, original seed commitment/draws, selected token, absolute
position and stop cause. A sorted list without a permutation/source proof is
insufficient. E7-08 and configured E6/E8 consumers must implement these relations;
research arithmetic earns no NC-0107/0108 or source-closure credit.

Sorting costs O(v log v) comparisons per generated token; all prefix/temperature/
CDF work costs O(v) bounded integer operations. Account for these in T_witness,
c_a/c_lu and T_misc as applicable. There is no claim that sampling is free or
that it adds no vocabulary-dependent work. It does not add a weight pass or cut.

Hash binding invokes one seed hash and one draw hash per generated token,
besides the existing identity hashes. Their actual proof/wrapper consumers must
include them in RFC-0012's global H/query accounting and preserve Q12/Q29; this
draft does not produce a profile budget or a new challenge/error record. The
deterministic CDF rounding error above is not a probabilistic soundness loss.
Coordinated ledger/control review and independent numerical evidence remain open
before this appendix or RFC-0025 can be Accepted.
