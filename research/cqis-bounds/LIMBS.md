# Q26 static limb bounds

Question: which static radix-column bounds make nonnegative sums of products
faithful in M31, including carries and the result side? The security property
is INV-5 / RFC-0004 §6 under Draft A3 and RFC-0003 A2. Kill criteria: any admitted
configuration has a column side at least p/2, an in-range witness exceeds a
derived bound, or modular relations admit a different integer result when all
stated source, digit and carry ranges are enforced. Source whole-value bounds
must come from authenticated formats/shapes, never observations or prover choice.

This research lemma is a prerequisite for closed per-reduction schemas. It does
not authorize a generic bound tuple in the native verifier or satisfy NC-0109.
The cost terms at stake are c_a and c_lu for limb arithmetic/ranges; no measured
constant, challenge, commitment or weight-pass change is proposed here.

## Candidate and argument

Let radix B=2^b with explicit b in {4,8}, count 1<=d<2^32, and static whole-input
bounds 0<=A,C<2^160. Each source integer satisfies 0<=a_r<=A and 0<=c_r<=C.
For M, use max(1,ceil(bit_length(M)/b)) digits and caps
`u_i(M)=min(B-1,floor(M/B^i))`. These caps are overapproximations: B=256,M=257
gives (255,1), which also admits 511. Enforcing only digit caps is insufficient.
Whole-source ranges and the link from source values to digits remain separate
proof obligations; the prototype checks them as plaintext integers.

Set Z=d*A*C and K=max(len(u(A))+len(u(C))-1, digits(Z)). Pad result caps
`o_k=min(B-1,floor(Z/B^k))` to exactly K columns. Derive
`t_k=d*sum_{i+j=k} u_i(A)*u_j(C)`, `C_0=0`, and, for k<K-1,
`C_{k+1}=floor((t_k+C_k)/B)`. Enforce final carry `C_K=0` separately. This final
zero follows for honest inputs because their dot product is at most Z<B^K;
independent digit caps can overestimate the last carry and do not justify it.
Every actual interior carry is at most C_k by induction. The two static sides
are `L_k=t_k+C_k` and `R_k=o_k+B*C_{k+1}`. Reject unless `2*L_k<p` and
`2*R_k<p` for every column, with fixed p=2^31-1. No runtime value affects this
decision. Full Z is below 2^352; this is not one M31 element.

With source/digit/carry ranges and both zero boundaries enforced, each modular
relation `sum a_{r,i}*c_{r,j}+carry_k = z_k+B*carry_{k+1} (mod p)` has each
nonnegative side strictly below p/2. Its difference is in (-p,p), so equality
mod p implies equality over integers. Multiply column k by B^k and sum:
interior carries cancel, zero boundary carries vanish, and the unique result
is the original integer dot product. No probabilistic or conjectural step is
used. Signed recomposition, negative terms, biases and quotient/remainder
relations require their own certificates; this lemma does not cover them.

`limbs.py` rederives every supplied field from a separate expected Spec. It
rejects altered fields, keys and types, including Python booleans. This generic
Spec is a research interface, not an admitted operator schema. An actual
consumer must derive it from authenticated static data and enforce every range
and source binding through the accepted reduction/lookup/PCS contract.

## Reproduction and evidence

Run `uv run --locked --script research/cqis-bounds/check_limbs.py`. The pinned
NumPy version is 2.3.4; `limbs.json` records the deterministic result. The test
was written before the implementation and initially failed at the missing module.
There are 10,000 varied static configurations: 5,119 accepted and 4,881 rejected.
The independent oracle packs cap polynomials into an integer base larger than
all coefficients, multiplies, extracts coefficients without carries, and uses
prefix division for carry bounds rather than the candidate recurrence.

Another 10,000 supported input cases compare all modular relations and output
with a direct exact integer dot product and NumPy int64 digit convolution.
Only small digits enter NumPy; no wide value is narrowed. Maximum-dimension
zero/endpoint rows are also checked. Result checksum:
`22bcf861389d7e5524234cafce04cb9a408dac37c4d89c6f2b1313e3e2c0e697`.

| Static magnitudes, radix 256 | Count | Largest L_k | Largest R_k | Decision |
|---|---:|---:|---:|---|
| 128,128 | 65,535 | 1,073,725,440 | 1,073,725,695 | admit |
| 32,768,32,768 | 16,384 | 1,073,709,120 | 1,073,709,311 | admit |

The next count rejects in both cases. For signed-int16 magnitudes the leading
digit cap is 128; using an unsigned-16 bound of 65,535 instead rejects count
16,384. The tight cap comes from the static format, not observed inputs. This
supports the sum-of-squares magnitude part of RFC-0021's maximum RMSNorm
dimension, not the full RMSNorm reduction or its other wide identities.

Local tamper cases reject certificate fields/types, residue-preserving output
or carry additions of p, legal-range digit/carry changes, nonzero boundary
carries, changed source digits and 511 under the whole-input bound 257 even
when multiplied by zero. An unsafe count rejects even with all-zero inputs.
These checks are plaintext research tests, not catalog controls or NC-0109.

## Recommendation and remaining contract

Continue Q26 under RFC-0003 A2 / RFC-0004 A3. This evidence supports a static
column lemma; it does not complete E5-03. Still required: closed per-reduction
schemas and authenticated sources, signed and biased arithmetic, all norm
normalization/quotient/remainder bounds, canonical certificate bytes, canonical
chunking or unsupported behavior, native fallible validation, actual range and
binding consumers, and the original property/control criteria. No automatic
switch to narrower limbs, chunking or DPA is implied. No performance claim or
change to cuts, weight-pass count, proof format or soundness ledger follows.
