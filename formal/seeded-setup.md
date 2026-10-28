# Candidate seeded setup and classical setup-loss bound (Q23)

Status: Draft, RFC-0010 A1 / RFC-0012 A7. This is a deterministic research sampler
and a conditional classical random-oracle argument. It is not a quantum setup
bound, a concrete BLAKE3 distance certificate, or permission to admit a profile.
RFC-0002 permits quantum adversaries; that acceptance obligation remains open.

## 1. Manifest, expansion and rejection

Use the map, degrees, base and raw setup codec in [recursive-code.md](recursive-code.md).
The manifest is exactly 55 bytes: ASCII `stele/expander-seed/v1` (22 bytes),
u8(J), and a public 32-byte seed, with integer 3<=J<=15. Unknown versions,
truncation, suffixes and unsupported J reject as `InvalidManifest`. No caller
supplies a degree, field, modulus, distance, success flag or security budget here.
At J=3 the map is the fixed circle base; the seed is unused. Different manifests
can describe equal maps. This format does not normalize semantic equivalence.

For each row, obtain 32-byte blocks as the unkeyed BLAKE3 digest of exactly:

```
ASCII("stele/v0.1/setup/expander/block/v1") || seed[32] ||
u8(level) || u8(kind) || u32_le(row) || u8(stream) || u8(counter)
```

Here level=4..15, kind=0 for A and 1 for B, row is in the derived matrix range,
stream=0 for neighbors and 1 for coefficients, and counter=0..31. Invalid record
coordinates reject as `InvalidSampler`. Each block yields eight u32le words.
J is deliberately absent: a seed selects one shared twelve-level tower, and all
supported sizes and extension fields use its corresponding levels. Domain/version,
record widths and ordering are fixed. These are setup expansion bytes, not proof
Fiat-Shamir challenges; this draft adds no `Transcript` label or alternate FS path.

Let m be the row's number of columns, always a power of two. For stream 0, project
each word with `word & (m-1)`, discard repeats, stop at the required degree, and
sort the selected columns increasingly. Independently, for stream 1, project with
`word & (2^31-1)`, reject the value 2^31-1, and retain the required number of
values in order. Zero is allowed. Pair these coefficients with the sorted columns.
Do not require nonzero/distinct coefficients or sort coefficients by value.

Each stream has at most 256 words. Stop immediately when sufficient values exist;
otherwise reject the whole setup as `SamplingExhausted`. No row or partial setup
is returned, no default graph is substituted, and no counter wraps. Generate levels
J down to 4, A then B, rows increasingly, neighbors before coefficients. Serialize
with the existing raw setup codec. The research implementation materializes all
rows and validates them before returning; production allocation limits remain open.

`check_setup` validates both descriptors, rejects a J mismatch, regenerates the
entire expected raw setup and compares all bytes. A canonical altered coefficient,
a changed seed at J>=4, or another J must not substitute for that source. Mismatches
reject as `SetupMismatch`; malformed raw bytes retain the codec's `InvalidSetup`.
Agreement proves only consistency with this deterministic expansion. An eventual
commitment/plan/passport must bind the manifest, algorithm version, raw map identity
and approved parameters through its actual consumer. That consumer is not supplied.

## 2. Uniform ensemble and bounded streams

Assume every distinct block input receives an independent uniform 256-bit string
from an ideal random oracle. All eight words and all seed/row/stream records are
then independent. The neighbor projection is uniform because m divides 2^32.
Removing repeats selects a uniform ordered sample without replacement; sorting it
produces a uniform subset. The coefficient projection is uniform on 2^31 values;
rejecting the single excluded value gives independent uniform M31 elements.
Neighbor and coefficient streams are independent, including zero coefficients.

To account for exhaustion without a conditioning error, extend every row stream
past its actual 256-word cap with auxiliary independent uniform words. The resulting
uncapped tower has precisely the ensemble distribution in
[expander-sampling.md](expander-sampling.md). On every successful capped generation,
each returned row equals its uncapped counterpart. Thus the event that an admitted
prefix violates the support properties is contained in failure of the uncapped
tower. There is no division by the probability of successful generation. Unused
higher levels need not pass their caps. Exhaustion rejects; it is not a successful
false statement or an excuse to retry under an uncharged new seed.

The fixed circle base has sufficient distance. Across levels j=4..15 the exact
finite analysis supplies two events per relevant support size, each <=2^-288:

```
D_j = floor(4^j/25)+1; I_j = floor(4^j/100)+1
L = sum_(j=4..15) 2*((D_j-1)+(D_j-I_j)) = 200431782
epsilon = L / 2^288 < 2^-260
```

Consequently each independent seed's uncapped tower fails with probability at most
epsilon. This covers all supported prefixes together, not a fresh independent
failure event each time a size/field/proof reuses that seed. The existing component
argument transports M31 minimum symbol distance to QM31/OM31. Neither this bound
nor regeneration establishes proximity, commitment codeword validity or PCS soundness.

## 3. Adaptive selection: classical queries only

Let Q bound all classical oracle queries made by the adversary and preprocessing
that can reveal setup information, including discarded attempts and information
available through other interfaces. Let S bound distinct final output seeds whose
setup records have never been queried. Budgets must include all relevant history;
there is no free oracle-correlated advice or uncounted trusted party leaking rows.

Lazily assign an independent complete uncapped tower when a seed is first touched
by a canonical setup-block query. Immediately before that query, its tower is
independent of the entire preceding classical history, so its bad-event probability
is at most epsilon. Charge the whole bad tower at this first touch, regardless of
how adaptively later queries inspect it or whether the seed is discarded. There
are at most Q such first touches. Every final untouched seed is independent of
the history used to choose it and has the same bound. A union bound gives:

```
Pr[any output successfully regenerates a bad supported code] <=
    min(1, (Q+S)*epsilon).
```

This is an original elementary argument for this candidate in the stated classical
model, not an attributed theorem about BLAKE3. One final seed gives S<=1; multiple
final instances require their actual distinct-seed accounting. For example,
Q=2^100,S=1 makes this expression less than 2^-160, but does not authorize that
budget or establish any profile target. `setup_bound` checks only exact arithmetic;
caller-supplied Q=0 is not a certificate. Reuse of an already charged seed is the
same event; new versions/domains require explicit composition. Future admission
must authenticate its lifetime/query policy, not trust prover-supplied attempt counts.

The distinction between a random-oracle proof and instantiation with a concrete
hash follows the model described by [Bellare and Rogaway](https://cseweb.ucsd.edu/~mihir/papers/ro.pdf).
The research BLAKE3 implementation and fixed vectors do not prove this assumption.

## 4. Quantum counterexample and remaining admission gate

Classical first-touch reasoning does not cover superposition queries. As an exact
small counterexample to reusing its formula, consider 16 inputs with independent
oracle outputs marked with probability 1/16. Conditional on k marked inputs, put
x=k/16. Starting from the uniform state, mark phases and invert about the mean.
The marked amplitude becomes (3-4x)/sqrt(16), so success is x*(3-4x)^2. This is one
iteration of [Grover's search](https://arxiv.org/abs/quant-ph/9605043); the following
finite expectation is derived and checked here rather than cited as his theorem:

```
sum_(k=0..16) C(16,k)*(1/16)^k*(15/16)^(16-k)*(k/16)*(3-4*k/16)^2
  = 13073/32768 > 1/4.
```

Computing/uncomputing the mark takes two oracle queries; checking the measured
output takes one more. Even allowing S=1, the classical expression with Q=3 would
be (3+1)/16=1/4, which is false in this quantum experiment. This generic sparse-output
example is not an attack on the actual expander instance or a quantum upper bound.
It demonstrates why a classical linear query charge cannot discharge RFC-0002.

Before A1/A7 acceptance, supply an applicable quantum setup-selection theorem,
its exact oracle/query convention and composition with the actual FS/H accounting.
Re-derive finite degrees/budgets if necessary. Q12's existing 2^100-query H example
already exceeds the treaty target; this draft does not repair it. Conditional PCS
error and setup failure must both appear in a complete instantiated bound, with
actual source authentication, proximity hypotheses and profile enforcement.
No production registry, loss enum, ledger entry or `proven=true` is added here.

## 5. Cost and executable evidence

For R(J)=sum_(j=4..J)(4^j+4^j/2) rows there are at most 64*R(J) hash blocks.
Generation is O(n) because degrees, caps and base are fixed; this is an operation
bound, not measured throughput. Account for hashing/preparation under T_misc and
c_c, O(E(J)) retained graph entries, transient canonical bytes, and the supplied,
decoded and regenerated copies in `check_setup`. Production allocation, peak-memory
and encoder benchmarks are still required; no weight-pass constant changes.

Run `uv run --locked --script research/code-provenance/check_sampler.py` for finite
sampler symmetry, exact cap boundaries, whole-setup rejection, independent framing/
row expansion, four fixed full-setup digests, prefix reuse, regenerated source tamper
rejection, actual generated-map parity in all three fields, adaptive classical toy
selection and the exact quantum counterexample. The largest generated map is n=1024;
there is no maximum-size, Rust/GPU parity, PCS control or independent-audit credit.
