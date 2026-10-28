# Candidate v2 seeded setup and all-seed setup-loss bound (Q23)

Status: §1's deterministic manifest/sampler is governed by RFC-0010 A4. The
security/admission argument remains Draft RFC-0010 A1 / RFC-0012 A7. V2 strengthens the finite parameters
and bounds all seeds simultaneously in an ideal random-oracle experiment. The
setup event is independent of any seed-selection algorithm, including quantum
selection. This is not a concrete BLAKE3 guarantee or complete profile bound.
It supersedes v1; raw setup, manifest and block domains all change to v2. V1
bytes reject, including at the unchanged circle base. A4 permits only encoder
implementation; no production setup-distance/profile admission follows.

## 1. Manifest, expansion and rejection

Use the map, degrees, base and raw setup codec in [recursive-code.md](recursive-code.md).
The manifest is exactly 55 bytes: ASCII `stele/expander-seed/v2` (22 bytes),
u8(J), and a public 32-byte seed, with integer 3<=J<=15. Unknown versions,
truncation, suffixes and unsupported J reject as `InvalidManifest`. No caller
supplies a degree, field, modulus, distance, success flag or security budget here.
At J=3 the map is the fixed circle base; the seed is unused. Different manifests
can describe equal maps. This format does not normalize semantic equivalence.

For each row, obtain 32-byte blocks as the unkeyed BLAKE3 digest of exactly:

```
ASCII("stele/v0.1/setup/expander/block/v2") || seed[32] ||
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
false statement. All possible retry seeds are included in the union below.

The fixed circle base has sufficient distance. Across levels j=4..15 the exact
finite analysis supplies two events per relevant support size, each <=2^-416:

```
D_j = floor(4^j/25)+1; I_j = floor(4^j/100)+1
L = sum_(j=4..15) 2*((D_j-1)+(D_j-I_j)) = 200431782
epsilon = L / 2^416 < 2^-388
```

Consequently each independent seed's uncapped tower fails with probability at most
epsilon. This covers all supported prefixes together, not a fresh independent
failure event each time a size/field/proof reuses that seed. The existing component
argument transports M31 minimum symbol distance to QM31/OM31. Neither this bound
nor regeneration establishes proximity, commitment codeword validity or PCS soundness.

## 3. Union over every seed: no selection/query restriction

Fix precisely the v2 domains and the 32-byte seed format above. There are 2^256
possible seeds. For each seed s, let B_s mean that at least one successfully
regenerated supported prefix fails its required support/distance properties.
Section 2's coupling proves Pr[B_s]<=epsilon. Exhausted prefixes are not admitted;
base-only J=3 has deterministic distance and contributes no bad event.

Define B as the union of B_s over this entire finite seed universe. A union bound,
which does not require independence between the B_s, gives:

```
Pr[B] <= 2^256 * epsilon = 200431782 / 2^160 < 2^-132.
```

For every fixed oracle outside B, **every** successfully regenerated supported
v2 code has the asserted distance. An adversary that outputs any such bad code
therefore succeeds only on B. This implication holds pointwise for every classical
or quantum algorithm, arbitrary auxiliary computation, adaptive selection, number
of queries, number of outputs, and reuse. Averaging over the initially sampled
ideal oracle proves the bound. No first-touch argument, quantum query theorem,
prover-declared attempt count or assumption about the selection distribution is
needed. Merely conditioning on a deliberately selected bad oracle would change
the stated experiment and is not what this argument proves.

The cap coupling is per seed; it can use auxiliary infinite streams to analyze
that seed's marginal event without changing the finite block oracle. The finite
union then applies directly to B_s events in the actual capped-oracle experiment.
There is no need to enumerate the seed universe, test all matrices, or evaluate
uncapped streams in the implementation. Extra fields/sizes use the same charged
tower; distinct seeds are already all included. New seed lengths, map versions,
block domains, degrees or accepted code families require a new explicit bound.
For example, allowing 272-bit seeds with this event budget would exceed 2^-128.
The earlier 288-bit per-event budget also fails this all-seed obligation.

`all_seeds_bound()` returns the exact fixed rational above with no caller options.
It is a research arithmetic check, not an admission API. Future consumers must
bind the exact v2 identity and regenerate the actual map, reject arbitrary raw
matrices/v1/unknown variants, and enforce an authenticated parameter registry.
A structurally valid all-zero setup still has distance one: accepting arbitrary
raw setups would violate the theorem's regeneration premise.

The distinction between an ideal random-oracle proof and instantiation with a
concrete hash follows the model described by
[Bellare and Rogaway](https://cseweb.ucsd.edu/~mihir/papers/ro.pdf). The concrete
BLAKE3 implementation and fixed vectors do not establish that assumption. The
all-seed claim is an original elementary application of the finite bound and union
bound here, not a theorem attributed to those authors about this code or BLAKE3.

## 4. Why v1 was insufficient; remaining admission gate

V1 used a classical (Q+S)*epsilon charge. Classical first-touch reasoning does
not cover superposition queries; v2 deliberately avoids that argument. As an exact
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

V2's all-seed argument addresses setup selection in the ideal oracle, not quantum
Fiat-Shamir or hash-collision accounting. Q12's existing 2^100-query H example
already exceeds the treaty target and remains unresolved. A complete bound needs
this setup event plus the actual protocol error with good setup, including FS/H,
proximity, codeword validity and all source bindings. Do not infer independence
between these events or multiply their probabilities. For joint composition, bound
the remaining failure event outside B under its actual oracle model; treating the
oracle conditioned on good setup as fresh independent randomness needs justification.
The union decomposition alone does not supply that missing proof.
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
rejection, actual generated-map parity in all three fields, finite all-seed unions,
budget/seed-length rejection checks, adaptive classical toy selection and the exact
quantum counterexample. The largest generated map is n=1024;
there is no maximum-size, Rust/GPU parity, PCS control or independent-audit credit.
