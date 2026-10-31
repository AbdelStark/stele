# Fixed field oracles from partial Merkle trees

Status: Accepted, RFC-0010 A8 and question Q27. This is a classical ideal-hash
argument for the authentication premise of [certified openings](certified-functional-opening.md).
It does not instantiate BLAKE3, Fiat-Shamir, quantum queries or a profile.

## 1. Model and fixed context

Let H map arbitrary finite byte strings to independent uniform lambda-bit
outputs, with lambda=256 for the specified transport. Count every distinct
full-input call by the adversary and verifier, across all domains sharing H.
Repeated input calls return the same value. Hash evaluation has no hidden
unlogged channel. These are classical random-oracle hypotheses, stronger
than merely asserting collision resistance of an implemented hash.

Before any fresh certificate row challenge, fix the expected root and its
complete context: RFC-0012 A3 descriptor, exact code identity, base and
challenge fields, dimensions, coordinate order and source interpretation.
Use column leaves of exactly 4R bytes, with R canonical u32le M31 values in
row order. The later verifier authenticates the expected index and invokes
canonical field decoding. Payload length, path length, absent-index and
noncanonical-field errors reject; none supplies a zero column.

For the first Circle PCS contract N is a power of two. The lemma also
covers real columns of a non-power-of-two tree, but does not establish that
unqueried absent padding was constructed canonically. Logical zero padding
inside the real message remains a separate source relation.

## 2. Frozen completion

Freeze the hash log when this root/context is first fixed. On a
collision-free prefix, each recorded output identifies at most one input.
Starting at the expected root, look up that input and parse it only as the
exact descriptor/level/index frame for the current tree position.

- A matching internal-node frame fixes its two child digests; recurse.
- A matching real-leaf frame with canonical field bytes fixes that column.
- An unknown digest starts an unresolved subtree. Set its real columns to
  zero and record that digest in the frontier F.
- A known input with wrong framing or malformed field bytes closes that
  subtree with zero columns. It is not an unresolved target: a distinct
  acceptable input giving its digest would already be a hash collision.

This defines one complete W in F^(R by N), embedded in K, before the row
randomness. Define W arbitrarily if the prefix already contains a collision;
that case belongs to the bad event below. Neither W nor the query log is
computed or supplied by the real verifier. The proof device gives no
efficient knowledge extractor and no commitment to an external model.

At most one initial root and two child digests per recorded internal-node
input can enter F. For Q_pre distinct calls in the frozen prefix,
`|F| <= 1 + 2*Q_pre` is a conservative bound. Correct frame positions stop
one logged internal node from being expanded at unrelated positions.
The explicit one covers a height-zero root with no recorded preimage.

## 3. Authentication containment and bad events

Let BadCollision mean that two distinct full inputs ever receive the same
output. Let BadLate mean that a new post-freeze input receives an output
in F. A real accepted canonical opening at index c equals W[:,c] outside
these events.

To see this, follow its authenticated path downward from the root. At a
known node, absence of a collision forces the exact recorded preimage,
and hence the same child digest. A wrong-context or malformed known node
cannot be repaired by another preimage without a collision. At an
unresolved frontier digest, a successful path supplies a new preimage
that hits the frozen target, so BadLate occurred. Otherwise the traversal
reaches the same known canonical leaf and obtains its fixed value.

Missing responses and malformed fields still reject even when their
mathematical completion is zero. Thus real acceptance implies acceptance
of all the corresponding equations against W; the converse need not hold.
A producer can always refuse to reveal a column. Availability is not a
consequence of this consistency statement.

For deterministic total query bounds Q_total and Q_after, lazy sampling
and a union bound give

```
epsilon_lift <= min(1,
  [Q_total*(Q_total-1)/2 + (1+2*Q_pre)*Q_after] / 2^lambda).
```

The first term counts collisions among all calls. The second counts new
outputs hitting a target set fixed at the freeze. It cannot be deleted:
an unqueried chosen root may acquire a first preimage later without any
two recorded inputs colliding. Repeating an existing query supplies no
new probability trial. The tiny-output controls exhibit both cases.

For adaptive distinct root/context registrations, fix a deterministic
registration cap R_max and query caps before execution. Retain each first
freeze and charge the conservative lifetime bound

```
[choose(Q_total,2) + sum_(r=1..R_max) (1+2*Q_pre,r)*Q_after,r] / 2^lambda,
```

capped at one, summing over every permitted slot even if fewer are used. Equivalently,
fix a deterministic B that bounds the total frontier exposure on every
allowed execution, and use `[choose(Q_total,2)+B]/2^lambda`. An unbounded
or realized random registration count cannot define that probability bound.
The caps are assumptions of the resource-bounded analysis, never authority
from prover-reported measurements. Overlapping frontiers may be counted more
than once. Replaying or recertifying the same root/context retains its
first W; it does not re-freeze a more convenient completed tree. Fresh
certificate attempts still incur their own algebraic failure terms.

## 4. Composition with the proximity argument

Apply [Diamond-Posen Theorem 2](https://cic.iacr.org/p/1/1/2/pdf) only to
the fixed W and fresh independent interactive row challenges. The separate
near-matrix and query arguments in certified-functional-opening.md then
apply to every accepted column equation. Real false acceptance is contained
in BadCollision, BadLate, or false acceptance in that fixed-oracle protocol.
Add epsilon_lift to its certificate, opening and batch terms.

Do not condition on the absence of future bad hash events and then assume
the row/query randomness stays uniform. Use event containment and the
unconditional fixed-oracle argument for each frozen history. Hash queries
made after the row challenge are included in Q_after.

No classical log is available for coherent quantum queries. This proof
therefore does not establish the quantum or Fiat-Shamir composition
required by Q12. Existing H/FS placeholders are not replaced or zeroed.

## 5. Native interface obligations

An eventual consumer takes an expected root/context from the source owner.
It rejects proof-selected replacement roots or field decoders. The cache
key includes the exact context, certificate bytes and parameter policy;
only successful complete verification may populate a typed cache entry.
Cache reuse does not erase the certificate's lifetime error. Certificates
for other code IDs, layouts, fields or roots cannot supply source authority.

Sample columns after the full u and statement are fixed. Preserve every
draw with replacement. A wire format may authenticate sorted unique leaves
once only if the verifier derives the exact draw-to-leaf mapping; no missing
draw, changed index or proof-selected deduplication is allowed. Keep each
separate row/group equation, including zero-coefficient originals.

This study does not yet specify the native statement/certificate/opening
wire, registered challenge schedule, unbiased sampler, capacity limits or
source-claim adapters. Those are required before native code or A3 admission.
Its first use is the field-valued Circle source consumer from the native
closure plan. Packed integers, literal fused u=B, privacy and model ownership
retain their separate contracts.

The log traversal and materialized W are proof devices, not verifier costs.
Actual costs still include u decoding and scalar checks, coefficient
generation, encoding/eval_row, authenticated columns, paths and cache state.
No measured constant, extra weight pass or benchmark result is claimed.
