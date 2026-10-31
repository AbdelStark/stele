# Merkle roots and a fixed field oracle

Question Q27: does RFC-0012 A3 authentication justify the fixed complete
field oracle assumed by the PCS proximity argument, when a malicious root
has missing subtrees or noncanonical leaves? The security property is
consistency with one oracle fixed before the certificate row challenges.
The relevant costs are column authentication and certificate work in T_misc.

Kill criterion: an accepted canonical column differs from the frozen
completion without a recorded hash collision or a later query hitting a
frozen unresolved digest. A collision-only argument is insufficient if a
root was chosen before any corresponding hash query.

This study uses a classical random-oracle query log for the proof argument.
The real verifier receives neither that log nor the complete source table.
It authenticates each requested column and rejects malformed field bytes.
Zero completion is a mathematical definition, never a verifier fallback.
The study does not justify a quantum query log, instantiate Fiat-Shamir,
admit a profile or establish knowledge of an external model.

The [formal argument](../../formal/merkle-field-oracle.md) charges collisions
and later preimages of frozen unresolved digests separately. The latter
term covers roots chosen without a queried preimage, including one-leaf
trees. Adaptive reuse retains the first completion for the same context.

Run `uv run --locked --script research/merkle-oracle/check_lifting.py`.
The tests-first run failed at the missing lifting module. The implemented
checker passes 15 actual BLAKE3 trees and 57 paths against the existing
RFC-0012 A3 reference, including non-power-of-two trees and repeated queries.
Missing leaves, malformed fields, wrong context and wrong levels exercise
the accepted-opening containment boundary. These are research controls,
with no production NC-0600..0605 credit.

Two symbolic controls isolate a late preimage without a collision and an
actual collision. Separate seeded eight-bit lazy-oracle cases find a late
preimage after 16 and 18 new leaf inputs for partial and one-leaf trees,
with no collision in either recorded history. These demonstrate why the
two bad events differ; they are not attacks on BLAKE3 or estimates of a
256-bit failure probability. The general bound follows from the argument,
not from finite samples.

Recommendation: retain Draft RFC-0010 A8 while completing the exact native
consumer contract. Both profiles remain unavailable from this result.
