# Native certificate production

`PreparedSource::certificate` implements RFC-0010 A9 §3 over the immutable M31
message and prepared column tree. It binds the source before drawing row
weights, forms the MSB-first weighted row, absorbs that row before column
sampling, copies each full response in draw order, and absorbs the complete
response block. Repeated queries retain repeated payloads and paths.

The output is unverified wire bytes. No native verifier, certificate ID, handle,
opening or negative-control credit is introduced here. The four certificate
labels land with this real producer; the other five A10 labels remain absent.

The six independent fixtures cover QM31 and OM31, R=1 with no row draw, and
nontrivial MSB coordinates at both code rates. Native tests compare every wire
byte, repeat the call for determinism, and compare a real continuation challenge
with an independently regenerated value after final response absorption.
The existing full-wire fixture digest is unchanged:
`4e5327828a8fe47f4b44537278f550e6231da0415022474110b56d6113a8b7ed`.

The capped sampler tests all 30 supported domain sizes at their thresholds,
63 rejects followed by a successful 64th attempt, 64 rejects, invalid domains,
outer overflow, inner accounting failure and full-field ratchet parity in both
fields. Each attempted column draw is counted before its full K challenge.

The returned usage is hash-only. Preparation has its own observed hash work;
copying responses performs no new Merkle hashing. Failure retains all transcript
work after construction and returns no proof or continuation. Full owned-buffer,
encoder, runtime and proof-size ledger evidence remains E4-03a work. This slice
changes no measured cost-model constant, matmul pass count or profile budget.

Focused validation: both-crate native tests and doctests, seven gate regressions,
Clippy, workspace/no_std checks, dependency policy and scaffold tests. Full
repository gates are queued on the frozen committed head. Native verification,
malformed-proof rejection and the required query-binding controls belong to the
next consumer change; all original task acceptance criteria remain intact.
