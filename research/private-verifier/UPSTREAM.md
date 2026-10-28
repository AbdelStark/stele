# Pinned Stwo privacy inspection for Q30

Scope: source inspection, not a backend audit, security theorem, benchmark or
Stele integration. The original [Stwo repository](https://github.com/starkware-libs/stwo)
directs development to `starkware-libs/proving`. The inspected commit there is
`3a396f51036e91f17d694a5523bc064782dd9ddf`; all file links below pin that commit.
No upstream implementation is copied into the core or admitted by this note.

## Entry points and public boundary

The [workspace manifest](https://github.com/starkware-libs/proving/blob/3a396f51036e91f17d694a5523bc064782dd9ddf/Cargo.toml)
includes privacy proving and verification crates. In
[privacy_prove/src/lib.rs](https://github.com/starkware-libs/proving/blob/3a396f51036e91f17d694a5523bc064782dd9ddf/crates/privacy_prove/src/lib.rs),
`privacy_prove` runs the privacy bootloader and serializes a Cairo proof.
`privacy_recursive_prove` additionally constructs and proves the verifier computation.
The paths have distinct public verifiers; their names do not establish identical
privacy guarantees. Source inspection alone establishes neither path's complete
simulator, extraction loss or compatibility with the Stele statement.

[privacy_circuit_verify/src/lib.rs](https://github.com/starkware-libs/proving/blob/3a396f51036e91f17d694a5523bc064782dd9ddf/crates/privacy_circuit_verify/src/lib.rs)
returns proof bytes and an `output_preimage`. The direct and recursive verifiers
derive their output digest from that preimage. The recursive path selects a
configuration through a recognized preprocessed root and rejects trailing proof
bytes. A Stele adaptation must bind exactly the approved verifier, public
statement and parameters, and audit all public output/preimage fields. These
observations are not evidence that a Stele verifier has been arithmetized.

## Parameters and masking mechanism

[cairo_verifier/src/privacy.rs](https://github.com/starkware-libs/proving/blob/3a396f51036e91f17d694a5523bc064782dd9ddf/crates/cairo_verifier/src/privacy.rs)
explicitly targets 96 bits through these parameter choices:

| log blowup | proof-of-work bits | queries | configured arithmetic sum |
|---|---|---|---|
| 1 | 26 | 70 | 96 |
| 2 | 26 | 35 | 96 |
| 3 | 27 | 23 | 96 |

The last column is `pow_bits + queries * log_blowup`, the arithmetic checked
there. It is not a derivation of a complete FRI/STARK error, extraction bound,
quantum bound or grinding budget. The
[privacy verifier constants](https://github.com/starkware-libs/proving/blob/3a396f51036e91f17d694a5523bc064782dd9ddf/crates/privacy_circuit_verify/src/consts.rs)
use the third configuration for Cairo and the second for the recursive proof.
Stele requires total error <=2^-100 or <=2^-128 with its own adversary/resource
model. Neither profile follows from an upstream target of 96, nor by changing
only the target number without the full applicable theorem and implementation.

[cairo_verifier/src/verify.rs](https://github.com/starkware-libs/proving/blob/3a396f51036e91f17d694a5523bc064782dd9ddf/crates/cairo_verifier/src/verify.rs)
has an optional `zk_blinding_amount`, counts non-query leakage, and invokes
blinding on the finalized verifier computation when enabled. Its seed is derived
from the inner `proof.trace_root`. In
[circuit_common/src/finalize.rs](https://github.com/starkware-libs/proving/blob/3a396f51036e91f17d694a5523bc064782dd9ddf/crates/circuit_common/src/finalize.rs),
`add_zk_blinding` uses a ChaCha20 generator to add rows to several components.
This is actual masking code, not merely an advertised feature.
It is also not an independently verified simulator for all public messages.
Seed secrecy, entropy, repeated use, field sampling, all disclosed linear
combinations and the exact selected path need the applicable joint analysis.
No upstream privacy attack is established by these observations.

## Admission consequences

The complete Stele relation in [the formal note](../../formal/private-verification.md)
still needs a backend-specific quantitative argument of knowledge, simulator,
compiler/constraint correctness, authenticated program/configuration, hash/FS
composition and full native cost evidence. The repository's existence supplies
none of those Stele-specific results. The code is a concrete candidate for
further investigation, not a reason to claim the wrapper is absent or complete.

Inspected file blob identifiers (Git object identities, not theorem versions):

| file | blob |
|---|---|
| workspace Cargo.toml | 937957cf6b4355e30f560f4558c9a680a54ce2a3 |
| privacy_prove/src/lib.rs | 8b84fb186522a748fb5d4716ada10faead9d26b4 |
| privacy_circuit_verify/src/lib.rs | b09b0d0cf80b6ae9e4c792d636716399c8f54377 |
| privacy_circuit_verify/src/consts.rs | 846f418fe4411602a28690493b35c8c3739c5c70 |
| cairo_verifier/src/privacy.rs | 48935b5ebc2bea0e299dd756837f4490e8d6c493 |
| cairo_verifier/src/verify.rs | aa100d440b35c6f18846521529481bf0afb74987 |
| circuit_common/src/finalize.rs | bdcbed0098c9f6ba10b115f27fa7d3ddfcab9a8a |
