# Native field-source bytes and wire parsing

The first E4-03a slice implements RFC-0010 A9 source context, fixed policy
and unverified certificate/opening parsing in stele-pcs. It authenticates no
root and exposes no certificate verifier or verified-certificate constructor.

Source construction uses the existing Circle factory and sealed QM31/OM31
challenge types. The 105 source bytes match all six independent fixture cases.
The native policy exporter checks N,D,e and both least query counts against
independent integer arithmetic for all 59 Circle identities. Source dimensions
and every proof-size product are checked before any allocation or execution.
The maximum shape test computes its size without allocating the domain.

The parser borrows the complete input, requires its exact version and length,
and rejects every noncanonical row limb. Its response iterator preserves
duplicate draws and order. Column bytes remain unauthenticated; the eventual
consumer must authenticate each response before field decoding. Neither parsed
bytes nor public parameter metadata are verification receipts.

Run `cargo test -p stele-pcs --locked --offline` and
`python3 research/merkle-oracle/check_native_policy.py --native`.
The tests-first run failed at the absent API. Four native tests cover the
both-field corpus, malformed wires, unsupported sources and maximum dimensions;
two compile-fail checks reject a base-field challenge and an absent verifier API.

The PCS gate now runs the actual native parser, independent policy and full
Python wire corpus. A closed declaration inventory rejects an extra accepting
method or trait conversion inside the existing source module, as well as new
files, exports or dependencies. This is a narrow regression guard, not a Rust
semantic sandbox. Existing unrelated scaffold guards remain in place.

No challenge, PCS accounting producer, control credit or performance result is
added. Registration, certificate and opening verification, all-original native
RFC-0006 A1 closure, full resource measurements and the rest of E4-03a remain.
