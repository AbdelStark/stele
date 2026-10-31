# Certificate verification review

Codex-root applied pcs-engineer; a separate read-only soundness-auditor approved
the conditional verifier, controls and gate wiring. This is internal agent review.
Full required repository gates remain queued on the frozen committed head.

- Public verifier/record/handle/failure/ID APIs implement RFC-0010 A9 §§3,9 and
  RFC-0012 A10. Source and Wire getters expose no new authority.
- Expected context precedes weights, canonical t precedes queries, and complete
  ordered responses precede continuation. Full K ratchets preserve rejected draws.
- Only complete verification constructs the private handle and original obligation;
  imports reverify. No unchecked constructor, digest receipt or conversion exists.
- NC-0600/0601/0606/0607/0608/0803 execute both-field native consumers. Query
  controls change one logical index while retaining all honest draw consumption.
- Conditional tensor/query terms and ordinary hash observations are documented;
  certificate replay retains its obligation. No FS/H, cap or profile is evaluated.
- Static source geometry determines all lengths/counts; canonical dimensions
  introduce no implicit padding. Checked allocation and no_std remain.
- Independent full-wire, ID and continuation parity passes in both fields;
  response order and duplicates are deterministic. GPU code is unchanged.
- No original table or authentication callback enters verification. Authentication
  precedes decoding; failures preserve usage and return no handle.
- Usage is hash-only. Full encoder/buffer measurements remain open; no measured
  cost constant or matmul pass count changes. No conflicting glossary term found.

Review ran the certificate tests (768 mutations and 768 truncations), six NCs,
ID-overflow and gate rejection/omission checks. Root also ran both-crate native
suites/doctests, Clippy, workspace/no_std, dependency, catalog and policy checks.

I tried to break it by replacing one query index, deriving one query from stale
state, and supplying authenticated and unauthenticated noncanonical limbs, and
NC-0601, NC-0803, NC-0607, and the authentication-order regression rejected them
for the required reasons.
