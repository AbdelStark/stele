# E3-05 bounded streaming delivery review

Reviewer: codex-root, also the author; benchmark-runner, sumcheck-prover-engineer
and soundness-auditor. This is not an independent audit.

Scope: finish the Accepted RFC-0006 A6 / RFC-0014 A1 delivery requirements.
No production algorithm, protocol bytes, challenge, consumer or loss changes here.
The final test addition checks proof rows, outer/final vectors and absorb buffer
pointers/capacities across the actual Streaming bounded call in both fields;
the source already checks arena addresses on every read through transitions.

Acceptance evidence:
- Contract and equivalence: formal/streaming.md; bounded engine and reusable arena
  reviews; exact canonical source, explicit windows and tail contracts on main.
- Production paths: default no_std bounded engine, opt-in std preparation/FileSource,
  actual error/cached-instance/capacity controls and original claim consumption.
- Parity: 1,000 seeded cases per degree and field; schedule boundaries, m=0,
  no inputs, constants, unused inputs, zero/one challenges and suffix contributions.
- Independent oracle: 420 Rust/Python decisions, canonical bytes, every final claim,
  SC fields, continuation and actual source receipts; gate mutants reject drift
  and bypass of the real streaming adapter.
- NC-0210: one unused prepared source value changes; an actual forged Streaming
  artifact reaches the unchanged original consumer and rejects as ClaimMismatch
  in both fields. Catalog coverage remains partial system coverage.
- Complete measurements: both E3-05 ledgers retain every sample from clean source
  c9fd07538ff239462ac87225d4d3221c8ea3f983. Three samples for each of 24 cases per
  field; every subproof is consumed and strategy bytes/continuation match.
  Source/capacity/storage arithmetic and the production ledger validator pass.

Imported ledger JSON values are exactly equal to the native exports; only whitespace
changes to put each complete sample on one line. Export SHA-256:
- QM31: 1c559373f18a54498798951ff3c484ea0867cba38482bf3a5576aa176930add6
- OM31: 60156bd35901a6270dff9c818e19ad9b707b31b2bf595753b8843a48eed75018

The README tables are calculated from these ledgers. Prover buffer/RSS savings do
not lower the complete original-consumer pipeline peak. Every tested streaming
schedule loses on complete time. This simple grid algorithm is a measured memory
tradeoff, not a speedup, fitted global constant or automatic schedule policy.
Native phase peaks include transitions and allocator retention; controller/OS
caches are excluded. Capacity payloads and named inline sizes are separate from RSS.

Challenge order, all A1 final obligations and m*delta/p^d accounting are unchanged.
No static integer certificate is added; no new inference identity is asserted.
Padding/masks, default no_std behavior and weight-pass count remain unchanged.
Q12, private PCS consumers, inference composition, ZK and GPU admission remain open.

I tried to break it by changing one unused source value; NC-0210 rejects the real
forged final with ClaimMismatch. The exporter regression additionally requires
both-field schema acceptance with consumer-dominated costs and complete totals.

Delivery requires local gates and exact-head hosted checks before merge. This
completes the CPU E3-05 task on merge, not the full Stele MVP or treaty profile.
