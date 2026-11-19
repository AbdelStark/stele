# E19-08 selected material implementation

Lane E reviewer `integration_path` reviewed `35d61813` and the correction at
`93faa76f` with the soundness-auditor skill. Accept for balanced development
proofs. The first revision let a factory overwrite its caller's cumulative
local hash observations. The reviewed revision isolates each call, requires
the full Merkle tree on success and limits partial work on failure. Checked
addition preserves earlier counts on overflow.

I tried to break it by substituting the descriptor, root or response, spending
an opening again after a malformed response, and injecting foreign hash work.
The four tests in `cargo test --frozen -p stele-pcs --test selected_material`
passed. The source retains the immutable input and the host derives the row,
mask ranks and lifetime admission. The original transcript and verifier own the
draws, their order, the final claims and authentication. No new challenge,
soundness term, static field identity, virtual column or profile comes from the
storage implementation.
