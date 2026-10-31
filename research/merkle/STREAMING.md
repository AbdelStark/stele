# Streamed source roots

Question Q26/Q31, E5-03. Before code: can root-only source commitments retain
the exact RFC-0012 A3 bytes while accepting a single-pass payload iterator and
keeping only a logarithmic digest frontier? The weighted attention study must
eventually consume all source entries in a block. Materializing every Merkle
level is unnecessary when the revealing consumer needs only the source root.

This is an implementation of Accepted RFC-0012 A3. Descriptors, leaf order,
present/absent tags, padding and node coordinates remain unchanged. It adds no
commitment, challenge, cut or proof authority. `build` remains the independent
stored-tree reference and still supplies authentication paths. Only the
research lookup root-only call switches to the streamed builder. Native hash
code, public interfaces and production coverage remain unchanged.

For P=next_power_of_two(n), both constructions hash P leaves and P-1 internal
nodes. The candidate keeps at most h+1 frontier digests, h=log2(P), instead of
all 2P-1 tree digests; transient hash inputs and caller payloads are additional.
This changes temporary research commitment storage in c_c/T_cuts and T_misc,
without changing the hash work or a measured constant. No throughput or
process-memory result is claimed without a benchmark ledger.

Kill the candidate if any canonical root differs, a short/long stream or wrong
payload width is admitted, a changed root authenticates an existing path, a
complete lookup proof changes bytes/state/accounting, or a second input pass
is required. Tests precede code: ten existing Merkle vectors; 10000 seeded
descriptor/payload cases against `build`; power-of-two boundaries through
131073 leaves; malformed streams; both tree kinds; four complete lookup
proofs across QM31/OM31 and repetitions one/two with frozen baseline digests.
Each complete proof retains its source consumers and source/root controls.

The frontier merges a completed right subtree with the immediately preceding
left subtree while the current node index is odd. At each merge, its parent
level and index match the stored-tree reference. Explicit absent leaves finish
the next power-of-two tree. Exact EOF is required before a root is returned.

This helper does not enlarge the weighted source consumer or establish model
ownership. Continue with complete streamed source ranges, the canonical flat
four-plane root and one degree-two sumcheck over all key rows, with every
actual source claim consumed. Full attention composition, native/private
PCS/ZK/FS, GPU parity, fidelity and independent audit remain required. Original
task status and acceptance criteria stay blocked.

Before implementation, the corrected test harness failed because `root` did
not exist. The initial harness import error was fixed first. The four complete
lookup proofs then passed against the unchanged stored-tree implementation at
base `ff0f005e87d283d4d2fb8fbce172216b0eda5322`; their proof/root/receipt
digests are frozen in `streaming-proof-digests.json`. A wrong expected root
rejected at FinalEvaluationMismatch; the test's original expected diagnostic
was corrected before capture. Actual source mutations rejected at
CommitmentMismatch. No verifier code changed during baseline capture.
