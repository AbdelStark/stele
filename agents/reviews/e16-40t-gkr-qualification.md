# E16-40t masked GKR on Lucid

Job 6781 executed the combined observer at `0a59b594` and exited successfully. Its one
stories42M T32 proof passed a separately built expected-model verifier. Changing the
first digit of the expected model produced the prescribed model-mismatch rejection.
The CPU produced the complete proof. The [GKR component ledger](../../bench/ledger/e16-40t-t32-resident-gkr-h100.json)
pins the public archive, CLI, verifier, proof, public input and individual evidence files.

Replaying every `t32_gkr_*` record reproduced the stage receipt exactly. The H100
matched the original polynomials and compact finals of 383 steps at their transcript
challenges. Steps 96 and 97 exceeded their budgets before admission. Their original
CPU construction and rounds totalled 95.555 s, and both are included in the retained
CPU time. Both attempts are charged. The complete-device memory schedule and the 50
CPU/GPU whole-proof comparisons remain open.

The build interval includes synchronous logging of the child view in the combined
observer. Device transfer counters cover explicit buffer transfers. Cold compilation
and context setup are reported separately. Driver pool highs include the retained
lookup trees. The 40% bound on admitted step allocations alone cannot qualify the
entire prover process.

Lane Z independently reviewed `ee606239` against `acbfb797`. The instrumentation
captures both mixed-field CPU arithmetic branches, each challenge and every compact
final. The reviewer identified the host expansion map for compact leaves as an
additional cost when projecting a device producer. Its creation shares a factor
timer with the CPU reference tables. The ledger retains the full 26.579 s of factor
preparation for the 20 admitted compact leaves as a conservative upper bound for
that cost. The rejected leaf is already covered by its full CPU time.

The GPU and CPU durations in this report concern the same job and proof as the
E16-40v combined receipt. Only the approved lane-stack CI can qualify a merge.
