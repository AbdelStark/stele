# E12-25a Spec review

Reviewer: Codex, lane C (independent of implementation lane Z), using the
`code-review` Spec axis and repository `soundness-auditor` skill. Reviewed PR #386
at `1651697b4dffee2ffe55f79ccfcfaa9d617d574c`, against
`2358906eb5b6a455d6fbddeaf2d7ea8910d7498a`, plus the working-tree rename from
`reader` to `open_fifo_writer`. The rename has no semantic effect.

Verdict: **spec approved; no findings**. Full integration gates remain the primary
agent's responsibility and were still running when this review was recorded.

## Spec report

No missing or incorrectly implemented requirement found. E12-25a requires
"one stable exclusive sidecar lock before loading commitment or secret state"
and retention "through proving, rollback and durable persistence." Both CLI
callers keep the guard until return, including publication. Reads and atomic
replacement use the returned canonical path; the sidecar is retained. Existing
file and directory aliases resolve to that same owner, and pre-existing hard
links fail closed. File and directory sync and private creation remain intact.

RFC-0013 A6 item 5 says state "is persisted before each proof starts" and a failed
proof "restores the prior state." The existing `prove_next` ordering is unchanged;
ownership now surrounds it. The API and CLI documentation also retain A6's
owner responsibility for copied or restored state. RFC-0026 §8 verifier replay
and typed errors are untouched. No protocol, proof format, challenge, ledger,
committed column or profile change appears in the diff.

No unrequested runtime behavior found. The task-graph status corrections match
already-merged tasks (#342, #343, #348 and #384).

I tried to break it by proving through a symlink, pausing after durable atomic
replacement, and starting competing readers through the original path and file
and directory aliases, and the control `e12-25a-spec-adversarial.py` rejected it.
Every competitor returned exit 2 with `secret state is locked` before reading a
deliberately missing commitment. The symlink survived writeback; the lock inode
stayed stable. After release, indices 0 and 1 both verified against one commitment.

## Observed validation

- `cargo test -p stele-cli --test secret_ownership -- --nocapture`: passed. This
  includes rejection reasons for invalid lock paths, hard links and competing
  commitments, then sequential proofs against the same model pin.
- `cargo test -p stele-ir relation::tests --lib`: all 27 selected tests passed,
  including honest relations and identity, lookup, range and matmul near misses.
- The independent post-persistence attack above passed on disposable private
  state; no seed or secret bytes were printed. Replay:
  `python3 /Users/abdel/dev/stele-validation/e12-25a-spec-adversarial.py`.
- Read author evidence in `e12-25a-cli-red.log` and `e12-25a-cli-tests.log` under
  `/Users/abdel/dev/stele-validation`: before the fix, the competitor published
  index 0; the final process regression passed after the fix. This is additional
  evidence, not a substitute for the independently exercised attack.

## Workflow 03 checklist

1. **Public items:** existing `Persist` and `prove_next` documentation clarifies
   RFC-0013 A6 item 5. New ownership helper is CLI-private; RFC-0026 §8 unchanged.
2. **Challenges/absorbs:** no added or moved challenge or transcript operation.
3. **Claims/consumers:** no added or moved claim; all existing discharge paths
   remain unchanged.
4. **Bindings/controls:** no new proof binding. The process regression and review
   attack test owner exclusion with the stated lock error. Existing NC-0933 and
   NC-0934 cover commitment pin and lifetime budget; not rerun separately here.
5. **Ledger:** no accounting line changes. The primary agent's native/accounting
   gate was pending; no accounting pass is claimed by this review.
6. **Bounds:** no new instance or bound certificate; static validation unchanged.
7. **Padding/masks:** padding unchanged. Exclusive ownership prevents ordinary
   cooperating CLI processes from reading the same counter and reusing its masks.
8. **Determinism:** no map iteration, arithmetic, seed derivation or reduction
   order change; OS scheduling only chooses which command acquires ownership.
9. **Parity:** no CPU/SIMD/CUDA implementation changes; GPU parity not rerun here.
10. **Cost model:** no numerical performance claim or moved arithmetic term.
    The retired risk is simultaneous use of one persisted model index.
11. **Verifier:** untouched, including `no_std`, lengths and failure paths.
12. **Glossary:** no forbidden synonym found.
13. **Tier:** development only; no promotion or security-level claim.
14. **Commit rule:** no column, virtual definition or commitment added.
15. **Plain checker:** ran the 27 relation tests above; honest and near-miss
    behavior remains correct.
16. **Segments:** no relation or segment change.
17. **Proof bytes:** production proof encoding and transcript code unchanged.
    Digest gate delegated to primary integration validation; no repinning needed.
18. **Ladder:** reviewer ran one-layer CLI proof/verify, indices 0 and 1. Full
    L0/L1 pinned checks and native gate were pending with the primary agent.
    No before/after performance comparison is claimed, so no ledger pair needed.

Skipped duplicate full-workspace/native gates and GPU execution. Copied/restored
state and mutation of the live lock namespace remain documented owner duties;
this review does not claim protection against those actions.
