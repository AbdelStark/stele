# Compact-range replay author review

This is a same-author correction review, not independent audit. No false
external proof admission was demonstrated: these verifiers populate private
temporary files only from complete verified range openings. The replay
contract nevertheless requires authentication of every retained byte.

1. Draft RFC-0004 A3/A6 source/canonicality rules govern both corrected paths.
2. Challenge order, absorbed bytes and transcript labels are unchanged.
3. Every original still uses the same actual-point consumer. The replayed
   word must now fit its compact width, so root equality authenticates its
   entire stored value rather than only its low bytes.
4. The tests-first weighted control failed because replay accepted a changed
   high byte. A separate restoration reproduction changed its projected
   target. All twenty high-byte controls now reject in both fields.
5. No challenge, algebraic loss or lookup account changes. Complete proof
   receipt and state parity is being checked against the captured baseline.
6. Range widths and caps are fixed by expected metadata. The new check uses
   that width before compact re-encoding; no witness selects a bound.
7. Local/global padding and every carry check remain. The correction adds
   an explicit check of the unused high bytes in temporary uint32 records.
8. The check is deterministic integer arithmetic with the same failure reason
   as a changed compact root; valid inputs retain the same proof construction.
9. Both fields passed the new controls. Native CPU/SIMD/CUDA are unchanged;
   no production parity or control credit is claimed.
10. Temporary-source validation in c_x/T_misc gains one bound check per
    value. No benchmark, new weight pass, cut or capacity claim is made.
11. Production no_std code is unchanged. Existing fixed spool lengths, exact
    stream termination and complete child verification remain mandatory.
12. Existing glossary names and original task criteria remain unchanged.

I tried to break it by changing each unused high byte of the spooled values,
and the control for each rejected it after the correction.

The original full-size processes and logs remain intact. Their current
maximum fixtures use all four compact bytes. Complete honest parity and
required gates remain pending; the wider inference goal is still open.
