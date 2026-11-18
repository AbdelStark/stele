# E20-10 development-tier field backend contract

Codex-source-visits, lane Z, reviewed draft `806b7f74` against main
`0874019f`. The ordinary batch's dense coordinate order, face and weight
geometry, claimed-sum check and two finals agree with the existing A5
consumer. The reviewer traced the A4 transcript and source opening
authority through the normal proof entry and checked the field-only
dependency direction, hardware parity and 50 complete byte-pair gate.

The initial draft allowed source identifiers and dimensions to recur on a
shared device between attempts. The reviewer required a separate proof
session, an immutable authenticated input chosen by the caller and a
same-id/same-extent stale-owner control. The reviewer accepted the
amended contract at `3b69ddb4` after checking this change. This review
covers RFC-0014 A2, RFC-0020 A10 and RFC-0026 A19.
