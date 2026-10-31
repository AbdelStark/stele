# Canonical compact-range replay

Q26/Q31, E5-03; Draft RFC-0004 A3/A6. Before code: do the full-block
restoration and weighted consumers reject a changed unused high byte in
their temporary uint32 value records? Compact ranges may use one or two
bytes, while the temporary files retain four. Re-encoding only the compact
width can discard a changed high byte and leave the compact root unchanged.
Kill this replay path if any stored byte can change without rejection.

The normal verifier writes its private temporary file from completely
verified range openings. No accepted false external proof has been shown.
The gap concerns the promised replay reauthentication and canonical source
representation. Restoration reads the full uint32 during projection, so its
replayed value must equal the range-authenticated value exactly. Weighted
projection may ignore those high digits, but must enforce the same storage
contract rather than silently discard a modified byte.

Tests first mutate each unused high byte for compact widths one and two in
both fields. Exercise the real parent replay with correctly rooted values;
synthetic child states in these arithmetic tests never authorize verify.
Capture complete honest proof states before the fix and require identical
states, accounts and original claims afterward. Add no challenge, loss,
transcript label, source format or capacity change. The check affects only
temporary-source validation in c_x/T_misc; no measured performance claim.

Keep all original full-size processes and logs. Their current maximum
configurations use all four compact bytes; do not restart them. Required
gates for this correction follow the existing gate queue. Production
coverage and original task criteria remain unchanged.
