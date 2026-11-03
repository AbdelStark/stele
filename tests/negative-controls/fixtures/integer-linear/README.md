# Frozen RFC-0024 comparisons

The corpus retains 270 distinct public requests and their complete independently
computed results. Its 278 named entries cover 28 positive compositions, 20
accumulator/cap cases, 32 continuation cases, 74 import-order cases, 112 native
control packets and 12 earlier control-prefix cases. Shared requests appear once.

`provenance.json` preserves the original execution receipts, source identities
and raw artifact hashes. Their historical status and scope remain unchanged.
Packaging checked full native/reference equality again; it did not rerun the
reference campaigns. The manifest separately pins the transitive oracle source
definitions present when the evidence was packaged.

`corpus.zip` shares repeated packet chunks losslessly. `chunks.bin` contains a
little-endian u32 length followed by the chunk bytes; each chunk has at most 1024
bytes. In `rows.jsonl`, request fields ending in `_hex` hold ordered chunk
indexes. The decoder concatenates their bytes and restores the hexadecimal
string. Expected results remain ordinary JSON. Every reconstructed request and
result must match its manifest digest.

The native gate regenerates all 28 positive proofs, comparing their complete
requests, producer Usage and verification results. It then imports and consumes
all 270 requests through the current closed native adapter, comparing every
record, import, failed-prefix Usage and continuation with the frozen result.
The actual ProverHook controls remain mandatory separate native tests. Frozen
replay adds no control count or resource, profile, privacy or inference credit.
