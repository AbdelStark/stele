# Canonical Merkle authentication candidate

Question Q16: which exact bytes and shape make E2-02 interoperable? Security at
stake: byte payload, position, descriptor and child-root authentication. Cost
terms: c_c/T_cuts and authentication/T_misc; no timing measurement or fitted constant.
Kill criterion: any altered payload/path accepted at a fixed root, ambiguous
framing, unbound index/shape, padding opened as data, or incomplete batch accepted.

Method: pinned Python BLAKE3 backend, bottom-up construction and independently
reconstructed authentication paths. The script checks both kinds, n = 1,2,3,5,8,
full batches, equal payloads, one-byte payload/root changes, each sibling change,
wrong indices, tree ids, kinds, counts, widths, lengths and malformed batches.
The committed ten vectors contain descriptors, payloads, roots and every path.
Execution: `uv run --locked --script research/merkle/check_merkle.py`.
Result: 38 honest paths and 498 rejection cases pass. This is candidate-byte
validation, not a production verifier/control, hash collision theorem or PCS test.
The oracle uses the same official hash implementation family as Rust; the framing
and tree logic are separate. Regeneration uses exclusive `--write-vectors` output.

The chosen baseline pads to the next power of two with explicitly absent leaves,
includes the real count in every frame, and refuses openings of padded positions.
A kind-2 tree hashes child roots as typed leaves. Full individual paths make the
batch contract unambiguous; compressed multiproofs are outside E2-02's baseline.
Canonical field decoding remains a PCS consumer obligation: authenticating bytes
alone does not establish that they encode valid field elements or a codeword.

Binding argument: two accepted, different values at one descriptor/index/root
must converge at a common digest after hashing distinct framed inputs. Thus a
forgery against a previously fixed honest commitment yields an H collision.
This conditional reduction does not prove BLAKE3's security or settle Q12's
aggregate hash/Fiat-Shamir budget. Honest padding is deterministic; membership
does not prove that unqueried subtrees were constructed canonically.

References inspected: [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs)
for the hash definition; [RFC 9162 §2.1.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.1)
for the leaf/internal domain-separation rationale. Its unbalanced tree shape is
not adopted; no theorem or byte compatibility with Certificate Transparency is claimed.

Recommendation: amend RFC-0012 with A3, complete the required skill reviews, then
implement E2-02 against these bytes with registered production NC-0602. No core
imports research code. The research cases must not change catalog status.

Review finding Q17: E4-07's 1-versus-N-shard digest criterion needs a canonical
logical partition or an explicit amendment. Hashing different root lists cannot
be claimed to preserve a digest. A3 authenticates the fixed list only; no
partition-independent or distributed parity claim is made.
