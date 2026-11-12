# dev-zk sources: balanced geometry and Policy 2 (design note, task E12-28)

Status: design note for RFC-0013 A8 (Proposed). Nothing here is implemented. It reads
`formal/zk-development.md` (§3, Lemmas 1–3), RFC-0013 A2, A5 and A6, RFC-0010 A14/A15,
RFC-0026 A9 and A11, and RFC-0012 A17.

## 1. Where the 141 MB goes

The eight-layer dev-zk proof (T = 64, P = 8; E16-24 after-run, 141,745,010 bytes) by
section, from `claims::decode` of the proof:

| Section | Bytes | Share |
|---|---|---|
| witness source (0): certificate | 67,380,161 | 47.5% |
| witness source (0): opening | 67,221,185 | 47.4% |
| shared claims source (3): certificate + opening | 4,506,882 | 3.2% |
| weight source (1): certificate + opening | 993,154 | 0.7% |
| top source (2), A4 mask source | ~0.5 MB | 0.4% |
| masked sumchecks (797 relations, 336 GKR steps, batches) | ~1.1 MB | 0.8% |

Every dev-zk source is already a Circle source at rate 1/4: an RFC-0010 A15 hiding source
with blow-up exponent 2 (`zk::BLOWUP = 2`). None is an expander source. What differs from
RFC-0026 A11's development sources is the following:

1. **Geometry.** Every claim source except the lifetime source has the least row
   count A2 allows, `R = 2D = 8` data rows (`ell = 3`), and grows its columns. The
   witness source holds `2^24` entries as `8 × 2^21`. The source sends `M'`'s
   combined row (`2C` values of `K`) once in the certificate and once in the opening:
   `2 × 16 × 2^22` bytes = 134.2 MB. Its query responses are 0.38 MB.
2. **Policy.** Hiding sources resolve RFC-0010 A3 Policy 1, with `q_c/q_o = 314/130`
   at `b = 2`. A14's Policy 2 needs 222/92 there, with 16-bit column grinding.

The geometry is the 20× lever; Policy 2 adds about 1 MB.

## 2. Proposal

1. **Balanced geometry.**
   - Each claim source of `2^S` data entries takes the `ell` that minimises its bytes
     `(1 + J)·16·2C + (q_c + J·q_o)·(4·2R + 32·log2 N + 32)`, with `R = 2^ell`,
     `C = 2^(S−ell)` and `N = 8C`. `J` is the number of openings per proof: 1.
   - It does so subject to §3's constraints; ties take the smallest `ell`.
   - The verifier derives `ell` from the statement as today; no proof byte chooses it.
2. **Policy 2 on every dev-zk source.** Claim, lifetime, shared and A4 mask sources
   carry policy byte 2 with A14 items 2–4. The counts are resolved as the
   development profile (`proven: false`), as RFC-0026 A11 item 3 does. The A4 mask
   source keeps its fixed `2D`-row shape.
3. **Profile byte 4: dev-zk on A8 sources.** RFC-0026 A9's tag gains the value 4.
   Byte 1 (A5/A6/A7 sources) keeps verifying unchanged.
   - The public file is `stele-dev-zk-public-v2`.
   - The model commitment file is `stele-dev-zk-model-v2` and records the profile
     byte. The lifetime source's geometry and policy change its root and blocks, so
     a byte-1 commitment cannot serve byte-4 proofs, and the reverse; `verify-dev`
     rejects a mismatch (`StatementMismatch`).
4. **No level is claimed.** As RFC-0026 A11 item 4: Policy 2 is a size and speed
   choice; each grinded PCS round is `≤ 2^-108` (A14 item 5) instead of `≤ 2^-130`,
   the worst round stays the ungrinded LU round, and nothing is summed into a level.

Projected source bytes on the eight-layer window (`research/zk-sources/zkgeom.py`, which reproduces the
measured 140.4 MB of sources at the current geometry to 0.1 MB):

| Source (`2^S` entries) | Now: `ell`, bytes | Balanced, Policy 1 | Balanced, Policy 2 |
|---|---|---|---|
| witness (S = 24) | 3, 134.60 MB | ell 9, 4.19 MB | ell 9, 3.57 MB |
| weights, lifetime (S = 19) | 6, 0.99 MB | ell 7, 0.94 MB | ell 7, 0.74 MB |
| top (S = 12) | 3, 0.25 MB | ell 3, 0.25 MB | ell 3, 0.18 MB |
| shared claims (S = 19) | 3, 4.51 MB | ell 7, 0.94 MB | ell 7, 0.74 MB |
| total sources | 140.3 MB | 6.3 MB | 5.3 MB |

With the sumchecks and the A4 mask source the proof would be about 6.6 MB, against
141.7 MB. This is a projection, not a measurement; the ledger of the implementing task
measures it. The verifier also gets cheaper: it encodes each combined row, and the
witness row shrinks from `2^22` to `2^16` values.

## 3. The hiding argument at the new geometry

A2's privacy statement (design note §3) rests on four conditions. Each is checked here
for balanced Circle sources at `b = 2` under Policy 2.

1. **Lemma 1 (column privacy).** It holds for every blow-up `b` and every `m`
   whenever the lifetime union `Q` of queried positions has `|Q| ≤ C − 1`. The proof
   uses only Bézout on the circle and the interpolation basis; `ell` does not
   enter. Constraints:
   - per-proof source: `q_c + q_o ≤ C − 1`, that is `314 ≤ C − 1` under Policy 2
     (`C ≥ 2^9`);
   - lifetime source (A6): `q_c + P·q_o ≤ C − 1`, `222 + 8·92 = 958` (`C ≥ 2^10`).

   Every balanced choice in §2 satisfies these with room to spare: the witness has
   `C = 2^15`. Policy 2 lowers `q`, so these constraints are weaker than today's.
2. **Lemma 2 (joint linear view, rank check).** It needs the mask-row parts of the
   revealed row combinations to have rank `D·(messages)`. That requires `R ≥ 2D` for a
   per-proof source and `R ≥ (P + 1)·D` for the lifetime source. Balancing raises `R`,
   so the rank check has more slack and the `MaskRank` abort, which depends on public
   challenges only, is rarer. The A4 mask source keeps `R = 2D`.
3. **Lemma 3 (salted leaves).** One uniform 32-byte salt per codeword position, from
   the source-salt stream. It is independent of geometry; there are fewer, wider
   leaves.
4. **Grinding nonces (new).** Policy 2 adds, per certificate and opening column
   round, a public `u64` nonce before the column draws, and per certificate a tensor
   nonce before `t_bytes` when `k_t ≥ 1`.
   - **Determinism.** The prover's nonce is the least `n` passing the A17 predicate
     on the current transcript state `S` (`Transcript::grind`). `S` is a function of
     the public proof prefix, so the nonce is a function of public data: it adds no
     information to the view, and a simulator recomputes it (expected `2^k` hashes)
     or programs the random oracle.
   - **Adaptive queries.** The column draws now depend on the nonce. They are still a
     function of the public prefix, and Lemmas 1–2 hold for every fixed `Q` with
     `|Q| ≤ C − 1`. So the hybrid of A2 (fix the public prefix, then the opened columns
     are `X`-independent) goes through unchanged.
   - **Requirement.** The nonce must not depend on any secret. A search started at a
     seed-derived offset, or a prover that retries masks until some nonce property
     holds, would break the argument above. A8 states "least nonce" as a producer
     rule, and a unit test pins that dev-zk hiding sources grind through
     `Transcript::grind`.
   - **Timing.** The time spent grinding depends only on `S`, which is public.

Conclusion: A2's conditional, computational hiding statement carries over to balanced
Policy 2 sources with the constraints of items 1–2 and the least-nonce rule of item 4.
No lemma needs a new proof; Lemma 1's query budget and Lemma 2's rank budget are
re-instantiated with the new `q`, `C` and `R`.

## 4. Implementation plan (after #353 lands; not started)

1. `stele-pcs`: hiding sources and preparations with an explicit policy, resolved for
   development, and the grind rounds on the hiding certificate and opening paths
   (shared with A9/A14).
2. `stele-reductions::zk::claims`: per-source `ell` by §2's cost rule, and
   `lifetime_shape` under Policy 2.
3. `stele-prover`/`stele-cli`: profile byte 4, `stele-dev-zk-public-v2`,
   `stele-dev-zk-model-v2` with the profile byte, `prove-dev --zk` producing byte 4,
   and byte 1 still verified.
4. Tests and controls:
   - pinned byte-4 proofs (one and eight layers);
   - the χ² privacy tests and the eight-layer bare-evaluation test on byte 4;
   - Lemma 1's rank check at the new `(m, b)`;
   - least-nonce pin;
   - controls for a grind mismatch on a hiding source, a byte-1 commitment used
     under byte 4, and a wrong profile byte.
5. Ledger: the eight-layer window, byte 1 against byte 4, three runs each.
