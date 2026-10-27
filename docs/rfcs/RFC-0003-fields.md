# RFC-0003 — Fields

Status: Accepted · Version: 0.1.0

## 1. Base field `F = F_p`, `p = 2³¹ − 1` (Mersenne-31)
Reduction is one add-with-carry; multiplication is one 32×32→64 and a reduction; 32-bit lanes on CPUs (AVX2/512,
NEON) and GPUs (native `mul.lo/hi.u32`). Representation: canonical `[0, p)`; a lazy `[0, 2p)` representation is
allowed inside kernels with a `// INV: lazy` comment and a final reduction before hashing or serialisation.
Signed integers `z ∈ (−p/2, p/2)` embed as `z mod p`; recovery is `v < p/2 ? v : v − p`.

## 2. Extensions
- `CM31 = F[i]/(i²+1)` (degree 2; `p ≡ 3 mod 4` so `−1` is a non-residue).
- `QM31 = CM31[u]/(u² − (2+i))` (degree 4, 124 bits) — **the challenge field K**. Multiplication ≈ 9–12 M31 mults (Karatsuba over CM31); base×K ≈ 4 mults.
- `OM31` (degree 8, 248 bits) — optional, for the treaty-profile LogUp challenge when the octic option is chosen (RFC-0019 R-OCTIC). Same tower construction; must be irreducible — the quantiser's CI test verifies irreducibility of the chosen modulus.
- Serialisation: little-endian limbs, base elements first.

## 3. Why M31 and not a 2-adic 31-bit prime
Arithmetic is ~1.3–1.5× faster than BabyBear/KoalaBear on the same lanes, and Stele needs no 2-adic FFT on the
per-proof path (RFC-0010 §3). The circle group `x²+y²=1` of order `p+1 = 2³¹` provides a smooth domain for the
*one-time* Reed–Solomon encoding of weight commitments (Haböck–Levit–Papini 2024). Linear-time codes (RAA/expander)
need no structure at all.

## 4. Integer-faithfulness bounds
Every arithmetic identity `Σ_k a_k b_k = c` proven in `F` is meaningful as an integer identity only if
`|Σ_k a_k b_k| < p/2`. Rules (enforced by the CQIS bound certificate, RFC-0004 §6):
- int8 × int8 with inner dimension `d`: need `2¹⁴·d < 2³⁰` ⇒ `d ≤ 2¹⁶`. Llama-405B: `d = 16384`, `d_ff = 53248` ✓.
- int4 × int8: `d ≤ 2²⁰`.
- int16 × int8 (SiLU·gate product before requant): elementwise only, `2²³` ✓.
- Attention P̂·V: `P̂ ≤ 2^E`, V int8, keys `n`: need `2^(E+7)·n < 2³⁰` ⇒ blockwise accumulation (RFC-0009 §6) or DPA.
- Sum of squares for RMSNorm over int16: limb-split (RFC-0004 §5.3) or DPA.
When a shape violates a bound, the quantiser must either chunk the inner dimension (chunk partial sums are virtual
tensors, re-summed with a range-checked carry) or select DPA; it never silently wraps.

## 5. Dual-prime accumulation (DPA) — interface only (research RFC-0019 R-DPA)
A second prime `q = 2³¹ − 2²⁴ + 1` (KoalaBear) with the same kernel shapes. A reduction marked `dpa` runs its
sumcheck twice over integers committed once (shared systematic Merkle leaves, field-specific parity columns,
RFC-0010 §8). Verifier accepts only if both transcripts accept. Integer identities then hold modulo `p·q > 2⁶¹`.

## 6. Kernel contract
`trait Field: Copy + Add + Sub + Mul + Neg + Inverse + Serialize { const MODULUS; fn from_i64; fn to_i64_signed; }`
with `M31`, `CM31`, `QM31`, `OM31`, `KoalaBear` implementations in `stele-field`; SIMD specialisations in
`stele-simd`; CUDA mirrors generated from the same op table (RFC-0014 §2). Property tests: ring axioms,
Frobenius, inverse, serialisation round-trip, lazy-reduction equivalence, 10⁶ random cases per op per backend.

## 7. Amendment log

### A1 — Explicit octic modulus, basis and checked signed recovery

Status: Accepted. Review record: [A1 skill reviews](../../agents/reviews/field-cqis-a1.md).

Motivation: E1-02 cannot implement interoperable OM31 arithmetic from an unspecified
modulus. The §6 interface also leaves signed recovery undefined for an extension
element outside the prime subfield. Q9 in RFC-0019 tracks both issues.

Exact replacement for the OM31 and serialisation bullets in §2:

> - `OM31 = QM31[v]/(v²-u)` (degree 8). Its field order is exactly `p⁸`, not `2²⁴⁸`.
>   This fixes the field representation only; profile selection remains governed by
>   RFC-0012 and R-OCTIC. Irreducibility must be checked in the field CI tests.
> - Serialisation uses canonical M31 limbs in little-endian order. The ordered bases
>   are CM31 `(1,i)`, QM31 `(1,i,u,iu)`, OM31 `(1,i,u,iu,v,iv,uv,iuv)`.
>   Reject any limb outside `[0,p)`; do not reduce encoded limbs. Encodings have
>   exactly 8, 16 and 32 bytes respectively.

Exact replacement for §6's trait sketch and its signed-conversion semantics:

> `trait Field: Copy + Add + Sub + Mul + Neg + Inverse + Serialize { const MODULUS: u32; fn from_i64(value: i64) -> Self; fn to_i64_signed(self) -> Option<i64>; }`
>
> `MODULUS` is the prime characteristic, not the field order. `from_i64` reduces
> modulo that characteristic and embeds into the prime subfield. `to_i64_signed`
> returns `Some(z)` for a prime-subfield element with its unique centered signed
> representative, and `None` if any nonconstant coefficient is nonzero. For M31
> and KoalaBear it always returns `Some`. It never silently projects an extension
> element onto its constant coefficient. Inversion returns `None` exactly at zero.

Proof basis: `research/r-octic/REPORT.md` derives irreducibility using the cyclic
multiplicative group theorem and quadratic norms. Its independent exact-arithmetic
script verifies the nonsquare certificates for `5`, `2+i` and `u`.
No conjectural assumption is needed for this algebraic claim.

Soundness accounting: no new challenge, binding, or error term. Implemented accounting
must use exact orders `p⁴`/`p⁸` in existing SC/RLC/LU/MASK denominators; bit widths alone
are not cardinalities. This amendment does not establish any profile error budget.
Cost model: no measured constant changes; E1-02 still requires the QM31:M31 ledger.
Affected tasks: E1-02 is unblocked by A1; E1-01/E1-03 signed-recovery callers must be
updated atomically with acceptance of A1. E2-01 uses the explicit basis on acceptance.
No new NC catalog binding; acceptance tests must reject noncanonical limbs at every
position and reject signed recovery when each nonconstant coefficient is nonzero.

Completed skill review passes (Workflow 02; same authoring agent, not independent review):
- [x] soundness-auditor (codex-root): norm proof, exact field orders, error terms
- [x] rfc-author (codex-root): glossary, basis consistency, profile scope
- [x] stele-field owner / sumcheck-prover-engineer (codex-root): API migration and independent irreducibility tests
