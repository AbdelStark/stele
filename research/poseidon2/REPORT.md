# Poseidon2-M31 parameter contract (Q13)

Question: which fixed permutation makes E2-03's reference KAT requirement
reproducible? RFC-0012 §3 omits width, exponent, round counts, matrices and constants.
Security property: one auditable permutation identity, distinct from a hash mode.
Kill criterion: disagreement with pinned upstream execution, an unspecified round
step, or a wrapper security claim inferred from a permutation KAT.

## Reproduce

```sh
cargo +1.95.0 run --manifest-path vendor-ref/poseidon2-m31/Cargo.toml --example vectors --locked > /tmp/stele-poseidon2.jsonl
cmp research/poseidon2/reference.jsonl /tmp/stele-poseidon2.jsonl
python3 research/poseidon2/check_poseidon2.py
```

The isolated package has dev-dependencies only, exact Plonky3 0.8.0 pins and a
committed Cargo.lock. No core dependency points to it. CI separately regenerates
the vectors with Rust 1.95.0; Stele core keeps its existing toolchain. Constants
and the published sequential-input KAT come from [Plonky3's pinned source](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/mersenne-31/src/poseidon2.rs),
under the included MIT license. Its [external linear layer](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/poseidon2/src/external.rs)
uses MDSMat4, distinct from the alternative HLMDSMat4 in the same file.

## Results and limits

The Python oracle uses direct matrix multiplication and integer modular powers,
not Plonky3's field or optimized linear-layer code. All 35 states agree: zero,
all p-1, sequential limbs, sixteen basis vectors, and sixteen deterministic
pseudorandom states. Removing the initial layer, changing -2 to -1 in the diagonal,
or changing one partial-round constant breaks the published sequential KAT.
Exact checks establish invertibility of the fifth power and both linear layers.
These are permutation consistency checks, not protocol controls or cryptanalysis.

The [Poseidon2 paper](https://eprint.iacr.org/2023/323) motivates the design; neither
it nor these checks proves a concrete Stele wrapper budget. Eight M31 limbs have
fewer than 248 bits of range, insufficient by themselves for a 128-bit generic
collision target. Q14 must select and account for a wrapper mode before E14-01
uses it. Native BLAKE3 and Q12 remain unchanged. No timing or performance claim.

Recommendation: accept RFC-0012 A2's fixed permutation contract, implement it for
E2-03 behind the wrapper feature, and retain E14-01's full protocol obligations.
Nothing under research or vendor-ref is imported by Stele core.
