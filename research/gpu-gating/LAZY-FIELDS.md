# Research field helper qualification (E16-40h)

RFC-0003 §§1/2/6 permits lazy limbs in `[0,2p)` inside kernels and requires
canonical values at serialization boundaries. The old research helpers assumed
canonical operands: addition of two `2p-1` operands lost a 32-bit carry, and
multiplication truncated part of the first reduction. The unchanged helper
source compiled as host C++ reproduces both failures. Stored raw `p` also remained
noncanonical. No production prover used raw lazy inputs through these helpers.

The fix retains addition's carry and multiplication's first fold in 64 bits,
then reduces the bounded result. Negation and embedded/stored QM31 limbs are
canonicalized explicitly. Canonical operands retain their values.
This changes only the research sandbox; no protocol, challenge, source visit,
commitment, proof byte, verifier API or production dependency changes.

`field_cases` supplies one million deterministic cases, seed `0x4000000001`.
It starts with the Cartesian edge pairs `0,1,p-1,p,p+1,2p-1`, rotating them
through extension limbs, then alternates canonical and raw-lazy random cases.
The actual `stele-field` M31/QM31 implementation is the reference. Every case
checks M31 add/subtract/multiply/negate, QM31 add/subtract/base-multiply/multiply,
and embedded/stored limbs. All observed output limbs must be canonical.

The ordinary CPU test compiles the actual CUDA helper prefix with the installed
host C++ compiler (`c++`, C++17, optimized, strict aliasing disabled for the
Q/u32 allocation views). It feeds native-word input/output files to that process
and compares every returned word. Temporary synthetic files are removed, including
on assertion failure. This is host-expression evidence, not NVRTC or device evidence.

```sh
cargo test --manifest-path research/gpu-gating/masked/Cargo.toml --locked --lib field_cases::matches_reference_cuda_field_helpers_on_host -- --exact
cargo test --manifest-path research/gpu-gating/masked/Cargo.toml --release --features cuda --locked --lib gpu::field_tests::matches_reference_raw_field_helpers_on_h100 -- --ignored --exact --nocapture
```

The explicit device test refuses absent CUDA/NVRTC and any device not named H100.
It compiles a wrapper around the same actual helpers, uploads the raw limbs,
launches the device kernel, synchronizes and compares all downloaded results with
the reference. Its completed receipt is `field_device_cases=1000000`, with the seed
and device name. The H100 campaign must also rerun the existing canonical masked
round and complete-source device tests, checking their explicit case receipts.

Hardware evidence is pending. This is qualification of the listed primitive
helpers only: it does not qualify every actual kernel on raw inputs, establish a
complete field backend (inverse/Frobenius operations are absent here), move a
scoreboard cell or establish full CPU/GPU proof parity, device budgets, speedup or
ADR-127 GO. The already queued E16-40d/E16-40f archives are unchanged and retain
their own acceptance contracts. Core integration remains blocked on its complete
reviewed evidence and accepted backend contract.
