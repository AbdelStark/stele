//! RFC-0019 Q13 research: execute the pinned upstream permutation, outside Stele core.
use p3_field::PrimeField32;
use p3_mersenne_31::{
    MERSENNE31_POSEIDON2_RC_16_EXTERNAL_FINAL as FINAL,
    MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL as INITIAL,
    MERSENNE31_POSEIDON2_RC_16_INTERNAL as INTERNAL, Mersenne31, default_mersenne31_poseidon2_16,
};
use p3_symmetric::Permutation;
use serde_json::json;

fn main() {
    println!(
        "{}",
        json!({"reference": "p3-mersenne-31=0.8.0", "commit": "a21e3ed42905040ad49c519e402f018381c12d0c",
        "initial": INITIAL.map(|row| row.map(|x| x.as_canonical_u32())),
        "internal": INTERNAL.map(|x| x.as_canonical_u32()),
        "final": FINAL.map(|row| row.map(|x| x.as_canonical_u32()))})
    );
    let p = (1u32 << 31) - 1;
    let mut inputs = vec![[0; 16], [p - 1; 16], core::array::from_fn(|i| i as u32)];
    for i in 0..16 {
        let mut unit = [0; 16];
        unit[i] = 1;
        inputs.push(unit);
    }
    let mut seed = 1u64;
    for _ in 0..16 {
        inputs.push(core::array::from_fn(|_| {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            (seed >> 32) as u32 % p
        }));
    }
    let permutation = default_mersenne31_poseidon2_16();
    for input in inputs {
        let mut state = input.map(Mersenne31::new);
        permutation.permute_mut(&mut state);
        println!(
            "{}",
            json!({"input": input, "output": state.map(|x| x.as_canonical_u32())})
        );
    }
}
