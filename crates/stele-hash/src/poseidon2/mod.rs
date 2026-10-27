//! Fixed wrapper-only permutation governed by RFC-0012 A2.
//! This is not a hash or transcript; wrapper modes require Q14 resolution in E14-01.
use stele_field::{Field, M31};

mod constants;
use constants::{FINAL, INITIAL, INTERNAL};

const M4: [[u64; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
const DIAGONAL: [i64; 16] = [
    -2, 1, 2, 4, 8, 16, 32, 64, 128, 256, 1024, 4096, 8192, 16384, 32768, 65536,
];

/// Apply the fixed width-16 Poseidon2-M31 permutation in place (RFC-0012 A2).
/// Field elements are canonical; there is no byte reduction or digest encoding.
pub fn permute(state: &mut [M31; 16]) {
    external(state);
    for constants in &INITIAL {
        full_round(state, constants);
    }
    for constant in INTERNAL {
        state[0] = fifth_power(state[0] + M31::from_u64(u64::from(constant)));
        let sum = state.iter().fold(M31::ZERO, |acc, x| acc + *x);
        for (value, diagonal) in state.iter_mut().zip(DIAGONAL) {
            *value = sum + *value * M31::from_i64(diagonal);
        }
    }
    for constants in &FINAL {
        full_round(state, constants);
    }
}

fn fifth_power(x: M31) -> M31 {
    let square = x * x;
    square * square * x
}

fn full_round(state: &mut [M31; 16], constants: &[u32; 16]) {
    for (value, constant) in state.iter_mut().zip(constants) {
        *value = fifth_power(*value + M31::from_u64(u64::from(*constant)));
    }
    external(state);
}

fn external(state: &mut [M31; 16]) {
    for block in state.chunks_exact_mut(4) {
        let transformed: [M31; 4] = core::array::from_fn(|i| {
            M4[i]
                .iter()
                .zip(block.iter())
                .fold(M31::ZERO, |acc, (coefficient, x)| {
                    acc + M31::from_u64(*coefficient) * *x
                })
        });
        block.copy_from_slice(&transformed);
    }
    // RFC-0012 A2: compute every sum before modifying any transformed block.
    let sums: [M31; 4] =
        core::array::from_fn(|j| (0..4).fold(M31::ZERO, |acc, i| acc + state[4 * i + j]));
    for (i, value) in state.iter_mut().enumerate() {
        *value = *value + sums[i % 4];
    }
}

#[cfg(test)]
mod tests;
