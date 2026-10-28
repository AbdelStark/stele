//! RFC-0010 A2 / RFC-0018 §1: full encoding with every output checked.
use std::{hint::black_box, time::Instant};
use stele_code::Circle;
use stele_field::M31;

const P: u64 = (1 << 31) - 1;

// Independent integer circle arithmetic, not the encoder's domain/field routines.
fn multiply(a: (u64, u64), b: (u64, u64)) -> (u64, u64) {
    (
        (a.0 * b.0 + P * P - a.1 * b.1) % P,
        (a.0 * b.1 + a.1 * b.0) % P,
    )
}

fn point(log: u32, j: usize) -> (u64, u64) {
    let mut exponent = (2 * j as u64 + 1) << (30 - log);
    let (mut value, mut g) = ((1, 0), (1717986917, 1288490189));
    while exponent != 0 {
        if exponent & 1 != 0 {
            value = multiply(value, g);
        }
        g = multiply(g, g);
        exponent >>= 1;
    }
    value
}

fn value(y: u64, high_x: u64, row: u64) -> u64 {
    let low = (17 + row + (29 + 2 * row) * y) % P;
    let high = (43 + 3 * row + (71 + 5 * row) * y) % P;
    (low + high * high_x) % P
}

// v_(m-1)(x)=cos(2^(m-2)*theta); this polynomial belongs to the exact FFT span.
fn expected(m: u32, log_domain: u32, row: u64) -> impl Iterator<Item = u64> {
    let mut low = point(log_domain, 0);
    let mut high = point(log_domain - m + 2, 0);
    let (low_step, high_step) = (multiply(low, low), multiply(high, high));
    (0..1usize << log_domain).map(move |_| {
        let result = value(low.1, high.0, row);
        low = multiply(low, low_step);
        high = multiply(high, high_step);
        result
    })
}

fn validate(word: &[M31], m: u32, log_domain: u32, row: u64) -> Result<u64, String> {
    if word.len() != 1usize << log_domain {
        return Err("wrong output length".into());
    }
    let mut checksum = 0u64;
    for (j, (actual, reference)) in word.iter().zip(expected(m, log_domain, row)).enumerate() {
        if u64::from(actual.as_u32()) != reference {
            return Err(format!("output mismatch at {j}"));
        }
        checksum = checksum
            .wrapping_mul(6364136223846793005)
            .wrapping_add(reference);
    }
    Ok(checksum)
}

fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: circle_bench <m:2..29> <log-blowup:1|2> <row:0..3>".into());
    }
    let m: u32 = args[0].parse().map_err(|_| "invalid m")?;
    let b: u32 = args[1].parse().map_err(|_| "invalid blowup")?;
    let row: u64 = args[2].parse().map_err(|_| "invalid row")?;
    if m < 2 || row > 3 {
        return Err("invalid fixture dimensions".into());
    }
    let code = Circle::new(m, b).map_err(|e| format!("{e:?}"))?;
    let start = Instant::now();
    let mut input = Vec::new();
    input
        .try_reserve_exact(code.message_len())
        .map_err(|e| e.to_string())?;
    input.extend(expected(m, m, row).map(M31::from_u64));
    let preparation_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let output = code
        .encode(black_box(&input))
        .map_err(|e| format!("{e:?}"))?;
    let encode_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let checksum = validate(black_box(&output), m, m + b, row)?;
    let validation_ns = start.elapsed().as_nanos();
    println!(
        "{{\"m\":{m},\"b\":{b},\"row\":{row},\"input_symbols\":{},\"output_symbols\":{},\"input_capacity_bytes\":{},\"output_capacity_bytes\":{},\"preparation_ns\":{preparation_ns},\"encode_ns\":{encode_ns},\"validation_ns\":{validation_ns},\"checked_symbols\":{},\"checksum\":{checksum}}}",
        input.len(), output.len(), input.capacity() * size_of::<M31>(),
        output.capacity() * size_of::<M31>(), output.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference_pointwise_high_basis_and_full_encoding() {
        for m in 2..=8 {
            for b in [1, 2] {
                for row in 0..4 {
                    for (j, result) in expected(m, m + b, row).enumerate() {
                        let (mut x, y) = point(m + b, j);
                        for _ in 0..m - 2 {
                            x = (2 * x * x + P - 1) % P;
                        }
                        assert_eq!(result, value(y, x, row));
                    }
                    let input: Vec<_> = expected(m, m, row).map(M31::from_u64).collect();
                    let output = Circle::new(m, b).unwrap().encode(&input).unwrap();
                    validate(&output, m, m + b, row).unwrap();
                }
            }
        }
    }

    #[test]
    fn rejects_changed_missing_or_reordered_output() {
        let input: Vec<_> = expected(4, 4, 0).map(M31::from_u64).collect();
        let original = Circle::new(4, 2).unwrap().encode(&input).unwrap();
        for j in [0, 17, original.len() - 1] {
            let mut changed = original.clone();
            changed[j] = changed[j] + M31::ONE;
            assert!(validate(&changed, 4, 6, 0).is_err());
        }
        assert!(validate(&original[..63], 4, 6, 0).is_err());
        let mut changed = original;
        changed.swap(0, 1);
        assert!(validate(&changed, 4, 6, 0).is_err());
    }
}
