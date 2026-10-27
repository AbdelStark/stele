//! RFC-0018 §1: synthetic partial-evaluation timing and payload measurement (E1-05).
use std::{hint::black_box, time::Instant};
use stele_field::{Field, Serialize, CM31, M31, QM31};
use stele_poly::{SmallMle, Strategy};

fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: partial_eval <4|8|16> <naive|bucketed>".into());
    }
    let bits: u32 = args[0].parse().map_err(|_| "invalid bit width")?;
    if ![4, 8, 16].contains(&bits) {
        return Err("invalid bit width".into());
    }
    let strategy = match args[1].as_str() {
        "naive" => Strategy::Naive,
        "bucketed" => Strategy::Bucketed,
        _ => return Err("invalid strategy".into()),
    };
    let values: Vec<i16> = (0..65536)
        .map(|i| (((i * 73 + 19) % (1 << bits)) - (1 << (bits - 1))) as i16)
        .collect();
    let table = match bits {
        4 => SmallMle::int4(values.into_iter().map(|v| v as i8).collect()),
        8 => SmallMle::int8(values.into_iter().map(|v| v as i8).collect()),
        _ => SmallMle::int16(values),
    }
    .map_err(|e| format!("{e:?}"))?;
    let point: Vec<_> = (0..14)
        .map(|i| {
            QM31(
                CM31(M31::from_i64(i + 3), M31::from_i64(i + 17)),
                CM31(M31::from_i64(i + 29), M31::from_i64(i + 43)),
            )
        })
        .collect();
    let mut output = table
        .partial_evaluate(&point, strategy)
        .map_err(|e| format!("{e:?}"))?;
    black_box(&output); // One warmup before the measured calls.
    let start = Instant::now();
    for _ in 0..10 {
        output = black_box(&table)
            .partial_evaluate(black_box(&point), strategy)
            .map_err(|e| format!("{e:?}"))?;
        black_box(output.values());
    }
    let ns = start.elapsed().as_nanos();
    println!("time_ns {ns}");
    println!("payload_bytes {}", table.payload_bytes());
    print!("output ");
    for value in output.values() {
        for byte in value.to_le_bytes() {
            print!("{byte:02x}");
        }
    }
    println!();
    Ok(())
}
