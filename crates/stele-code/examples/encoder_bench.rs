//! RFC-0010 A4/A5, RFC-0018 §1 — full operation and exhaustive integer validation.
#![forbid(unsafe_code)]
#[path = "support/reference.rs"]
mod reference;
use std::{hint::black_box, time::Instant};
use stele_code::{CodeField, Encoder, EncoderWork};
use stele_field::{CM31, M31, OM31, QM31};

fn observations(w: &EncoderWork) -> [(&'static str, u128); 13] {
    [
        ("peak_owned_bytes", w.peak_owned_bytes as u128),
        ("hash_blocks", w.hash_blocks.into()),
        ("generated_rows", w.generated_rows.into()),
        ("sparse_limb_additions", w.sparse_limb_additions.into()),
        ("sparse_limb_products", w.sparse_limb_products.into()),
        ("initialized_symbols", w.initialized_symbols.into()),
        ("copied_symbols", w.copied_symbols.into()),
        ("circle_calls", w.circle_calls.into()),
        (
            "circle_transform_additions",
            w.circle_transform_additions.into(),
        ),
        (
            "circle_transform_products",
            w.circle_transform_products.into(),
        ),
        ("twiddle_elements", w.twiddle_elements.into()),
        ("inverse_prefix_elements", w.inverse_prefix_elements.into()),
        ("max_recursive_frames", w.max_recursive_frames.into()),
    ]
}
fn run<K: CodeField>(j: u8, value: impl Fn(usize) -> K) -> Result<(), String> {
    let total = Instant::now();
    let at = Instant::now();
    let mut id = [0; 55];
    id[..22].copy_from_slice(b"stele/expander-seed/v2");
    id[22] = j;
    let code = Encoder::from_code_id(&id).map_err(|e| format!("{e:?}"))?;
    let factory_ns = at.elapsed().as_nanos();
    let n = 4usize.pow(u32::from(j));
    let d = usize::from(K::DEGREE);
    let at = Instant::now();
    let row: Vec<_> = (0..n).map(value).collect();
    let input_ns = at.elapsed().as_nanos();
    let at = Instant::now();
    let encoded = code
        .encode_measured(black_box(&row))
        .map_err(|e| format!("{e:?}"))?;
    let encode_ns = at.elapsed().as_nanos();
    let columns = [2 * n - 1, 0, n, 0];
    let at = Instant::now();
    let query = code
        .eval_row_measured(black_box(&row), &columns)
        .map_err(|e| format!("{e:?}"))?;
    let query_ns = at.elapsed().as_nanos();
    let at = Instant::now();
    let expected = reference::encode(&reference::fixture(n, d), j, d, &[0; 32]);
    if expected.len() != 2 * n
        || encoded.values.len() != 2 * n
        || query.values.len() != columns.len()
    {
        return Err("shape mismatch".into());
    }
    let mut checksum = 0u64;
    for (actual, expected) in encoded.values.iter().zip(expected) {
        let bytes = actual.to_le_bytes();
        for (word, limb) in bytes.as_ref().chunks_exact(4).zip(expected) {
            let v = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            if v != limb {
                return Err("independent integer mismatch".into());
            }
            checksum = checksum
                .wrapping_mul(6364136223846793005)
                .wrapping_add(v.into());
        }
    }
    for (v, c) in query.values.iter().zip(columns) {
        if v.to_le_bytes().as_ref() != encoded.values[c].to_le_bytes().as_ref() {
            return Err("query mismatch".into());
        }
    }
    let validation_ns = at.elapsed().as_nanos();
    let input_bytes = row.capacity() * size_of::<K>();
    let output_bytes = encoded.values.capacity() * size_of::<K>();
    let query_bytes = query.values.capacity() * size_of::<K>();
    let live = input_bytes + output_bytes + query.work.peak_owned_bytes;
    let total_ns = total.elapsed().as_nanos();
    // Serialization is excluded; native input and both results survive timing.
    let mut result: Vec<(String, u128)> = vec![
        ("j", j.into()),
        ("d", d as u128),
        ("input_symbols", n as u128),
        ("checked_symbols", (2 * n) as u128),
        ("factory_ns", factory_ns),
        ("input_ns", input_ns),
        ("encode_ns", encode_ns),
        ("query_ns", query_ns),
        ("validation_ns", validation_ns),
        ("total_ns", total_ns),
        ("input_capacity_bytes", input_bytes as u128),
        ("output_capacity_bytes", output_bytes as u128),
        ("query_capacity_bytes", query_bytes as u128),
        ("native_live_peak_bytes", live as u128),
        ("encoder_inline_bytes", size_of::<Encoder>() as u128),
        ("observation_inline_bytes", size_of::<EncoderWork>() as u128),
        ("query_input_bytes", size_of_val(&columns) as u128),
        ("checksum", checksum.into()),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v))
    .collect();
    for (prefix, work) in [("encode", &encoded.work), ("query", &query.work)] {
        result.extend(
            observations(work)
                .into_iter()
                .map(|(k, v)| (format!("{prefix}_{k}"), v)),
        );
    }
    println!(
        "{{{}}}",
        result
            .iter()
            .map(|(k, v)| format!("\"{k}\":{v}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    Ok(())
}
fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: encoder_bench <j:3..10> <d:1|4|8>".into());
    }
    let j: u8 = args[0].parse().map_err(|_| "j")?;
    let d: u8 = args[1].parse().map_err(|_| "d")?;
    drop(args);
    if !(3..=10).contains(&j) {
        return Err("size".into());
    }
    let m = |i, k| M31::from_u64(reference::value(i, k).into());
    let q = |i, k| QM31(CM31(m(i, k), m(i, k + 1)), CM31(m(i, k + 2), m(i, k + 3)));
    match d {
        1 => run(j, |i| m(i, 0)),
        4 => run(j, |i| q(i, 0)),
        8 => run(j, |i| OM31(q(i, 0), q(i, 4))),
        _ => Err("field".into()),
    }
}
