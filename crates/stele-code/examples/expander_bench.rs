//! RFC-0010 A4 / RFC-0018 §1 — complete native encode/query and integer validation.
#[path = "support/reference.rs"]
mod reference;
use std::{hint::black_box, time::Instant};
use stele_code::{CodeId, Element};
use stele_field::{Field, CM31, M31, OM31, QM31};
fn run<K: Element>(j: u8, d: usize, value: impl Fn(usize) -> K) -> Result<(), String> {
    let total = Instant::now();
    let mut raw = b"stele/expander-seed/v2".to_vec();
    raw.push(j);
    raw.extend([0; 32]);
    let id = CodeId::parse(&raw).map_err(|e| format!("{e:?}"))?;
    let p = id.parameters();
    let n = p.message_len;
    let at = Instant::now();
    let row: Vec<_> = (0..n).map(value).collect();
    let input_ns = at.elapsed().as_nanos();
    let at = Instant::now();
    let code = id.prepare(1 << 30).map_err(|e| format!("{e:?}"))?;
    let setup_ns = at.elapsed().as_nanos();
    let at = Instant::now();
    let encoded = code
        .encode_with_memory(black_box(&row))
        .map_err(|e| format!("{e:?}"))?;
    let encode_ns = at.elapsed().as_nanos();
    let columns = [2 * n - 1, 0, n, 0];
    let at = Instant::now();
    let queried = code
        .eval_row_with_memory(black_box(&row), &columns)
        .map_err(|e| format!("{e:?}"))?;
    let query_ns = at.elapsed().as_nanos();
    let at = Instant::now();
    let original = reference::fixture(n, d);
    let expected = reference::encode(&original, j, d, &[0; 32]);
    let mut checksum = 0u64;
    for (actual, expected) in encoded.word.iter().zip(&expected) {
        let bytes = actual.to_le_bytes();
        for (word, expected) in bytes.as_ref().chunks_exact(4).zip(expected) {
            let v = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            if v != *expected {
                return Err("independent codeword mismatch".into());
            }
            checksum = checksum
                .wrapping_mul(6364136223846793005)
                .wrapping_add(u64::from(v));
        }
    }
    for (value, column) in queried.word.iter().zip(columns) {
        if value.to_le_bytes().as_ref() != encoded.word[column].to_le_bytes().as_ref() {
            return Err("query mismatch".into());
        }
    }
    if encoded.word.len() != 2 * n || expected.len() != 2 * n || queried.word.len() != columns.len()
    {
        return Err("shape".into());
    }
    let validation_ns = at.elapsed().as_nanos();
    let input_capacity_bytes = row.capacity() * size_of::<K>();
    let output_capacity_bytes = encoded.word.capacity() * size_of::<K>();
    let query_capacity_bytes = queried.word.capacity() * size_of::<K>();
    let id_capacity_bytes = raw.capacity();
    let native_peak = id_capacity_bytes
        + input_capacity_bytes
        + output_capacity_bytes
        + queried.peak_owned_heap_bytes;
    println!("{{\"j\":{j},\"d\":{d},\"input_symbols\":{n},\"checked_symbols\":{},\"input_ns\":{input_ns},\"setup_ns\":{setup_ns},\"encode_ns\":{encode_ns},\"query_ns\":{query_ns},\"validation_ns\":{validation_ns},\"total_ns\":{},\"graph_capacity_bytes\":{},\"input_capacity_bytes\":{input_capacity_bytes},\"output_capacity_bytes\":{output_capacity_bytes},\"query_capacity_bytes\":{query_capacity_bytes},\"encode_owned_peak_bytes\":{},\"query_owned_peak_bytes\":{},\"id_capacity_bytes\":{id_capacity_bytes},\"native_live_peak_bytes\":{native_peak},\"setup_blocks\":{},\"sparse_adds_per_encode\":{},\"sparse_base_products_per_encode\":{},\"checksum\":{checksum}}}",2*n,total.elapsed().as_nanos(),code.graph_capacity_bytes(),encoded.peak_owned_heap_bytes,queried.peak_owned_heap_bytes,code.setup_hash_blocks(),p.edge_count,p.edge_count);
    Ok(())
}
fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: expander_bench <j:3..9> <field:1|4|8>".into());
    }
    let j: u8 = args[0].parse().map_err(|_| "j")?;
    let d: usize = args[1].parse().map_err(|_| "field")?;
    drop(args); // No argument buffers remain live inside the measured operation.
    if !(3..=9).contains(&j) {
        return Err("unsupported benchmark size".into());
    }
    let m = |i, k| M31::from_i64(i64::from(reference::value(i, k)));
    let q = |i, k| QM31(CM31(m(i, k), m(i, k + 1)), CM31(m(i, k + 2), m(i, k + 3)));
    match d {
        1 => run(j, d, |i| m(i, 0)),
        4 => run(j, d, |i| q(i, 0)),
        8 => run(j, d, |i| OM31(q(i, 0), q(i, 4))),
        _ => Err("field".into()),
    }
}
