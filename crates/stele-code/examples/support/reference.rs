//! RFC-0010 A4 — benchmark-only integer oracle, separate from native sparse/FFT code.
// Independently construct the specified bytes; do not call the native sampler.
fn block(seed: &[u8; 32], j: u8, kind: u8, row: u32, stream: u8, counter: u8) -> [u8; 32] {
    let mut bytes = [0; 74];
    bytes[..34].copy_from_slice(b"stele/v0.1/setup/expander/block/v2");
    bytes[34..66].copy_from_slice(seed);
    bytes[66] = j;
    bytes[67] = kind;
    bytes[68..72].copy_from_slice(&row.to_le_bytes());
    bytes[72] = stream;
    bytes[73] = counter;
    *blake3::hash(&bytes).as_bytes()
}
pub const P: u64 = (1 << 31) - 1;
pub type Value = [u32; 8];
const BASE: &[u8] = include_bytes!("circle-base.bin");
const A: [usize; 12] = [25, 21, 19, 19, 18, 18, 17, 17, 17, 18, 18, 18];
const B: [usize; 12] = [26, 21, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18];
fn words(
    seed: &[u8; 32],
    j: u8,
    kind: u8,
    row: usize,
    stream: u8,
) -> impl Iterator<Item = u32> + '_ {
    (0..32).flat_map(move |counter| {
        block(seed, j, kind, row as u32, stream, counter)
            .chunks_exact(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect::<Vec<_>>()
    })
}
fn edges(
    seed: &[u8; 32],
    j: u8,
    kind: u8,
    row: usize,
    columns: usize,
    degree: usize,
) -> Vec<(usize, u32)> {
    let mut selected = Vec::new();
    for word in words(seed, j, kind, row, 0) {
        let column = word as usize % columns;
        if !selected.contains(&column) {
            selected.push(column);
        }
        if selected.len() == degree {
            break;
        }
    }
    selected.sort_unstable();
    let values: Vec<_> = words(seed, j, kind, row, 1)
        .map(|w| (u64::from(w) % (1 << 31)) as u32)
        .filter(|v| u64::from(*v) != P)
        .take(degree)
        .collect();
    assert_eq!(selected.len(), degree);
    assert_eq!(values.len(), degree);
    selected.into_iter().zip(values).collect()
}
fn sparse(row: &[Value], j: u8, kind: u8, columns: usize, d: usize, seed: &[u8; 32]) -> Vec<Value> {
    let mut out = vec![[0; 8]; columns];
    let degree = if kind == 0 {
        A[usize::from(j - 4)]
    } else {
        B[usize::from(j - 4)]
    };
    for (i, value) in row.iter().enumerate() {
        for (column, weight) in edges(seed, j, kind, i, columns, degree) {
            for (slot, x) in out[column][..d].iter_mut().zip(value) {
                *slot = ((u64::from(*slot) + u64::from(*x) * u64::from(weight)) % P) as u32;
            }
        }
    }
    out
}
pub fn encode(row: &[Value], j: u8, d: usize, seed: &[u8; 32]) -> Vec<Value> {
    if j == 3 {
        let mut out = vec![[0; 8]; 128];
        for (i, value) in row.iter().enumerate() {
            for (column, result) in out.iter_mut().enumerate() {
                let at = (i * 128 + column) * 4;
                let w = u64::from(u32::from_le_bytes([
                    BASE[at],
                    BASE[at + 1],
                    BASE[at + 2],
                    BASE[at + 3],
                ]));
                for (slot, x) in result[..d].iter_mut().zip(value) {
                    *slot = ((u64::from(*slot) + u64::from(*x) * w) % P) as u32;
                }
            }
        }
        return out;
    }
    let y = sparse(row, j, 0, row.len() / 4, d, seed);
    let z = encode(&y, j - 1, d, seed);
    let tail = sparse(&z, j, 1, row.len() / 2, d, seed);
    [row, z.as_slice(), tail.as_slice()].concat()
}
pub fn value(index: usize, limb: usize) -> u32 {
    ((index as u64 * 37 + limb as u64 * 17 + 9) % P) as u32
}
pub fn fixture(n: usize, d: usize) -> Vec<Value> {
    (0..n)
        .map(|i| {
            let mut v = [0; 8];
            for (k, x) in v[..d].iter_mut().enumerate() {
                *x = value(i, k);
            }
            v
        })
        .collect()
}
