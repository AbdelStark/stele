//! E16-36: hiding-source preparation (RFC-0013 A2/A8, RFC-0010 A2, RFC-0012 A3) as the
//! device runs it, in plain Rust: the Circle encoding of every row of `M'` in
//! symbol-major order (symbol `c` of row `r` at `c·rows + r`), each leaf
//! `salt || column` hashed with BLAKE3 under the Merkle domain, and the tree. The
//! functions mirror `source.cu` step for step, so the CPU tests here check the
//! device algorithm against the production `PreparedSource` before any GPU runs.
use crate::M31;
use stele_reductions::stele_hash::mask::SOURCE_SALT;
use stele_reductions::stele_hash::merkle::Descriptor;

const P: u32 = 0x7fff_ffff;

fn mul(a: (M31, M31), b: (M31, M31)) -> (M31, M31) {
    (a.0 * b.0 - a.1 * b.1, a.0 * b.1 + a.1 * b.0)
}

fn generator_power(mut exponent: u32) -> (M31, M31) {
    let mut g = (M31::from_u64(1717986917), M31::from_u64(1288490189));
    let mut value = (M31::ONE, M31::ZERO);
    while exponent != 0 {
        if exponent & 1 != 0 {
            value = mul(value, g);
        }
        g = mul(g, g);
        exponent >>= 1;
    }
    value
}

/// RFC-0010 A2 twiddles of a `2^log` transform, level 0 (`2^(log-1)` entries) first,
/// as `stele-code`'s `twiddles`; `inverse` replaces each by its inverse.
pub fn twiddles(log: u32, inverse: bool) -> Vec<Vec<u32>> {
    let mut levels: Vec<Vec<M31>> = Vec::new();
    if log == 0 {
        return Vec::new();
    }
    let half = 1usize << (log - 1);
    let (mut ys, mut xs) = (Vec::new(), Vec::new());
    let mut pt = generator_power(1 << (30 - log));
    let step = mul(pt, pt);
    for j in 0..half {
        ys.push(pt.1);
        if j < half / 2 {
            xs.push(pt.0);
        }
        pt = mul(pt, step);
    }
    levels.push(ys);
    if !xs.is_empty() {
        levels.push(xs);
    }
    for level in 2..log as usize {
        let next = levels[level - 1][..levels[level - 1].len() / 2]
            .iter()
            .map(|x| *x * *x + *x * *x - M31::ONE)
            .collect();
        levels.push(next);
    }
    levels
        .into_iter()
        .map(|level| {
            level
                .into_iter()
                .map(|t| if inverse { t.pow(u64::from(P) - 2) } else { t })
                .map(|t| t.as_u32())
                .collect()
        })
        .collect()
}

fn madd(a: u32, b: u32) -> u32 {
    (M31::from_u64(u64::from(a)) + M31::from_u64(u64::from(b))).as_u32()
}
fn msub(a: u32, b: u32) -> u32 {
    (M31::from_u64(u64::from(a)) - M31::from_u64(u64::from(b))).as_u32()
}
fn mmul(a: u32, b: u32) -> u32 {
    (M31::from_u64(u64::from(a)) * M31::from_u64(u64::from(b))).as_u32()
}

/// One butterfly level over every row of a symbol-major table of `n` symbols, as the
/// device's `level_kernel`: blocks of width `2h`, the quad `{j, h-1-j, h+j, 2h-1-j}`
/// per thread. Inverse: `x[j] = a + b`, `x[h+j] = (a - b)·t_j` with `a = x[j]`,
/// `b = x[2h-1-j]` (the CPU's butterfly followed by its second-half reversal).
/// Forward: `x[j] = a + t_j·c`, `x[2h-1-j] = a - t_j·c` with `c = x[h+j]` (the
/// reversal followed by the butterfly).
pub fn level(x: &mut [u32], rows: usize, n: usize, tw: &[u32], inverse: bool) {
    let h = tw.len();
    let w = 2 * h;
    let at = |i: usize, r: usize| i * rows + r;
    for base in (0..n).step_by(w) {
        for j in 0..h.div_ceil(2) {
            for r in 0..rows {
                let (p0, p1, p2, p3) = (base + j, base + h - 1 - j, base + h + j, base + w - 1 - j);
                let (v0, v1, v2, v3) = (x[at(p0, r)], x[at(p1, r)], x[at(p2, r)], x[at(p3, r)]);
                let (t0, t1) = (tw[j], tw[h - 1 - j]);
                if inverse {
                    // pair j: (p0, p3) -> (p0, p2); pair h-1-j: (p1, p2) -> (p1, p3)
                    x[at(p0, r)] = madd(v0, v3);
                    x[at(p2, r)] = mmul(msub(v0, v3), t0);
                    if p1 != p0 {
                        x[at(p1, r)] = madd(v1, v2);
                        x[at(p3, r)] = mmul(msub(v1, v2), t1);
                    }
                } else {
                    let (c0, c1) = (mmul(v2, t0), mmul(v3, t1));
                    x[at(p0, r)] = madd(v0, c0);
                    x[at(p3, r)] = msub(v0, c0);
                    if p1 != p0 {
                        x[at(p1, r)] = madd(v1, c1);
                        x[at(p2, r)] = msub(v1, c1);
                    }
                }
            }
        }
    }
}

/// Swap symbols `i` and `rev(i)` of every row.
pub fn bit_reverse(x: &mut [u32], rows: usize, log: u32) {
    for i in 0..1usize << log {
        let j = i.reverse_bits() >> (usize::BITS - log);
        if i < j {
            for r in 0..rows {
                x.swap(i * rows + r, j * rows + r);
            }
        }
    }
}

/// Encode every row of row-major `message` (`rows × 2^log_n`) at log blowup `blowup`:
/// symbol-major codewords of `2^(log_n + blowup)` symbols.
pub fn encode_rows(message: &[u32], rows: usize, log_n: u32, blowup: u32) -> Vec<u32> {
    let (n, big) = (1usize << log_n, 1usize << (log_n + blowup));
    let mut x = vec![0u32; big * rows];
    for r in 0..rows {
        for c in 0..n {
            x[c * rows + r] = message[r * n + c];
        }
    }
    let msg = &mut x[..n * rows];
    for tw in twiddles(log_n, true) {
        level(msg, rows, n, &tw, true);
    }
    bit_reverse(msg, rows, log_n);
    let scale = M31::from_u64(n as u64).pow(u64::from(P) - 2).as_u32();
    msg.iter_mut().for_each(|v| *v = mmul(*v, scale));
    bit_reverse(&mut x, rows, log_n + blowup);
    for tw in twiddles(log_n + blowup, false).iter().rev() {
        level(&mut x, rows, big, tw, false);
    }
    x
}

// BLAKE3, as source.cu: one compression function, chunks of 16 blocks, the
// reference implementation's chaining-value stack.
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const PERM: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
/// Domain flags.
pub const CHUNK_START: u32 = 1;
pub const CHUNK_END: u32 = 2;
pub const PARENT: u32 = 4;
pub const ROOT: u32 = 8;
pub const KEYED_HASH: u32 = 16;

fn g(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(x);
    s[d] = (s[d] ^ s[a]).rotate_right(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(12);
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(y);
    s[d] = (s[d] ^ s[a]).rotate_right(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(7);
}

/// The full 16-word compression output.
pub fn compress(cv: &[u32; 8], block: &[u32; 16], counter: u64, len: u32, flags: u32) -> [u32; 16] {
    let mut s = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        len,
        flags,
    ];
    let mut m = *block;
    for round in 0..7 {
        g(&mut s, 0, 4, 8, 12, m[0], m[1]);
        g(&mut s, 1, 5, 9, 13, m[2], m[3]);
        g(&mut s, 2, 6, 10, 14, m[4], m[5]);
        g(&mut s, 3, 7, 11, 15, m[6], m[7]);
        g(&mut s, 0, 5, 10, 15, m[8], m[9]);
        g(&mut s, 1, 6, 11, 12, m[10], m[11]);
        g(&mut s, 2, 7, 8, 13, m[12], m[13]);
        g(&mut s, 3, 4, 9, 14, m[14], m[15]);
        if round < 6 {
            m = core::array::from_fn(|i| m[PERM[i]]);
        }
    }
    for i in 0..8 {
        s[i] ^= s[i + 8];
        s[i + 8] ^= cv[i];
    }
    s
}

fn first8(s: [u32; 16]) -> [u32; 8] {
    core::array::from_fn(|i| s[i])
}

/// BLAKE3-256 (unkeyed) of a message of `len` bytes, read as little-endian words by
/// `word(i)` (a final partial word zero-padded).
pub fn hash_words(len: usize, word: &dyn Fn(usize) -> u32) -> [u32; 8] {
    let chunks = len.div_ceil(1024).max(1);
    let mut stack: Vec<[u32; 8]> = Vec::new();
    for c in 0..chunks {
        let start = c * 1024;
        let bytes = (len - start).min(1024);
        let blocks = bytes.div_ceil(64).max(1);
        let mut cv = IV;
        for b in 0..blocks {
            let off = start + b * 64;
            let blen = (len - off).min(64) as u32;
            let block: [u32; 16] = core::array::from_fn(|i| {
                if 4 * i < blen as usize {
                    word(off / 4 + i)
                } else {
                    0
                }
            });
            let mut flags = if b == 0 { CHUNK_START } else { 0 };
            if b + 1 == blocks {
                flags |= CHUNK_END;
                if c + 1 == chunks {
                    // The final chunk's last block is the pending output.
                    let mut out = (cv, block, c as u64, blen, flags);
                    while let Some(left) = stack.pop() {
                        let right = first8(compress(&out.0, &out.1, out.2, out.3, out.4));
                        let mut pb = [0u32; 16];
                        pb[..8].copy_from_slice(&left);
                        pb[8..].copy_from_slice(&right);
                        out = (IV, pb, 0, 64, PARENT);
                    }
                    return first8(compress(&out.0, &out.1, out.2, out.3, out.4 | ROOT));
                }
            }
            cv = first8(compress(&cv, &block, c as u64, blen, flags));
        }
        let mut total = c + 1;
        while total & 1 == 0 {
            let left = stack.pop().unwrap_or(IV);
            let mut pb = [0u32; 16];
            pb[..8].copy_from_slice(&left);
            pb[8..].copy_from_slice(&cv);
            cv = first8(compress(&IV, &pb, 0, 64, PARENT));
            total >>= 1;
        }
        stack.push(cv);
    }
    IV
}

fn le_words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(4)
        .map(|c| {
            let mut w = [0u8; 4];
            w[..c.len()].copy_from_slice(c);
            u32::from_le_bytes(w)
        })
        .collect()
}

/// The 43-byte prefix `tag || "stele/v0.1/merkle" || kind || id || count || width`.
pub fn prefix(desc: &Descriptor, tag: u8) -> Vec<u8> {
    let mut b = vec![tag];
    b.extend_from_slice(b"stele/v0.1/merkle");
    b.push(desc.kind as u8);
    b.extend_from_slice(&desc.id.to_le_bytes());
    b.extend_from_slice(&desc.count.to_le_bytes());
    b.extend_from_slice(&desc.width.to_le_bytes());
    b
}

/// The salt stream's root block (key = seed): `SOURCE_SALT || id` padded, and its length.
pub fn salt_block(id: u64) -> ([u32; 16], u32) {
    let mut b = SOURCE_SALT.to_vec();
    b.extend_from_slice(&id.to_le_bytes());
    let len = b.len() as u32;
    b.resize(64, 0);
    let w = le_words(&b);
    (core::array::from_fn(|i| w[i]), len)
}

/// Salt words of leaf `i`: XOF bytes `[32i, 32i + 32)` of the keyed stream.
pub fn salt(key: &[u32; 8], block: &[u32; 16], len: u32, i: usize) -> [u32; 8] {
    let out = compress(
        key,
        block,
        (i / 2) as u64,
        len,
        CHUNK_START | CHUNK_END | ROOT | KEYED_HASH,
    );
    core::array::from_fn(|k| out[8 * (i % 2) + k])
}

/// The root of the tree over the symbol-major codewords `enc` (`leaves × rows`), each
/// leaf `salt || column`; leaves are a power of two, all real.
pub fn root(desc: &Descriptor, enc: &[u32], rows: usize, seed: &[u8; 32]) -> [u8; 32] {
    let leaves = desc.count as usize;
    let mut head = prefix(desc, desc.kind as u8);
    let key: [u32; 8] = core::array::from_fn(|i| le_words(seed)[i]);
    let (block, blen) = salt_block(desc.id);
    let len = 52 + 32 + 4 * rows;
    let mut level: Vec<[u32; 8]> = (0..leaves)
        .map(|i| {
            head.truncate(43);
            head.extend_from_slice(&(i as u64).to_le_bytes());
            head.push(1);
            let hw = le_words(&head);
            let s = salt(&key, &block, blen, i);
            hash_words(len, &|w| match w {
                0..=12 => hw[w],
                13..=20 => s[w - 13],
                _ => enc[i * rows + w - 21],
            })
        })
        .collect();
    let node_prefix = prefix(desc, 1);
    let mut height = 0u32;
    while level.len() > 1 {
        height += 1;
        level = level
            .chunks(2)
            .enumerate()
            .map(|(index, pair)| {
                let mut b = node_prefix.clone();
                b.extend_from_slice(&height.to_le_bytes());
                b.extend_from_slice(&(index as u64).to_le_bytes());
                for d in pair {
                    for w in d {
                        b.extend_from_slice(&w.to_le_bytes());
                    }
                }
                let len = b.len();
                let w = le_words(&b);
                hash_words(len, &|i| w[i])
            })
            .collect();
    }
    let mut out = [0u8; 32];
    for (o, w) in out.chunks_mut(4).zip(level[0]) {
        o.copy_from_slice(&w.to_le_bytes());
    }
    out
}

use crate::{Rng, QM31};
use std::time::{Duration, Instant};
use stele_reductions::stele_hash::HashUsage;
use stele_reductions::stele_pcs::{
    hiding_message, verify_certificate, Policy, PreparedSource, Source,
};

/// Log blowup of every hiding source (rate 1/4).
pub const BLOWUP: u8 = 2;

/// A hiding source of `R = 2^ell` data rows and `C = 2^m` columns: `M'` is
/// `2R × 2C`, each row Circle-encoded to `2^(m + 1 + BLOWUP)` symbols.
pub struct Shape {
    pub id: u64,
    pub ell: u8,
    pub m: u8,
    pub seed: [u8; 32],
}

impl Shape {
    pub fn new(ell: u8, m: u8, seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        Self {
            id: 3,
            ell,
            m,
            seed: core::array::from_fn(|_| (rng.m31().as_u32() & 0xff) as u8),
        }
    }
    /// `2R`, the rows of `M'`.
    pub fn rows(&self) -> usize {
        2 << self.ell
    }
    /// `log2(2C)`, the message length exponent of each row.
    pub fn log_n(&self) -> u32 {
        u32::from(self.m) + 1
    }
    /// `M'` of random M31 data, from the production `hiding_message`.
    pub fn message(&self) -> Vec<M31> {
        let mut rng = Rng::new(u64::from(self.seed[0]) + 1);
        let data: Vec<M31> = (0..1usize << (self.ell + self.m))
            .map(|_| rng.m31())
            .collect();
        hiding_message(self.id, self.ell, self.m, &data, &self.seed).unwrap_or_default()
    }
    /// The source's public descriptor (root-independent) and code id.
    pub fn source(&self) -> Option<Source<QM31>> {
        Source::<QM31>::hiding_with(self.id, self.ell, self.m, BLOWUP, [0; 32], Policy::Two).ok()
    }
}

/// The production preparation (encoding, salts, Merkle tree) and certificate of one
/// source, timed apart: `(root, prepare, certify)`.
pub fn cpu(shape: &Shape, message: &[M31]) -> Option<([u8; 32], Duration, Duration)> {
    let start = Instant::now();
    let prepared = PreparedSource::<QM31>::hiding_with(
        shape.id,
        shape.ell,
        shape.m,
        BLOWUP,
        message,
        &shape.seed,
        &mut HashUsage::default(),
        Policy::Two,
    )
    .ok()?;
    let prepare = start.elapsed();
    let start = Instant::now();
    let certificate = prepared.certificate().ok()?.0;
    verify_certificate(*prepared.source(), &certificate).ok()?;
    Some((prepared.source().root(), prepare, start.elapsed()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plain-Rust device algorithm (symbol-major Circle encoding, BLAKE3 leaves with
    /// keyed-XOF salts, the node tree) gives the production `PreparedSource` root.
    #[test]
    fn matches_reference_prepared_source_root() {
        // (8, 10) and (9, 11): 2132- and 4180-byte leaves, the multi-chunk BLAKE3 path.
        for (ell, m) in [(3u8, 9u8), (4, 10), (8, 10), (9, 11)] {
            let shape = Shape::new(ell, m, 5);
            let message = shape.message();
            let (expected, _, _) = cpu(&shape, &message).expect("production preparation");
            let source = shape.source().expect("source");
            let words: Vec<u32> = message.iter().map(|v| v.as_u32()).collect();
            let enc = encode_rows(&words, shape.rows(), shape.log_n(), u32::from(BLOWUP));
            assert_eq!(source.code_id().len(), 21);
            assert_eq!(
                root(&source.descriptor(), &enc, shape.rows(), &shape.seed),
                expected
            );
        }
    }
}
