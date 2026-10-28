//! RFC-0010 A4 — regenerated sparse recursive map; O(E) work and graph storage.
use crate::memory::{self, Memory};
use crate::{native::Element, reserved, Circle, Error};
use alloc::vec::Vec;
use core::mem::size_of;
use stele_field::{Field, M31};
const A: [usize; 12] = [25, 21, 19, 19, 18, 18, 17, 17, 17, 18, 18, 18];
const B: [usize; 12] = [26, 21, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18];
pub(crate) fn edge_count(j: u8) -> u64 {
    (4..=j)
        .map(|level| {
            let n = 1u64 << (2 * level);
            n * A[usize::from(level - 4)] as u64 + (n / 2) * B[usize::from(level - 4)] as u64
        })
        .sum()
}
struct Edge {
    column: u32,
    coefficient: M31,
}
pub(crate) struct Expander {
    exponent: u8,
    edges: Vec<Edge>,
    starts: [usize; 16],
    blocks: u64,
}

// Pure bounded rejection helpers have no alternate production oracle or bypass.
fn neighbors(
    words: impl Iterator<Item = Result<u32, Error>>,
    columns: u32,
    out: &mut [u32],
) -> Result<(), Error> {
    let mut count = 0;
    for word in words.take(256) {
        let value = word? & (columns - 1);
        if !out[..count].contains(&value) {
            out[count] = value;
            count += 1;
            if count == out.len() {
                out.sort_unstable();
                return Ok(());
            }
        }
    }
    Err(Error::SamplingExhausted)
}
fn coefficients(
    words: impl Iterator<Item = Result<u32, Error>>,
    out: &mut [M31],
) -> Result<(), Error> {
    let mut count = 0;
    for word in words.take(256) {
        let value = word? & M31::MODULUS;
        if value != M31::MODULUS {
            out[count] = M31::from_u64(u64::from(value));
            count += 1;
            if count == out.len() {
                return Ok(());
            }
        }
    }
    Err(Error::SamplingExhausted)
}
struct Words<'a> {
    seed: &'a [u8; 32],
    level: u8,
    kind: u8,
    row: u32,
    stream: u8,
    at: usize,
    bytes: [u8; 32],
    blocks: &'a mut u64,
}
impl Iterator for Words<'_> {
    type Item = Result<u32, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.at == 256 {
            return None;
        }
        if self.at.is_multiple_of(8) {
            match stele_hash::setup::expander_block(
                self.seed,
                self.level,
                self.kind,
                self.row,
                self.stream,
                (self.at / 8) as u8,
            ) {
                Ok(bytes) => self.bytes = bytes,
                Err(_) => return Some(Err(Error::InvalidCodeId)),
            }
            *self.blocks += 1;
        }
        let at = (self.at % 8) * 4;
        self.at += 1;
        Some(Ok(u32::from_le_bytes([
            self.bytes[at],
            self.bytes[at + 1],
            self.bytes[at + 2],
            self.bytes[at + 3],
        ])))
    }
}
impl Expander {
    pub(crate) fn new(exponent: u8, seed: &[u8; 32], max_bytes: usize) -> Result<Self, Error> {
        let count = usize::try_from(edge_count(exponent)).map_err(|_| Error::Capacity)?;
        let bytes = count
            .checked_mul(size_of::<Edge>())
            .ok_or(Error::Capacity)?;
        if bytes > max_bytes {
            return Err(Error::Capacity);
        }
        let mut edges = reserved(count)?;
        if edges
            .capacity()
            .checked_mul(size_of::<Edge>())
            .ok_or(Error::Capacity)?
            > max_bytes
        {
            return Err(Error::Capacity);
        }
        let mut starts = [0; 16];
        let mut blocks = 0;
        for level in (4..=exponent).rev() {
            starts[usize::from(level)] = edges.len();
            let n = 1u32 << (2 * level);
            for kind in 0..2 {
                let (rows, columns, degree) = if kind == 0 {
                    (n, n / 4, A[usize::from(level - 4)])
                } else {
                    (n / 2, n / 2, B[usize::from(level - 4)])
                };
                for row in 0..rows {
                    let mut chosen = [0; 26];
                    let mut values = [M31::ZERO; 26];
                    neighbors(
                        Words {
                            seed,
                            level,
                            kind,
                            row,
                            stream: 0,
                            at: 0,
                            bytes: [0; 32],
                            blocks: &mut blocks,
                        },
                        columns,
                        &mut chosen[..degree],
                    )?;
                    coefficients(
                        Words {
                            seed,
                            level,
                            kind,
                            row,
                            stream: 1,
                            at: 0,
                            bytes: [0; 32],
                            blocks: &mut blocks,
                        },
                        &mut values[..degree],
                    )?;
                    edges.extend(chosen[..degree].iter().zip(&values).map(
                        |(column, coefficient)| Edge {
                            column: *column,
                            coefficient: *coefficient,
                        },
                    ));
                }
            }
        }
        Ok(Self {
            exponent,
            edges,
            starts,
            blocks,
        })
    }
    pub(crate) fn capacity_bytes(&self) -> usize {
        self.edges.capacity() * size_of::<Edge>()
    }
    pub(crate) fn hash_blocks(&self) -> u64 {
        self.blocks
    }
    pub(crate) fn encode<K: Element>(
        &self,
        row: &[K],
        memory: &mut Memory,
    ) -> Result<Vec<K>, Error> {
        self.level(self.exponent, row, memory)
    }
    fn level<K: Element>(&self, j: u8, row: &[K], memory: &mut Memory) -> Result<Vec<K>, Error> {
        if j == 3 {
            return Circle::new(6, 1)?.encode_counted(row, memory);
        }
        // A4: private state comes only from a checked CodeId and full regeneration.
        // Every level offset/product below fits the admitted graph length; row
        // lengths follow n -> n/4 and the fixed n=64 base, with no raw graph input.
        let n = row.len();
        let start = self.starts[usize::from(j)];
        let a_degree = A[usize::from(j - 4)];
        let b_degree = B[usize::from(j - 4)];
        let b_start = start + n * a_degree;
        let mut y = memory.reserve(n / 4)?;
        y.resize(n / 4, K::from_i64(0));
        sparse(row, &self.edges[start..b_start], a_degree, &mut y);
        let z = self.level(j - 1, &y, memory)?;
        memory.remove(memory::bytes(&y));
        drop(y);
        let mut out = memory.reserve(n.checked_mul(2).ok_or(Error::Capacity)?)?;
        out.extend_from_slice(row);
        out.extend_from_slice(&z);
        out.resize(2 * n, K::from_i64(0));
        sparse(
            &z,
            &self.edges[b_start..b_start + (n / 2) * b_degree],
            b_degree,
            &mut out[n + n / 2..],
        );
        memory.remove(memory::bytes(&z));
        Ok(out)
    }
}
fn sparse<K: Element>(row: &[K], edges: &[Edge], degree: usize, out: &mut [K]) {
    for (value, entries) in row.iter().zip(edges.chunks_exact(degree)) {
        for edge in entries {
            let at = edge.column as usize;
            out[at] = out[at] + *value * K::from_i64(i64::from(edge.coefficient.as_u32()));
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_exhausted_streams_and_accepts_last_word() {
        let words = |last| (0..257).map(move |i| Ok(if i == last { 1 } else { 0 }));
        assert_eq!(
            neighbors(words(256), 64, &mut [0; 2]),
            Err(Error::SamplingExhausted)
        );
        let mut out = [0; 2];
        neighbors(words(255), 64, &mut out).expect("last word");
        assert_eq!(out, [0, 1]);
        let words = |last| (0..257).map(move |i| Ok(if i == last { 0 } else { M31::MODULUS }));
        assert_eq!(
            coefficients(words(256), &mut [M31::ZERO]),
            Err(Error::SamplingExhausted)
        );
        coefficients(words(255), &mut [M31::ONE]).expect("zero accepted");
        let mut out = [M31::ONE; 2];
        coefficients([Ok(1 << 31), Ok(0)].into_iter(), &mut out).expect("zeros allowed");
        assert_eq!(out, [M31::ZERO; 2]);
    }
}
