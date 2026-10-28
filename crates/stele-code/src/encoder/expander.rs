//! Exact v2 capped row expansion and disjoint recursion, RFC-0010 A4.
use super::{Circle, CodeField, Error, M31};

pub(super) fn degrees(level: u8) -> (usize, usize) {
    // A4: the checked identity and recursion restrict outer levels to 4..=15.
    const A: [usize; 12] = [25, 21, 19, 19, 18, 18, 17, 17, 17, 18, 18, 18];
    const B: [usize; 12] = [26, 21, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18];
    (A[usize::from(level - 4)], B[usize::from(level - 4)])
}
fn stream(
    frame: &mut [u8; 74],
    hash: &mut impl FnMut(&[u8; 74]) -> [u8; 32],
    mut accept: impl FnMut(u32) -> bool,
) -> Result<(), Error> {
    for counter in 0..32 {
        frame[73] = counter;
        for chunk in hash(frame).chunks_exact(4) {
            if accept(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])) {
                return Ok(());
            }
        }
    }
    Err(Error::SamplingExhausted)
}
fn row(
    frame: &mut [u8; 74],
    columns: usize,
    degree: usize,
    hash: &mut impl FnMut(&[u8; 74]) -> [u8; 32],
) -> Result<([u32; 26], [M31; 26]), Error> {
    let mut chosen = [0; 26];
    let mut values = [M31::ZERO; 26];
    let mut used = 0;
    let mask = u32::try_from(columns - 1).map_err(|_| Error::Capacity)?;
    frame[72] = 0;
    stream(frame, hash, |word| {
        let column = word & mask;
        if !chosen[..used].contains(&column) {
            chosen[used] = column;
            used += 1;
        }
        used == degree
    })?;
    chosen[..degree].sort_unstable();
    frame[72] = 1;
    used = 0;
    stream(frame, hash, |word| {
        let value = word & 0x7fff_ffff;
        if value != 0x7fff_ffff {
            values[used] = M31::from_u64(u64::from(value));
            used += 1;
        }
        used == degree
    })?;
    Ok((chosen, values))
}
fn scatter<K: CodeField>(
    frame: &mut [u8; 74],
    source: &[K],
    target: &mut [K],
    degree: usize,
    hash: &mut impl FnMut(&[u8; 74]) -> [u8; 32],
) -> Result<(), Error> {
    for (i, value) in source.iter().enumerate() {
        frame[68..72]
            .copy_from_slice(&u32::try_from(i).map_err(|_| Error::Capacity)?.to_le_bytes());
        let (columns, coefficients) = row(frame, target.len(), degree, hash)?;
        for edge in 0..degree {
            let at = usize::try_from(columns[edge]).map_err(|_| Error::Capacity)?;
            target[at] = target[at] + value.mul_base(coefficients[edge]);
        }
    }
    Ok(())
}
pub(super) fn run<K: CodeField>(
    seed: &[u8],
    level: u8,
    source: &[K],
    output: &mut [K],
    work: &mut [K],
    hash: &mut impl FnMut(&[u8; 74]) -> [u8; 32],
) -> Result<(), Error> {
    if level == 3 {
        output.copy_from_slice(&Circle::new(6, 1)?.encode(source)?);
        return Ok(());
    }
    // A4: n=4^level, output=2n, work=(n-64)/3; these splits preserve child shapes.
    let n = source.len();
    let (prefix, tail) = output.split_at_mut(n);
    let (z, parity) = tail.split_at_mut(n / 2);
    let (y, rest) = work.split_at_mut(n / 4);
    prefix.copy_from_slice(source);
    let mut frame = [0; 74];
    frame[..34].copy_from_slice(b"stele/v0.1/setup/expander/block/v2");
    frame[34..66].copy_from_slice(seed);
    frame[66] = level;
    let (a, b) = degrees(level);
    scatter(&mut frame, source, y, a, hash)?;
    run(seed, level - 1, y, z, rest, hash)?;
    frame[67] = 1;
    scatter(&mut frame, z, parity, b, hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_last_capped_word_and_rejects_a_word_after_the_cap() {
        for final_counter in [31, 32] {
            let mut calls = 0;
            let mut hash = |frame: &[u8; 74]| {
                calls += 1;
                let mut out = [0; 32];
                if frame[73] == final_counter {
                    out[28] = 1;
                }
                out
            };
            let result = stream(&mut [0; 74], &mut hash, |word| word == 1);
            assert_eq!(
                result,
                if final_counter == 31 {
                    Ok(())
                } else {
                    Err(Error::SamplingExhausted)
                }
            );
            assert_eq!(calls, 32);
        }
    }
}
