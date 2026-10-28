//! Bounded research corpus adapter for RFC-0010 A4, not a proof wire format.
#![forbid(unsafe_code)]
use std::io::{self, Read, Write};
use stele_code::{Code, CodeField, Encoder};
use stele_field::{M31, OM31, QM31};

fn bytes<const N: usize>(input: &mut impl Read) -> Result<[u8; N], String> {
    let mut out = [0; N];
    input.read_exact(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}
fn count(input: &mut impl Read) -> Result<usize, String> {
    usize::try_from(u32::from_le_bytes(bytes(input)?)).map_err(|e| e.to_string())
}
fn run<K: CodeField>(
    input: &mut impl Read,
    output: &mut impl Write,
    code: &Encoder,
    n: usize,
    q: usize,
) -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let width = 4 * usize::from(K::DEGREE);
    let mut row = Vec::with_capacity(n);
    for _ in 0..n {
        let mut raw = [0; 32];
        input
            .read_exact(&mut raw[..width])
            .map_err(|e| e.to_string())?;
        let value = K::Bytes::try_from(&raw[..width]).map_err(|_| "field width")?;
        row.push(K::from_le_bytes(value).ok_or("noncanonical field")?);
    }
    let columns = (0..q)
        .map(|_| count(input))
        .collect::<Result<Vec<_>, _>>()?;
    let word = code.encode(&row).map_err(|e| format!("{e:?}"))?;
    let selected = code
        .eval_row(&row, &columns)
        .map_err(|e| format!("{e:?}"))?;
    for value in word.into_iter().chain(selected) {
        output
            .write_all(value.to_le_bytes().as_ref())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn main() -> Result<(), String> {
    let mut input = io::stdin().lock();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let cases = count(&mut input)?;
    if !(1..=10_000).contains(&cases) {
        return Err("case count".into());
    }
    for _ in 0..cases {
        let [degree, length] = bytes(&mut input)?;
        if ![21, 55].contains(&length) {
            return Err("identity length".into());
        }
        let mut raw = [0; 55];
        input
            .read_exact(&mut raw[..usize::from(length)])
            .map_err(|e| e.to_string())?;
        let code =
            Encoder::from_code_id(&raw[..usize::from(length)]).map_err(|e| format!("{e:?}"))?;
        let (n, q) = (count(&mut input)?, count(&mut input)?);
        // Bound research-adapter allocations before reading caller-controlled data.
        if n > 1024 || q > 8 || code.info().codeword_len > 4096 {
            return Err("corpus bounds".into());
        }
        match degree {
            1 => run::<M31>(&mut input, &mut output, &code, n, q)?,
            4 => run::<QM31>(&mut input, &mut output, &code, n, q)?,
            8 => run::<OM31>(&mut input, &mut output, &code, n, q)?,
            _ => return Err("field degree".into()),
        }
    }
    if input.read(&mut [0]).map_err(|e| e.to_string())? != 0 {
        return Err("trailing bytes".into());
    }
    output.flush().map_err(|e| e.to_string())
}
