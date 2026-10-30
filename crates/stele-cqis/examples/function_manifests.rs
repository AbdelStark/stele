//! RFC-0021 §4: full-byte manifest parity adapter; no model or proof admission.
#![forbid(unsafe_code)]
use std::io::{self, Read, Write};
use stele_cqis::functions::{Descriptor, Manifest, Representation};

fn u16le(input: &mut impl Read) -> Result<u16, String> {
    let mut bytes = [0; 2];
    input.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok(u16::from_le_bytes(bytes))
}

fn frame<const N: usize>(input: &mut impl Read, bytes: &mut [u8; N]) -> Result<usize, String> {
    let length = usize::from(u16le(input)?);
    if length > N {
        return Err("descriptor length exceeds capacity".into());
    }
    input
        .read_exact(&mut bytes[..length])
        .map_err(|e| e.to_string())?;
    Ok(length)
}

fn main() -> Result<(), String> {
    let mut input = io::BufReader::new(io::stdin().lock());
    let mut output = io::BufWriter::new(io::stdout().lock());
    loop {
        let mut count = [0; 2];
        if input.read(&mut count[..1]).map_err(|e| e.to_string())? == 0 {
            break;
        }
        input
            .read_exact(&mut count[1..])
            .map_err(|e| e.to_string())?;
        let count = usize::from(u16::from_le_bytes(count));
        if count > 513 {
            return Err("function count exceeds model adapter capacity".into());
        }
        let mut selected = Vec::new();
        selected
            .try_reserve_exact(count)
            .map_err(|e| e.to_string())?;
        for _ in 0..count {
            let mut function = [0; 128];
            let length = frame(&mut input, &mut function)?;
            let function = Descriptor::decode(&function[..length]).map_err(|e| format!("{e:?}"))?;
            let mut representation = [0; 192];
            let length = frame(&mut input, &mut representation)?;
            selected.push(
                Representation::decode(function, &representation[..length])
                    .map_err(|e| format!("{e:?}"))?,
            );
        }
        match Manifest::new(&selected) {
            Ok(manifest) => {
                for value in manifest.as_bytes() {
                    write!(output, "{value:02x}").map_err(|e| e.to_string())?;
                }
                writeln!(output).map_err(|e| e.to_string())?;
            }
            Err(error) => writeln!(output, "error {error:?}").map_err(|e| e.to_string())?,
        }
    }
    output.flush().map_err(|e| e.to_string())
}
