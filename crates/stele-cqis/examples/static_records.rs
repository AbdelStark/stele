//! RFC-0022 §6: full-byte parity adapter; no proof or authenticated plan.
#![forbid(unsafe_code)]
use std::io::{self, BufRead, Write};
use stele_cqis::{
    bounds::{Error, Record},
    functions::Descriptor,
    Format, Requant,
};

fn record(kind: &str, p: &[u8]) -> Result<Record, Error> {
    match (kind, p) {
        ("1", [m0, m1, shift, bits]) => {
            let format = match bits {
                8 => Format::Int8,
                16 => Format::Int16,
                _ => return Err(Error::Parameters),
            };
            let config = Requant::new(u32::from(u16::from_le_bytes([*m0, *m1])), u32::from(*shift))
                .map_err(|_| Error::Parameters)?;
            Record::requant(config, format)
        }
        ("2", p) => {
            Record::rmsnorm(Descriptor::new("rmsnorm_q", 1, p).map_err(|_| Error::Parameters)?)
        }
        _ => Err(Error::Parameters),
    }
}

fn main() -> Result<(), String> {
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let words: Vec<_> = line.split_whitespace().collect();
        if words.len() != 2 || !words[1].is_ascii() || words[1].len() % 2 != 0 {
            return Err("expected schema and exact parameter hex".into());
        }
        let p = (0..words[1].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&words[1][i..i + 2], 16).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        match record(words[0], &p) {
            Ok(record) => {
                for value in record.as_bytes() {
                    write!(output, "{value:02x}").map_err(|e| e.to_string())?;
                }
                writeln!(output).map_err(|e| e.to_string())?;
            }
            Err(error) => writeln!(output, "error {error:?}").map_err(|e| e.to_string())?,
        }
    }
    output.flush().map_err(|e| e.to_string())
}
