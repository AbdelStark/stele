//! RFC-0004 A1 / §5.2: line-oriented scalar parity adapter, not a proof consumer.
use std::io::{self, BufRead, Write};
use stele_cqis::{residual_add, Format, Requant};

fn integer<T: std::str::FromStr>(text: &str) -> Result<T, String> {
    text.parse().map_err(|_| "invalid integer".into())
}

fn main() -> Result<(), String> {
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let words: Vec<_> = line.split_whitespace().collect();
        let result = match words.as_slice() {
            [op @ ("q8" | "q16"), acc, mantissa, shift] => {
                let format = if *op == "q8" {
                    Format::Int8
                } else {
                    Format::Int16
                };
                let acc = integer(acc)?;
                Requant::new(integer(mantissa)?, integer(shift)?)
                    .and_then(|scale| scale.apply(acc, format))
            }
            ["add", left, right] => residual_add(integer(left)?, integer(right)?),
            _ => return Err("expected q8|q16 acc mantissa shift, or add left right".into()),
        };
        match result {
            Ok(value) => writeln!(output, "ok {value}"),
            Err(error) => writeln!(output, "error {error:?}"),
        }
        .map_err(|e| e.to_string())?;
    }
    output.flush().map_err(|e| e.to_string())
}
