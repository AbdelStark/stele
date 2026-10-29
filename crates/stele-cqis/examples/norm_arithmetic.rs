//! RFC-0021 §2.3: numerical parity adapter, not a certificate or proof consumer.
#![forbid(unsafe_code)]
use std::io::{self, BufRead, Write};
use stele_cqis::functions::Descriptor;

fn integer<T: std::str::FromStr>(text: &str) -> Result<T, String> {
    text.parse().map_err(|_| "invalid integer".into())
}

fn main() -> Result<(), String> {
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let words: Vec<_> = line.split_whitespace().collect();
        if words.len() < 6 {
            return Err("expected d F G E en ed, followed by input and gain rows".into());
        }
        let d: u16 = integer(words[0])?;
        let mut parameters = d.to_le_bytes().to_vec();
        for word in &words[1..4] {
            parameters.push(integer::<u8>(word)?);
        }
        for word in &words[4..6] {
            parameters.extend(integer::<u32>(word)?.to_le_bytes());
        }
        let descriptor = Descriptor::new("rmsnorm_q", 1, &parameters)
            .map_err(|e| format!("invalid descriptor: {e:?}"))?;
        let d = usize::from(d);
        if words.len() != 6 + 2 * d {
            return Err("wrong row length".into());
        }
        let values = words[6..]
            .iter()
            .map(|v| integer::<i16>(v))
            .collect::<Result<Vec<_>, _>>()?;
        match descriptor.evaluate_rmsnorm(&values[..d], &values[d..]) {
            Ok(row) => {
                let (n, p) = row.ratio();
                let (a, d, r) = row.normalized_ratio();
                write!(
                    output,
                    "ok {} {n} {p} {a} {d} {r} {} {} {} {}",
                    row.statistic(),
                    row.exponent(),
                    row.mantissa(),
                    row.reciprocal(),
                    row.shift()
                )
                .map_err(|e| e.to_string())?;
                for value in row.outputs() {
                    write!(output, " {value}").map_err(|e| e.to_string())?;
                }
                writeln!(output).map_err(|e| e.to_string())?;
            }
            Err(error) => writeln!(output, "error {error:?}").map_err(|e| e.to_string())?,
        }
    }
    output.flush().map_err(|e| e.to_string())
}
