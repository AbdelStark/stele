//! RFC-0025 encoding §6: complete Registry parity adapter, without proof admission.
#![forbid(unsafe_code)]
use std::io::{self, Read, Write};
use stele_cqis::model::{Model, Registry};

fn main() -> Result<(), String> {
    let mut input = io::BufReader::new(io::stdin().lock());
    let mut output = io::BufWriter::new(io::stdout().lock());
    loop {
        let mut length = [0; 4];
        if input.read(&mut length[..1]).map_err(|e| e.to_string())? == 0 {
            break;
        }
        input
            .read_exact(&mut length[1..])
            .map_err(|e| e.to_string())?;
        let length = usize::try_from(u32::from_le_bytes(length)).map_err(|e| e.to_string())?;
        if length > 1 << 20 {
            return Err("Model frame exceeds capacity".into());
        }
        let mut raw = Vec::new();
        raw.try_reserve_exact(length).map_err(|e| e.to_string())?;
        raw.resize(length, 0);
        input.read_exact(&mut raw).map_err(|e| e.to_string())?;
        let model = Model::decode(&raw).map_err(|e| format!("{e:?}"))?;
        let registry = Registry::new(&model).map_err(|e| format!("{e:?}"))?;
        let length = u32::try_from(registry.as_bytes().len()).map_err(|e| e.to_string())?;
        output
            .write_all(&length.to_le_bytes())
            .map_err(|e| e.to_string())?;
        output
            .write_all(registry.as_bytes())
            .map_err(|e| e.to_string())?;
        output.flush().map_err(|e| e.to_string())?;
    }
    output.flush().map_err(|e| e.to_string())
}
