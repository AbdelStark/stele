//! RFC-0012 A1 — emit the validated canonical registry for transcript construction.
use stele_hash::{registry, LabelKind, LossLine};
fn main() -> Result<(), String> {
    for entry in registry().map_err(|error| format!("{error:?}"))? {
        let kind = match entry.kind {
            LabelKind::Constructor => "constructor",
            LabelKind::Absorb => "absorb",
            LabelKind::Challenge => "challenge",
        };
        let loss = match entry.loss {
            None => "-",
            Some(LossLine::Sc) => "SC",
            Some(LossLine::Rlc) => "RLC",
            Some(LossLine::PcsTensor) => "PCS_TENSOR",
            Some(LossLine::PcsQuery) => "PCS_QUERY",
        };
        println!("{kind}\t{}\t{loss}", entry.label);
    }
    Ok(())
}
