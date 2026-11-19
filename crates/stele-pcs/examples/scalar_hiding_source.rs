//! RFC-0014 A5. Scalar A15 roots, selected column limbs and sibling paths.
#[path = "../../../tests/parity/hiding_cases.rs"]
mod cases;
use std::io;
use stele_field::{M31, QM31};
use stele_hash::HashUsage;
use stele_pcs::{Policy, PreparedSource};

fn main() -> io::Result<()> {
    cases::compare(|id, rows, cols, seed, words, indices, out| {
        let message: Vec<_> = words.iter().map(|w| M31::from_u64(u64::from(*w))).collect();
        let source = PreparedSource::<QM31>::hiding_with(
            id,
            rows.ilog2() as u8 - 1,
            cols.ilog2() as u8 - 1,
            2,
            &message,
            seed,
            &mut HashUsage::default(),
            Policy::Two,
        )
        .map_err(|e| io::Error::other(format!("scalar source {e:?}")))?;
        out.write_all(&source.source().root())?;
        for index in indices {
            let column = source
                .response(*index as u64)
                .map_err(|e| io::Error::other(format!("column {e:?}")))?;
            out.write_all(&column.payload[32..])?;
            for sibling in column.siblings {
                out.write_all(&sibling)?;
            }
        }
        Ok(())
    })
}
