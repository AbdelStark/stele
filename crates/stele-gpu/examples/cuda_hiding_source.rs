//! RFC-0014 A5. Required-device roots, selected column limbs and sibling paths.
#[path = "../../../tests/parity/hiding_cases.rs"]
mod cases;
use std::io;
use stele_gpu::Cuda;
use stele_kernels::{Backend, HidingBackend, SourceGeometry, M31};

fn main() -> io::Result<()> {
    let device = Cuda::new().map_err(io::Error::other)?;
    cases::compare(|id, rows, columns, seed, words, indices, out| {
        let session = device.session();
        let geometry = SourceGeometry { id, rows, columns };
        let message: Vec<_> = words.iter().map(|w| M31::from_u64(u64::from(*w))).collect();
        let original = session
            .original(geometry, &message)
            .map_err(io::Error::other)?;
        let mut hashes = 0;
        let (tree, root) = session
            .prepare_columns(geometry, &original, seed, &mut hashes)
            .map_err(io::Error::other)?;
        out.write_all(&root)?;
        for &index in indices {
            let column = session
                .selected_column(geometry, &tree, index)
                .map_err(io::Error::other)?;
            for value in column.symbols {
                out.write_all(&value.as_u32().to_le_bytes())?;
            }
            for sibling in column.siblings {
                out.write_all(&sibling)?;
            }
        }
        if id == 0 {
            let other = device.session();
            assert!(other
                .prepare_columns(geometry, &original, seed, &mut hashes)
                .is_err());
            assert!(other.selected_column(geometry, &tree, 0).is_err());
            assert!(session
                .selected_column(geometry, &tree, columns * 4)
                .is_err());
        }
        assert_eq!(hashes, (8 * columns - 1) as u64);
        assert_eq!(session.counts().source_hashes, hashes);
        assert_eq!(session.counts().source_visits, 1);
        assert_eq!(session.counts().source_responses, 4);
        Ok(())
    })
}
