//! RFC-0014 A5. Public inputs shared by the independently built scalar and CUDA probes.
use std::io::{self, Write};

pub fn compare(
    run: impl Fn(u64, usize, usize, &[u8; 32], &[u32], &[usize], &mut dyn Write) -> io::Result<()>,
) -> io::Result<()> {
    let mut out = io::BufWriter::new(io::stdout().lock());
    let (mut cases, mut responses) = (0, 0);
    for id in 0..1000u64 {
        let rows = match id {
            0 => 512,
            1 => 1024,
            _ => 16 << (id as usize % 3),
        };
        let cols = 1024 << (id as usize % 2);
        let mut seed = id + 1;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u32
        };
        let salts = std::array::from_fn(|_| next() as u8);
        let words = (0..rows * cols)
            .map(|i| match i % 31 {
                0 => 0,
                1 => 1,
                2 => 0x7fff_fffe,
                _ => next() % 0x7fff_ffff,
            })
            .collect::<Vec<_>>();
        let last = 4 * cols - 1;
        let selected = next() as usize & last;
        let indices = [0, selected, last, selected];
        run(id, rows, cols, &salts, &words, &indices, &mut out)?;
        cases += 1;
        responses += indices.len();
    }
    out.flush()?;
    eprintln!("hiding_source_cases={cases} selected_columns={responses}");
    Ok(())
}
