//! RFC-0025 physical §§1–3: complete tensor/scale bytes from checked Shape roles.
use super::{term, Builder, Error, Record, Word};
use crate::model::Shape;

impl Record {
    /// Derive schema 19 from the prescribed ordinal/geometry and expected format.
    /// This does not establish original-source quantization or Artifact authority.
    pub fn physical(shape: Shape, ordinal: u16, bits: u8, parameter: u8) -> Result<Self, Error> {
        let physical = shape.physical(ordinal).ok_or(Error::Parameters)?;
        let dims = physical.dimensions();
        let matrix = dims.len() == 2;
        if (matrix && (!matches!(bits, 4 | 8) || parameter != 0))
            || (!matrix && (bits != 16 || parameter > 30))
        {
            return Err(Error::Parameters);
        }
        let (rows, columns) = if matrix {
            (u64::from(dims[0]), u64::from(dims[1]))
        } else {
            (1, u64::from(dims[0]))
        };
        // Shape proves N<=2^34. All byte/address arithmetic below fits u64.
        let n = rows * columns;
        let size = (n * u64::from(bits)).div_ceil(8);
        let first = if bits == 4 {
            (n - 1) / 2
        } else {
            (n - 1) * u64::from(bits / 8)
        };
        let descriptor_len = 2 + 1 + 4 * dims.len() + 2;
        let scale_start = b"stele/v0.1/cqis/tensor".len() as u64 + 4 + descriptor_len as u64;
        let header = scale_start + if matrix { 2 + 2 * rows } else { 0 } + 8;
        let full = 1u64 << bits;
        let half = full / 2;
        let negative = if matrix { half - 1 } else { half };
        let offset = negative + half - 1;
        let (lane, tail, odd) = (
            u64::from(bits == 4),
            u64::from(bits == 16),
            if bits == 4 { n % 2 } else { 0 },
        );
        let mut scalars = [Word::from(0); 30];
        scalars[..17].copy_from_slice(
            &[
                rows,
                columns,
                n,
                n - 1,
                size,
                size - 1,
                first,
                header,
                header + size,
                header + size - 1,
                full - 1,
                half,
                negative,
                offset,
                lane,
                tail,
                odd,
            ]
            .map(Word::from),
        );
        let ms = scale_start + 2;
        let last = ms + 2 * (rows - 1);
        if matrix {
            scalars[17..].copy_from_slice(
                &[
                    scale_start,
                    scale_start + 1,
                    ms,
                    last,
                    last + 1,
                    header - 8,
                    65535,
                    65534,
                    1099,
                    1024,
                    2123,
                    65536,
                    32768,
                ]
                .map(Word::from),
            );
        }
        let mut params = [0; 34];
        params[..21].copy_from_slice(&shape.encode());
        params[21..23].copy_from_slice(&ordinal.to_le_bytes());
        params[23] = dims.len() as u8;
        for (i, d) in dims.iter().enumerate() {
            params[24 + 4 * i..28 + 4 * i].copy_from_slice(&d.to_le_bytes());
        }
        let at = 24 + 4 * dims.len();
        params[at..at + 2].copy_from_slice(&[bits, parameter]);
        let mut b = Builder::new(
            19,
            &params[..21 + descriptor_len],
            8,
            &scalars[..if matrix { 30 } else { 17 }],
            &[],
            8 + u8::from(bits == 4) + 8 * u8::from(matrix),
        )?;
        b.column(&[term(rows - 1, columns), term(columns - 1, 1)])?;
        if bits == 4 {
            b.column(&[term(first, 2), term(1, 1)])?;
        } else {
            b.column(&[term(n - 1, u64::from(bits / 8))])?;
        }
        b.column(&[term(first, 1), term(tail, 1)])?;
        b.column(&[term(size - 1, 1), term(header, 1)])?;
        match bits {
            4 => b.column(&[term(15, 1), term(15, 16)])?,
            16 => b.column(&[term(255, 1), term(255, 256)])?,
            _ => b.column(&[term(255, 1)])?,
        }
        b.column(&[term(half - 1, 1), term(1, half)])?;
        b.column(&[term(full - 1, 1), term(negative, 1)])?;
        b.column(&[term(offset, 1), term(1, full)])?;
        if bits == 4 {
            b.column(&[term(1, 15), term(1, 15)])?;
        }
        if matrix {
            b.column(&[term(rows - 1, 2), term(ms, 1)])?;
            b.column(&[term(last, 1), term(1, 1)])?;
            b.column(&[term(255, 1), term(255, 256)])?;
            b.column(&[term(65534, 1), term(1, 1)])?;
            b.column(&[term(255, 1), term(255, 256)])?;
            b.column(&[term(32767, 1), term(1, 32768)])?;
            b.column(&[term(65535, 1), term(1099, 1)])?;
            b.column(&[term(2123, 1), term(1, 65536)])?;
        }
        let record = b.finish()?;
        if record.as_bytes().len() >= 36000 {
            return Err(Error::Capacity);
        }
        Ok(record)
    }
}
