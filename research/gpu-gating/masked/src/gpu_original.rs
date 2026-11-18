//! RFC-0013 A5 and RFC-0014 A1: one immutable M' device allocation per hiding source.
use super::{Device, Error};
#[cfg(test)]
use crate::Field;
use crate::M31;
use cudarc::driver::CudaSlice;

pub struct OriginalMessage<'d> {
    dev: &'d Device,
    id: u64,
    rows: usize,
    columns: usize,
    words: CudaSlice<u32>,
}

impl<'d> OriginalMessage<'d> {
    /// Stage the actual source once, using at most four MiB of page-locked host memory.
    pub fn upload(
        dev: &'d Device,
        id: u64,
        rows: usize,
        columns: usize,
        message: &[M31],
    ) -> Result<Self, Error> {
        Self::upload_words(dev, id, rows, columns, message, 0)
    }

    #[cfg(test)]
    pub(super) fn upload_raw(
        dev: &'d Device,
        id: u64,
        rows: usize,
        columns: usize,
        message: &[M31],
    ) -> Result<Self, Error> {
        Self::upload_words(dev, id, rows, columns, message, M31::MODULUS)
    }

    fn upload_words(
        dev: &'d Device,
        id: u64,
        rows: usize,
        columns: usize,
        message: &[M31],
        lift: u32,
    ) -> Result<Self, Error> {
        if !rows.is_power_of_two()
            || !columns.is_power_of_two()
            || rows.checked_mul(columns) != Some(message.len())
        {
            return Err(Error::Shape("original message extent"));
        }
        let bytes = message
            .len()
            .checked_mul(4)
            .ok_or(Error::Shape("original message bytes"))?;
        dev.require_budget(bytes)?;
        let mut words = dev.stream.alloc_zeros::<u32>(message.len())?;
        let tile = message.len().min(1 << 20);
        // SAFETY: every page-locked u32 is initialized before its first DMA read.
        let mut staging = unsafe { dev.ctx.alloc_pinned::<u32>(tile) }?;
        // Both the message and the tile have power-of-two lengths. Each transfer
        // fills the entire staging allocation; its event orders successive uses.
        for (i, chunk) in message.chunks_exact(tile).enumerate() {
            let dst = staging.as_mut_ptr()?;
            for (j, value) in chunk.iter().enumerate() {
                // SAFETY: the staging event has completed. j < tile, and this
                // unique mutable borrow initializes the word before the copy.
                unsafe { dst.add(j).write(value.as_u32() + lift) };
            }
            dev.stream
                .memcpy_htod(&staging, &mut words.slice_mut(i * tile..(i + 1) * tile))?;
        }
        dev.sync()?;
        Ok(Self {
            dev,
            id,
            rows,
            columns,
            words,
        })
    }

    pub fn words(
        &self,
        dev: &Device,
        id: u64,
        rows: usize,
        columns: usize,
    ) -> Result<&CudaSlice<u32>, Error> {
        if !std::ptr::eq(dev, self.dev) || (id, rows, columns) != (self.id, self.rows, self.columns)
        {
            return Err(Error::Shape("original message identity"));
        }
        Ok(&self.words)
    }
    pub fn bytes(&self) -> usize {
        4 * self.words.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        batch_cases, gpu_source,
        source::{material, Shape},
    };
    #[test]
    #[ignore = "requires an explicitly allocated H100"]
    fn matches_reference_original_source_responses_on_h100() {
        let dev = Device::new().expect("CUDA device");
        assert!(dev.name.contains("H100"));
        for case in 0..batch_cases::CASES {
            let seed = batch_cases::SEED + 2 * case as u64;
            let message = batch_cases::message(seed);
            let shape = Shape {
                id: 73,
                ell: batch_cases::ELL,
                m: batch_cases::M,
                seed: batch_cases::source_seed(seed),
            };
            let expected = material(&shape, &message).unwrap();
            let source = shape.source().unwrap();
            for raw in [false, true] {
                let upload = if raw {
                    OriginalMessage::upload_raw
                } else {
                    OriginalMessage::upload
                };
                let owner =
                    upload(&dev, shape.id, source.rows(), source.columns(), &message).unwrap();
                let (state, mut timing) =
                    gpu_source::prepare_from_original(&dev, &shape, &owner).unwrap();
                assert_eq!(state.root(), expected.root());
                let end = (source.codeword_len() - 1) as u64;
                for index in [0, seed & end, end] {
                    let (leaf, path) = expected.response(index).unwrap();
                    let got = state.response(index, &mut timing).unwrap();
                    assert_eq!((got.0.as_slice(), got.1), (leaf, path));
                }
            }
        }
        eprintln!("pinned_pcs_cases=1000 representations=2000 responses=6000");
    }
}
