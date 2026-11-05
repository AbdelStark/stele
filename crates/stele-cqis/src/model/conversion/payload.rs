//! RFC-0025 conversion §2/encoding §3: continuous codes, without row padding.
use super::{
    view::{Cache, Tensor},
    Error,
};
use crate::model::{Model, Scales, SourcePackage};

pub(super) struct Payload<'s, 'a> {
    model: &'s Model,
    package: &'s SourcePackage<'a>,
    scales: &'s Scales,
    tensor: Option<Tensor<'s, 'a>>,
    ordinal: Option<u16>,
    next: u64,
    pending: Option<u8>,
}
impl<'s, 'a> Payload<'s, 'a> {
    pub fn new(model: &'s Model, package: &'s SourcePackage<'a>, scales: &'s Scales) -> Self {
        Self {
            model,
            package,
            scales,
            tensor: None,
            ordinal: None,
            next: 0,
            pending: None,
        }
    }
    pub fn read<E>(
        &mut self,
        ordinal: u16,
        out: &mut [u8],
        cache: &mut Cache,
        read: &mut impl FnMut(&str, u64, &mut [u8]) -> Result<usize, E>,
    ) -> Result<usize, Error> {
        if self.ordinal != Some(ordinal) {
            self.tensor = Some(Tensor::new(
                self.package,
                self.model
                    .shape()
                    .physical(ordinal)
                    .ok_or(Error::Physical)?,
            )?);
            self.ordinal = Some(ordinal);
            self.next = 0;
            self.pending = None;
        }
        let tensor = self.tensor.as_ref().ok_or(Error::Physical)?;
        let format = self.model.formats()[usize::from(ordinal)];
        let scale = self.scales.matrix(ordinal);
        let mut code = |index| {
            let scalar = tensor.scalar(index, cache, read)?;
            if format.bits() == 16 {
                scalar.vector(format.parameter())
            } else {
                let scale = scale.ok_or(Error::Physical)?;
                let row =
                    usize::try_from(index / tensor.columns).map_err(|_| Error::SourceOffset)?;
                scalar.weight(
                    scale.exponent(),
                    *scale.mantissas().get(row).ok_or(Error::Physical)?,
                    format.bits(),
                )
            }
        };
        let mut count = 0;
        for byte in out {
            if let Some(pending) = self.pending.take() {
                *byte = pending;
            } else {
                if self.next == tensor.count {
                    break;
                }
                let value = code(self.next)?;
                self.next += 1;
                *byte = match format.bits() {
                    4 => {
                        let high = if self.next < tensor.count {
                            let v = code(self.next)?;
                            self.next += 1;
                            v as u8 & 15
                        } else {
                            0
                        };
                        (value as u8 & 15) | (high << 4)
                    }
                    8 => value as u8,
                    16 => {
                        let pair = value.to_le_bytes();
                        self.pending = Some(pair[1]);
                        pair[0]
                    }
                    _ => return Err(Error::Physical),
                };
            }
            count += 1;
        }
        Ok(count)
    }
}
