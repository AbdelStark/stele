//! RFC-0025 encoding §1: checked reads and fallibly reserved metadata output.
use super::Error;
use alloc::vec::Vec;

pub(super) fn reserved<T>(count: usize) -> Result<Vec<T>, Error> {
    count
        .checked_mul(core::mem::size_of::<T>())
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or(Error::Capacity)?;
    let mut out = Vec::new();
    out.try_reserve_exact(count).map_err(|_| Error::Capacity)?;
    Ok(out)
}

pub(super) struct Reader<'a>(pub &'a [u8]);
impl<'a> Reader<'a> {
    pub fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let out = self.0.get(..count).ok_or(Error::Encoding)?;
        self.0 = self.0.get(count..).ok_or(Error::Encoding)?;
        Ok(out)
    }
    pub fn prefix(&mut self, expected: &[u8]) -> Result<(), Error> {
        if self.take(expected.len())? != expected {
            return Err(Error::Encoding);
        }
        Ok(())
    }
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Encoding)?,
        ))
    }
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Encoding)?,
        ))
    }
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Encoding)?,
        ))
    }
    pub fn blob(&mut self, limit: usize) -> Result<&'a [u8], Error> {
        let length = usize::try_from(self.u32()?).map_err(|_| Error::Capacity)?;
        if length > limit {
            return Err(Error::Capacity);
        }
        self.take(length)
    }
    pub fn end(self) -> Result<(), Error> {
        if !self.0.is_empty() {
            return Err(Error::Encoding);
        }
        Ok(())
    }
}

pub(super) struct Writer {
    bytes: Vec<u8>,
    limit: usize,
}
impl Writer {
    pub fn new(limit: usize) -> Result<Self, Error> {
        Ok(Self {
            bytes: reserved(limit)?,
            limit,
        })
    }
    pub fn push(&mut self, raw: &[u8]) -> Result<(), Error> {
        let end = self
            .bytes
            .len()
            .checked_add(raw.len())
            .ok_or(Error::Capacity)?;
        if end > self.limit {
            return Err(Error::Capacity);
        }
        self.bytes.extend_from_slice(raw);
        Ok(())
    }
    pub fn blob(&mut self, raw: &[u8]) -> Result<(), Error> {
        self.push(
            &u32::try_from(raw.len())
                .map_err(|_| Error::Capacity)?
                .to_le_bytes(),
        )?;
        self.push(raw)
    }
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
    pub fn position(&self) -> usize {
        self.bytes.len()
    }
}

pub(super) fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}
