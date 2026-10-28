//! RFC-0006 A6 §1: read-only canonical files and separate bounded preparation.
use crate::{
    reserve,
    streaming::{pow2, reverse},
    Error, Instance, Source,
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
use stele_hash::ChallengeField;

/// Successful record operations and EOF probes; not OS-cache or physical-disk traffic.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IoCounts {
    /// Complete canonical records read.
    pub reads: u64,
    /// Complete records written.
    pub writes: u64,
    /// Explicit seeks, including rewinds.
    pub seeks: u64,
    /// Bytes in complete records read.
    pub read_bytes: u64,
    /// Bytes in complete records written.
    pub written_bytes: u64,
    /// Successful EOF probes (zero bytes returned).
    pub eof_checks: u64,
}
fn add(counter: &mut u64, n: u64) -> Result<(), Error> {
    *counter = counter.checked_add(n).ok_or(Error::Capacity)?;
    Ok(())
}
fn io<T>(result: std::io::Result<T>) -> Result<T, Error> {
    result.map_err(|_| Error::Source)
}
fn length<K: ChallengeField>(m: u32) -> Result<(usize, u64), Error> {
    let records = pow2(m)?;
    let bytes = u64::try_from(records)
        .map_err(|_| Error::Capacity)?
        .checked_mul((4 * K::DEGREE) as u64)
        .ok_or(Error::Capacity)?;
    Ok((records, bytes))
}
fn check_length(file: &File, expected: u64) -> Result<(), Error> {
    let metadata = io(file.metadata())?;
    if !metadata.is_file() || metadata.len() != expected {
        return Err(Error::Source);
    }
    Ok(())
}
fn read<K: ChallengeField>(file: &mut File, counts: &mut IoCounts) -> Result<K, Error>
where
    K::Bytes: AsMut<[u8]>,
{
    let mut bytes = K::from_i64(0).to_le_bytes();
    io(file.read_exact(bytes.as_mut()))?;
    let value = K::from_le_bytes(bytes).ok_or(Error::Source)?;
    add(&mut counts.reads, 1)?;
    add(&mut counts.read_bytes, (4 * K::DEGREE) as u64)?;
    Ok(value)
}
fn eof(file: &mut File, counts: &mut IoCounts) -> Result<(), Error> {
    if io(file.read(&mut [0; 1]))? != 0 {
        return Err(Error::Source);
    }
    add(&mut counts.eof_checks, 1)
}
/// Owns read-only handles; ids borrow the original descriptor, with no retained paths.
/// The file owner must preserve contents. Handles/metadata do not authenticate inputs.
pub struct FileSource<'a, K> {
    ids: &'a [u64],
    m: u32,
    files: Vec<File>,
    records: usize,
    remaining: usize,
    bytes: u64,
    counts: IoCounts,
    field: PhantomData<K>,
}
impl<'a, K: ChallengeField> FileSource<'a, K>
where
    K::Bytes: AsMut<[u8]>,
{
    /// Open one prepared file per input and validate every length before proving.
    pub fn open(i: &'a Instance<K>, paths: &[impl AsRef<Path>]) -> Result<Self, Error> {
        i.validate()?;
        if paths.len() != i.inputs.len() {
            return Err(Error::PublicShape);
        }
        let (records, bytes) = if paths.is_empty() {
            (pow2(i.num_vars)?, 0)
        } else {
            length::<K>(i.num_vars)?
        };
        let mut files = Vec::new();
        reserve(&mut files, paths.len())?;
        for path in paths {
            let file = io(File::open(path))?;
            check_length(&file, bytes)?;
            files.push(file);
        }
        Ok(Self {
            ids: &i.inputs,
            m: i.num_vars,
            files,
            records,
            remaining: records,
            bytes,
            counts: IoCounts::default(),
            field: PhantomData,
        })
    }
    /// Actual retained file-vector capacity; borrowed ids belong to caller accounting.
    /// Inline state, kernel handle storage and filesystem cache are separate.
    pub fn heap_bytes(&self) -> Result<usize, Error> {
        self.files
            .capacity()
            .checked_mul(core::mem::size_of::<File>())
            .ok_or(Error::Capacity)
    }
    /// Cumulative successful operations; reads on failed attempts may be partial.
    pub fn counts(&self) -> IoCounts {
        self.counts
    }
}
impl<K: ChallengeField> Source<K> for FileSource<'_, K>
where
    K::Bytes: AsMut<[u8]>,
{
    fn input_ids(&self) -> &[u64] {
        self.ids
    }
    fn num_vars(&self) -> u32 {
        self.m
    }
    fn rewind(&mut self) -> Result<(), Error> {
        for file in &mut self.files {
            check_length(file, self.bytes)?;
            io(file.seek(SeekFrom::Start(0)))?;
            add(&mut self.counts.seeks, 1)?;
        }
        self.remaining = self.records;
        Ok(())
    }
    fn next_row(&mut self, out: &mut [K]) -> Result<bool, Error> {
        if out.len() != self.files.len() {
            return Err(Error::PublicShape);
        }
        if self.remaining == 0 {
            for file in &mut self.files {
                eof(file, &mut self.counts)?;
            }
            return Ok(false);
        }
        for (file, value) in self.files.iter_mut().zip(out) {
            *value = read(file, &mut self.counts)?;
        }
        self.remaining -= 1;
        Ok(true)
    }
}
/// Convert one canonical row-major input to a separate bit-reversed file.
/// Reads once with fixed record scratch and positioned output writes; never overwrites.
/// Failure attempts to remove or truncate the new output; discard it on every error,
/// including filesystem cleanup failure. Only a successful return authorizes use.
/// Caller paths and filesystem/allocator costs are separate from the record scratch.
pub fn prepare<K: ChallengeField>(
    original: &Path,
    destination: &Path,
    m: u32,
) -> Result<IoCounts, Error>
where
    K::Bytes: AsMut<[u8]>,
{
    let (records, bytes) = length::<K>(m)?;
    let mut input = io(File::open(original))?;
    check_length(&input, bytes)?;
    let mut output = io(OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination))?;
    let result = (|| {
        let mut counts = IoCounts::default();
        for j in 0..records {
            let value = read::<K>(&mut input, &mut counts)?;
            let offset = (reverse(j, m) as u64)
                .checked_mul((4 * K::DEGREE) as u64)
                .ok_or(Error::Capacity)?;
            io(output.seek(SeekFrom::Start(offset)))?;
            add(&mut counts.seeks, 1)?;
            io(output.write_all(value.to_le_bytes().as_ref()))?;
            add(&mut counts.writes, 1)?;
            add(&mut counts.written_bytes, (4 * K::DEGREE) as u64)?;
        }
        eof(&mut input, &mut counts)?;
        io(output.flush())?;
        check_length(&output, bytes)?;
        Ok(counts)
    })();
    if result.is_err() {
        // A6 §1: invalidate before unlink, so an unlink failure leaves a wrong-length file.
        let truncated = output.set_len(0);
        drop(output);
        let removed = fs::remove_file(destination);
        if truncated.is_err() && removed.is_err() {
            return Err(Error::Source);
        }
    }
    result
}
