//! RFC-0010 A6: typed signed values to exactly one canonical M31 message element each.
//! Raw storage bytes belong to RFC-0011; a commitment proves no width (A6 resolution).
use crate::Error;
use alloc::vec::Vec;
use stele_field::{Field, M31};

/// Message embedding named by the consuming RFC's expected statement, one per source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Embedding {
    /// Field image of x: x for x>=0, p+x for x<0 (RFC-0007 §2).
    Signed,
    /// x+2^(w-1) in [0,2^w) (RFC-0024 §1 at w=8).
    Offset,
}

mod private {
    pub trait Sealed {}
    impl Sealed for i8 {}
    impl Sealed for i16 {}
}

/// A typed signed w-bit value; sealed to the int8 and int16 types A6 names.
/// ```compile_fail
/// use stele_pcs::{expand, Embedding};
/// let _ = expand(&[1i32], Embedding::Signed);
/// ```
pub trait Value: private::Sealed + Copy + Into<i32> {
    /// Bit width w.
    const WIDTH: u32;
}
impl Value for i8 {
    const WIDTH: u32 = 8;
}
impl Value for i16 {
    const WIDTH: u32 = 16;
}

/// Expand values in their given row-major (layout 0) order, one element per value.
/// Both embeddings are injective on [-2^(w-1),2^(w-1)) because 2^24 < p.
pub fn expand<T: Value>(values: &[T], embedding: Embedding) -> Result<Vec<M31>, Error> {
    let shift = match embedding {
        Embedding::Signed => 0,
        Embedding::Offset => 1i64 << (T::WIDTH - 1),
    };
    let mut message = Vec::new();
    message
        .try_reserve_exact(values.len())
        .map_err(|_| Error::Capacity)?;
    message.extend(
        values
            .iter()
            .map(|value| M31::from_i64(i64::from((*value).into()) + shift)),
    );
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    #[test]
    fn matches_reference_signed_and_offset_embeddings() {
        let p = i64::from(M31::MODULUS);
        for (x, signed, offset) in [
            (-128i8, p - 128, 0),
            (-1, p - 1, 127),
            (0, 0, 128),
            (127, 127, 255),
        ] {
            assert_eq!(
                expand(&[x], Embedding::Signed),
                Ok(vec![M31::from_i64(signed)])
            );
            assert_eq!(
                expand(&[x], Embedding::Offset),
                Ok(vec![M31::from_i64(offset)])
            );
        }
        let all: Vec<i16> = (i16::MIN..=i16::MAX).collect();
        for embedding in [Embedding::Signed, Embedding::Offset] {
            let message = expand(&all, embedding).expect("expansion");
            assert_eq!(message.len(), all.len());
            let mut seen: Vec<u32> = message.iter().map(|x| x.as_u32()).collect();
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), all.len(), "injective on the int16 range");
        }
        assert_eq!(
            expand(&[i16::MIN, i16::MAX], Embedding::Offset),
            Ok(vec![M31::from_i64(0), M31::from_i64(65535)])
        );
    }
}
