//! RFC-0025 request §4: full-capacity token, stop and canonical byte bounds.
use super::{term, Builder, Error, Record, Word};

/// Request-boundary parameters; observed request lengths do not narrow bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    /// Full vocabulary size, in 1..=2^20.
    pub vocabulary: u32,
    /// Full context capacity, in 1..=2^20.
    pub context: u32,
    /// Greedy=0 or sampled=1.
    pub mode: u8,
}
impl Record {
    /// Derive schema 18; stop, mask, token and seed consumers remain separate.
    pub fn request(p: Request) -> Result<Self, Error> {
        if !(1..=1 << 20).contains(&p.vocabulary)
            || !(1..=1 << 20).contains(&p.context)
            || p.mode > 1
        {
            return Err(Error::Parameters);
        }
        let v = u64::from(p.vocabulary);
        let n = u64::from(p.context);
        let (np, vp) = (n.next_power_of_two(), v.next_power_of_two());
        let rh = b"stele/v0.1/cqis/request-boundary".len() as u64 + 13;
        let ih = b"stele/v0.1/cqis/token-io".len() as u64 + 9;
        let scalars = [
            n,
            n - 1,
            v - 1,
            np,
            2 * np - 1,
            vp,
            2 * vp - 1,
            u64::from(np.trailing_zeros()),
            u64::from(vp.trailing_zeros()),
            rh,
            ih,
            rh + 4 * v + 32 * u64::from(p.mode),
            ih + 4 * n,
            u64::from(u32::MAX),
        ]
        .map(Word::from);
        let mut params = [0; 9];
        params[..4].copy_from_slice(&p.vocabulary.to_le_bytes());
        params[4..8].copy_from_slice(&p.context.to_le_bytes());
        params[8] = p.mode;
        let mut b = Builder::new(18, &params, 8, &scalars, &[], 16)?;
        b.column(&[term(n, 1), term(n, 1), term(n, 1)])?;
        b.column(&[term(n, 1), term(n, 1)])?;
        b.column(&[term(n, 1), term(n, 1)])?;
        b.column(&[term(n, 1), term(n - 1, 1)])?;
        b.column(&[term(n - 1, 1), term(1, 1)])?;
        b.column(&[term(n - 1, 1), term(1, 1)])?;
        b.column(&[term(n - 1, 1)])?;
        b.column(&[(p.context, 1.into(), 1.into())])?;
        b.column(&[term(1, 1)])?;
        b.column(&[term(n, 1)])?;
        b.column(&[term(n - 1, 4)])?;
        b.column(&[term(4 * (n - 1), 1), term(3, 1), term(ih, 1)])?;
        b.column(&[term(v - 1, 4)])?;
        b.column(&[term(4 * (v - 1), 1), term(3, 1), term(rh, 1)])?;
        b.column(&[
            term(255, 1),
            term(255, 256),
            term(255, 65536),
            term(255, 1 << 24),
        ])?;
        b.column(&[term(v - 1, 1), term(v - 1, 1), term(1, 1)])?;
        b.finish()
    }
}
