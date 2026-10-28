//! RFC-0010 A4 — fixed expander setup expansion, never proof challenges.

/// Invalid fixed-domain setup record coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidSetupRecord;

/// Hash one validated v2 setup record into eight little-endian words.
/// The seed is public setup data. Proof randomness still uses Transcript only.
pub fn expander_block(
    seed: &[u8; 32],
    level: u8,
    kind: u8,
    row: u32,
    stream: u8,
    counter: u8,
) -> Result<[u8; 32], InvalidSetupRecord> {
    if !(4..=15).contains(&level) || kind > 1 || stream > 1 || counter >= 32 {
        return Err(InvalidSetupRecord);
    }
    let rows = (1u32 << (2 * level)) >> kind;
    if row >= rows {
        return Err(InvalidSetupRecord);
    }
    let mut h = blake3::Hasher::new();
    h.update(b"stele/v0.1/setup/expander/block/v2");
    h.update(seed);
    h.update(&[level, kind]);
    h.update(&row.to_le_bytes());
    h.update(&[stream, counter]);
    Ok(*h.finalize().as_bytes())
}
