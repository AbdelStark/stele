//! RFC-0010 A16. Untrusted producer storage for individual transcript-selected columns.
use crate::{Error, PreparationWork, PreparedColumn};
use alloc::{borrow::Cow, vec::Vec};
use stele_hash::{merkle, ChallengeField};

/// Canonical payload (borrowed or downloaded) and its full bottom-up path.
pub type ColumnResponse<'a> = (Cow<'a, [u8]>, Vec<merkle::Digest>);

/// Encoding and tree owned by one hiding-source producer. These values gain
/// authority only through the ordinary certificate and opening verifiers.
pub trait ColumnMaterial {
    /// Tree domain and physical leaf geometry of the stored material.
    fn descriptor(&self) -> merkle::Descriptor;
    /// Root of the same immutable tree that answers every selected index.
    fn root(&self) -> merkle::Digest;
    /// Full individual response, including repeated requests for the same index.
    fn selected(&self, index: u64) -> Result<ColumnResponse<'_>, Error>;
}

/// Existing scalar storage. Its columns remain borrowable without allocation.
pub struct HostColumns {
    pub(crate) descriptor: merkle::Descriptor,
    pub(crate) columns: Vec<u8>,
    pub(crate) tree: merkle::Tree,
    pub(crate) work: PreparationWork,
}

impl HostColumns {
    pub(crate) fn response(&self, index: u64) -> Result<PreparedColumn<'_>, Error> {
        let siblings = self.tree.path(index).map_err(Error::Merkle)?;
        // The tree checked the index and preparation checked count * width.
        let width = self.descriptor.width as usize;
        let offset = index as usize * width;
        Ok(PreparedColumn {
            payload: &self.columns[offset..offset + width],
            siblings,
        })
    }
}
impl ColumnMaterial for HostColumns {
    fn descriptor(&self) -> merkle::Descriptor {
        self.descriptor
    }
    fn root(&self) -> merkle::Digest {
        self.tree.root()
    }
    fn selected(&self, index: u64) -> Result<ColumnResponse<'_>, Error> {
        let col = self.response(index)?;
        Ok((Cow::Borrowed(col.payload), col.siblings))
    }
}

/// RFC-0013 A2/A4/A6 opening authority held by the host for this prepared source.
pub enum HidingUse<K: ChallengeField> {
    /// One ordinary A2 opening.
    Single,
    /// The A4 mask polynomial has its fixed two-block opening shape.
    MaskPolynomial,
    /// A6 model source with its complete persisted opening history.
    Lifetime {
        budget: usize,
        revealed: Vec<Vec<K>>,
    },
}
