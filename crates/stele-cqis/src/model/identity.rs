//! RFC-0025 encoding §6: numerical identity from four complete checked artifacts.
use super::{Bounds, Error, Model, Registry, Scales};

const PREFIX: &[u8] = b"stele/v0.1/cqis/identity";

/// Complete canonical cqis_id preimage. Construction requires the full checked
/// Model, Scales, natively regenerated Registry and statically derived Bounds.
/// This content join grants no source/passport authority or proof admission.
/// ```compile_fail
/// fn forge(n: &mut stele_cqis::model::NumericalIdentity) { n.raw = [0; 152]; }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NumericalIdentity {
    raw: [u8; PREFIX.len() + 128],
}
impl NumericalIdentity {
    /// Join immutable validated inputs. Reusing these owned values does not
    /// repeat Registry generation or Bounds derivation; no supplied hash tuple
    /// or unchecked encoded child can construct a numerical identity.
    pub fn new(
        model: &Model,
        scales: &Scales,
        registry: &Registry,
        bounds: &Bounds,
    ) -> Result<Self, Error> {
        if scales.model_identity() != model.identity()
            || registry.model_identity() != model.identity()
            || bounds.model_identity() != model.identity()
            || bounds.scales_identity() != scales.identity()
            || bounds.registry_identity() != registry.identity()
        {
            return Err(Error::Identity);
        }
        let mut raw = [0; PREFIX.len() + 128];
        raw[..PREFIX.len()].copy_from_slice(PREFIX);
        for (slot, id) in raw[PREFIX.len()..].chunks_exact_mut(32).zip([
            model.identity(),
            scales.identity(),
            registry.identity(),
            bounds.identity(),
        ]) {
            slot.copy_from_slice(&id);
        }
        Ok(Self { raw })
    }
    /// Check the entire independently expected frame, including prefix and EOF.
    /// No field is adopted from the supplied bytes.
    pub fn verify(&self, expected: &[u8]) -> Result<(), Error> {
        if self.raw != expected {
            return Err(Error::Identity);
        }
        Ok(())
    }
    /// Exact 152-byte preimage, containing no private tensor payload.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }
    /// Canonical cqis_id, BLAKE3-256 of the complete preimage.
    pub fn identity(&self) -> [u8; 32] {
        *blake3::hash(&self.raw).as_bytes()
    }
}
