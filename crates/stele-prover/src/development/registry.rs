//! RFC-0026 A16 §5: publish a canonical entry from validated public model data.
use super::{
    bundle, certificates, decode, layout, model_identity, Error, PlanData, Public, Statement,
};
use alloc::vec::Vec;
use stele_reductions::relation::{self, Sources};
use stele_reductions::stele_cqis::model::Role;
use stele_reductions::stele_ir::relation::{Kind, Width};

/// Return `(entry bytes, original relation bytes)` for a byte-5 model and window.
///
/// Checks the canonical model data, plan obligation, static bounds and commitment
/// certificates using the same §8 path as production verification. No model secret
/// or inference witness is read. The sample request must be well formed; its greedy
/// claims need not be true to publish the static entry.
///
/// Publication is not authentication. A verifier caller must separately trust the
/// publisher and pin the entry for the intended model. Success remains scoped to a
/// trusted plan registry; development: no security level (A16 §§1,4).
pub fn publish(public: &Public, statement: &Statement) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if public.sources != Sources::CircleAllGrind || public.segment_layers > 0 {
        return Err(Error::StatementMismatch);
    }
    let d = decode(public)?;
    let shape = d.model.shape();
    statement.validate(shape.vocabulary(), shape.context())?;
    let lt = statement.tokens.len().trailing_zeros();
    let lv = u32::BITS - (shape.vocabulary() - 1).leading_zeros();
    let ld = u16::BITS - (shape.width() - 1).leading_zeros();
    if lt + lv > 30 || lt + ld > 30 || ld + lv > 30 {
        return Err(Error::StatementMismatch);
    }
    let mut layout = layout(&d, public, statement)?;
    layout
        .relation
        .validate()
        .map_err(|_| Error::StatementMismatch)?;
    let bits: Vec<u8> = layout
        .weights
        .iter()
        .map(|(id, _, _)| layout.relation.columns[id.0 as usize].log_len)
        .collect();
    certificates(public, &bits)?;
    let declaration = relation::encode(&layout.relation);
    // Only the hash preimage is normalized; these widths need not satisfy bounds.
    for column in &mut layout.relation.columns {
        if column.name.starts_with("G/embedding/O")
            || matches!(
                column.name.as_str(),
                "G/embedding/m"
                    | "G/embedding/mm"
                    | "G/argmax/onehot"
                    | "G/argmax/below"
                    | "G/argmax/rows"
            )
        {
            let Kind::Public(values) = &mut column.kind else {
                return Err(Error::StatementMismatch);
            };
            values.fill(0);
            column.width = Width::unsigned(1);
        }
    }
    let normalized = relation::encode(&layout.relation);
    let mut template = blake3::Hasher::new();
    template.update(b"stele/v0.1/dev-e2e/plan-template/v1");
    template.update(&(normalized.len() as u64).to_le_bytes());
    template.update(&normalized);
    let data = bundle::static_data(public);
    let mut static_hash = blake3::Hasher::new();
    static_hash.update(b"stele/v0.1/dev-e2e/plan-static/v1");
    static_hash.update(&(data.len() as u64).to_le_bytes());
    static_hash.update(&data);
    static_hash.update(&(public.commitment.len() as u32).to_le_bytes());
    for (root, _) in &public.commitment {
        static_hash.update(root);
    }
    let plan = PlanData {
        model: &d.model,
        scales: &d.scales,
        vectors: &public.vectors,
        zk: false,
        segment_layers: 0,
    };
    let token = plan.ordinal(Role::Token, None)?;
    let embedding = d.scales.matrix(token).ok_or(Error::UnsupportedModel)?;
    let (cqis, model) = model_identity(public)?;
    let mut entry = b"stele-dev-plan-v1".to_vec();
    entry.extend_from_slice(&cqis);
    entry.extend_from_slice(&model);
    entry.extend_from_slice(&(statement.tokens.len() as u32).to_le_bytes());
    entry.push(super::GRIND_PROFILE);
    entry.extend_from_slice(static_hash.finalize().as_bytes());
    entry.extend_from_slice(template.finalize().as_bytes());
    entry.extend_from_slice(&(declaration.len() as u64).to_le_bytes());
    entry.extend_from_slice(&shape.vocabulary().to_le_bytes());
    entry.extend_from_slice(&shape.width().to_le_bytes());
    entry.extend_from_slice(&embedding.exponent().to_le_bytes());
    entry.push(d.model.initial_fraction());
    entry.extend_from_slice(&(embedding.mantissas().len() as u32).to_le_bytes());
    for mantissa in embedding.mantissas() {
        entry.extend_from_slice(&mantissa.to_le_bytes());
    }
    Ok((entry, declaration))
}
