
impl<K: ChallengeField + CodeField> LookupCase<K> {
/// A deterministic source_message fixture for direct GPU tests. The current proof
/// uses the corresponding already-certified PCS owner from the ordinary prover.
#[allow(clippy::type_complexity)]
pub fn original_lookup_inputs(
    statement: &Statement<K>, columns: &[Vec<M31>], lookup_id: usize, seed: [u8;32],
) -> Result<(Vec<[usize;6]>, Vec<(usize, usize, Vec<M31>)>), super::Error> {
    let plan = super::super::plan(statement)?;
    let projected = plan.lookup_columns(columns)?;
    let lookup = plan.lookups.get(lookup_id).ok_or(super::Error::Statement)?;
    let views = lookup.original_columns().map(|i| projected[i].descriptor()).collect();
    let data = columns.iter().map(|column| column.iter().map(|x| super::element::<K>(*x)).collect()).collect::<Vec<_>>();
    let mut originals = Vec::new();
    for (s, layout) in plan.layouts[..plan.early()].iter().enumerate() {
        let m = super::super::source_message(&plan, s, &data, &seed, true)?;
        originals.push((2 << layout.ell, 2 << layout.m, m));
    }
    Ok((views, originals))
}
}
