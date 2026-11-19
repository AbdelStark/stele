// RFC-0008 A7: preserve member order and actual MSB-first coordinates.
fn compact_parts<'a>(
    plan: &'a LookupPlan,
    columns: &'a [Vec<M31>],
) -> Result<super::t32_sample::CompactParts<'a>, Error> {
    use construction::{GkrMember, GkrSelector};
    let mut tuples: Vec<Vec<_>> = (0..plan.c)
        .map(|_| Vec::with_capacity(plan.members.len()))
        .collect();
    let mut selectors = Vec::with_capacity(plan.members.len());
    for member in &plan.members {
        let range = member.offset..member.offset + (1usize << member.m);
        for ((out, (column, coordinates)), &shift) in
            tuples.iter_mut().zip(&member.tuple).zip(&member.shifts)
        {
            let values = columns.get(*column).ok_or(Error::Statement)?;
            out.push(GkrMember {
                range: range.clone(),
                values,
                coordinates,
                shift,
                mask: Vec::new(),
            });
        }
        selectors.push(GkrSelector {
            range,
            values: member
                .selector
                .as_ref()
                .map(|(v, c)| (v.as_slice(), c.as_slice())),
        });
    }
    Ok(super::t32_sample::CompactParts {
        variables: plan.n,
        top_variables: plan.k0,
        tuples,
        selectors,
        multiplicity: columns.get(plan.multiplicity).ok_or(Error::Statement)?,
        table: &plan.table,
        valid: plan.valid,
    })
}
