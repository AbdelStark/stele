// RFC-0008 A7. Member order is exactly the validated LookupPlan order.
impl LookupPlan {
    pub(super) fn original_columns(&self) -> impl Iterator<Item=usize> + '_ {
        core::iter::once(self.multiplicity).chain(
            self.members.iter().flat_map(|member| member.tuple.iter().map(|(id, _)| *id)))
    }
}
