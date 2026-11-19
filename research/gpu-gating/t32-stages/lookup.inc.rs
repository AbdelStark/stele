/// RFC-0008 A7. Only the disposable measurement CLI installs this callback.
pub(super) fn sample<K: ChallengeField>(
    id: usize,
    plan: &LookupPlan,
    data: &[Vec<K>],
    beta: K,
    alpha: K,
    layers: &Vec<Vec<[K; 2]>>,
    top: Option<[&Vec<K>; 3]>,
) {
    extern crate std;
    let start = std::time::Instant::now();
    let inputs = bench::LookupInputs {
        tuples: tuple(plan, data),
        table: table(plan, beta, alpha),
        selector: plan.selector(),
        multiplicity: data[plan.multiplicity].clone(),
        powers: powers(beta, plan.c),
        alpha,
        top_variables: plan.k0,
    };
    let normalize = start.elapsed();
    super::t32_sample::lookup(id, &inputs, layers, top, normalize);
    let release = std::time::Instant::now();
    drop(inputs);
    let ns = release.elapsed().as_nanos();
    let kind = if top.is_some() { "top" } else { "rebuild" };
    std::eprintln!("t32_normalize_release kind={kind} id={id} ns={ns}");
}
