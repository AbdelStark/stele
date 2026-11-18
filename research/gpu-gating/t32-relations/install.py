"""Install a device-authored ordinary relation summand only in a disposable source archive."""
import argparse
from pathlib import Path
import shutil


def install(root, standalone=False, corpus=False):
    root=Path(root).resolve()
    if (root/'.git').exists():
        raise ValueError('expected disposable archive')
    here=Path(__file__).resolve().parent
    red=root/'crates/stele-reductions/src/zk_claims.rs'
    gpu=root/'research/gpu-gating/masked/src'
    def replace(path, old, new):
        data=path.read_text()
        if data.count(old)!=1:
            raise ValueError(f'unexpected {path.name}: {old[:64]}')
        path.write_text(data.replace(old,new))
    def module(path, text):
        with path.open('a') as f: f.write('\n'+text+'\n')
    if corpus:
        if not standalone:
            raise ValueError('synthetic corpus requires a standalone device')
        replace(root/'research/gpu-gating/masked/examples/synthetic_proof.rs',
                'fn main() {', 'fn main() {\n    stele_masked_gpu_bench::t32_relations::install();')
    hashed=root/'crates/stele-hash/src/lib.rs'
    trait='pub trait ChallengeField: sealed::Target'
    if trait in hashed.read_text(): replace(hashed,trait,"pub trait ChallengeField: 'static + sealed::Target")
    if '\nextern crate std;' not in red.read_text():
        replace(red,'\nuse alloc::vec::Vec;','\nextern crate std;\nuse alloc::vec::Vec;')
    shutil.copyfile(here/'checked.rs',red.with_name('t32_relation.rs'))
    module(red,'#[path="t32_relation.rs"] pub mod t32_relation;')
    replace(red,'    let mut relations = Vec::new();\n    for (j, step)', '    let mut relations = Vec::new();\n    if forgery.is_none() { (t32_relation::backend().begin)(plan.steps.len()); }\n    for (j, step)')
    replace(red,'detail.lap("zk/detail/relation_prefix");','detail.lap("zk/detail/relation_prefix");\n        let relation_start = std::time::Instant::now();')
    replace(red,'detail.lap("zk/detail/relation_factors");','let host_factors = relation_start.elapsed();\n        detail.lap("zk/detail/relation_factors");')
    replace(red,'            masked_instance(&i, step.degree, summand, &masks[j], &binding, here, None, t)?','''            if forgery.is_some() {
                masked_instance(&i, step.degree, summand, &masks[j], &binding, here, None, t)?
            } else {
            let checked = t32_relation::Checked::new(j, summand, host_factors);
            let (proof, point) = masked::prove(&i, checked, &masks[j], &binding, t).map_err(Error::Sumcheck)?;
            let (truth, mu) = (proof.final_values.clone(), proof.mask_final);
            (proof, point, truth, mu)
            }''')
    replace(red,'    laps.lap("zk/relations_masked_sumcheck");','    if forgery.is_none() { (t32_relation::backend().end)(plan.steps.len()); }\n    laps.lap("zk/relations_masked_sumcheck");')
    shutil.copyfile(here/'build.rs',gpu/'relation_build.rs')
    shutil.copyfile(here/'device.rs',gpu/'t32_relations.rs')
    module(gpu/'gpu.rs','#[path="relation_build.rs"] mod relation_build;')
    module(gpu/'lib.rs','#[cfg(feature="cuda")] pub mod t32_relations;')
    if not standalone:
        replace(gpu/'t32_timing.rs','    resident::install();', '    crate::t32_relations::install_shared(DEVICE.get().expect("required H100"));\n    resident::install();')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('root',type=Path)
    p.add_argument('--standalone', action='store_true')
    p.add_argument('--corpus', action='store_true', help='require the H100 when proving each synthetic reference case')
    args=p.parse_args();install(args.root,args.standalone,args.corpus)
