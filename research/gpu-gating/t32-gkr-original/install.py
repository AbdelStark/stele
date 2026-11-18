"""Point each genuine GKR column occurrence at its original source layout in a disposable tree."""
from pathlib import Path
import runpy
import shutil
import sys

def install(root, fixtures=False):
    here=Path(__file__).resolve().parent
    root=Path(root).resolve()
    if (root/".git").exists(): raise ValueError("expected a disposable tree")
    red=root/"crates/stele-reductions/src"
    gpu=root/"research/gpu-gating/masked/src"
    def replace(p,a,b,count=1):
        s=p.read_text()
        if s.count(a)!=count: raise ValueError(f"unexpected {p.name}: {a[:68]}")
        p.write_text(s.replace(a,b))
    if fixtures:
        # No T32-only global observer is installed in the synthetic GPU campaign.
        lookup=red/"zk_lookup.rs"
        for p,f in [(lookup,"lookups.inc.rs"),(red/"zk_claims.rs","original.inc.rs")]:
            with p.open("a") as out: out.write((here.parent/"t32-alias"/f).read_text())
        shutil.copyfile(here.parent/"t32-alias/views.rs",red/"t32_alias.rs")
        shutil.copyfile(here.parent/"t32-alias/views_tests.rs",red/"t32_alias_tests.rs")
        replace(red/"zk_claims.rs",'laps.lap("zk/sources_prepare_certify");','laps.lap("zk/sources_prepare_certify");\n    #[cfg(feature="bench")] let projected=plan.lookup_columns(columns)?;')
    claims=red/"zk_claims.rs"
    construction=red/"zk_gkr_construction.rs"
    case=red/"zk_gkr_bench.rs"
    replace(construction,"pub struct GkrConstruction<'a, K> {","pub struct GkrConstruction<'a, K> {\n    pub column_origins: Vec<Vec<Option<[usize;6]>>>,")
    replace(construction,'    let mut factors = Vec::new();','    let mut factors = Vec::new();\n    let mut column_origins=Vec::new();')
    replace(construction,"    let factor = match input {","    let mut legs=Vec::new();\n        let factor = match input {")
    replace(construction,"    data: &'a [Vec<K>],","    data: &'a [Vec<K>],\n    projected:&[super::super::t32_alias::Column],")
    replace(construction,"                GkrFactor::Column {","""                legs.push(if matches!(input,Gin::Leaf(_)) {
                    Some(projected.get(o.column).ok_or(Error::Statement)?.descriptor())
                } else { None });
                GkrFactor::Column {""")
    replace(construction,"                        factors.push(GkrFactor::Combined {","                        let mut origins=Vec::new();\n                        factors.push(GkrFactor::Combined {")
    replace(construction,"                                    GkrMember {","                                    origins.push(Some(projected[*column].descriptor()));\n                                    GkrMember {")
    replace(construction,"                            vanishing,\n                        });","                            vanishing,\n                        });\n                        column_origins.push(origins);")
    replace(construction,"        factors.push(factor);","        factors.push(factor);\n        column_origins.push(legs);")
    replace(construction,"    Ok(GkrConstruction {","    Ok(GkrConstruction {\n        column_origins,")
    replace(claims,"                    &data,\n                    &shared_message,\n                    &block_of,\n                )\n            };","                    &data,\n                    &projected,\n                    &shared_message,\n                    &block_of,\n                )\n            };")
    replace(case,"pub struct GkrCase<'a, K> {","pub struct GkrCase<'a, K> {\n    pub original_messages: &'a [Vec<M31>],\n    pub lookup_origins: &'a dyn Fn()->Vec<usize>,")
    replace(claims,"observer(&gkr_bench::GkrCase {","observer(&gkr_bench::GkrCase {\n                original_messages: &messages,\n                lookup_origins: &||plan.lookups[l].original_columns().collect(),")
    for name in ("gkr_build.rs","gpu_lookup_tests.rs"):
        f=gpu/name
        replace(f,"= GkrConstruction {","= GkrConstruction {\n            column_origins: Vec::new(),",2)
    if not fixtures:
        adapter=gpu/"resident_timing.rs"
        replace(adapter,"            return dev.build_gkr_bounded(input);", "            return super::originals::with_originals(|owners| dev.build_gkr_original(input,&input.column_origins,owners));")
        t=gpu/"t32_timing.rs"
        replace(t,'    eprintln!("t32_gkr_step step=',(here/"report.inc.rs").read_text()+'\n    eprintln!("t32_gkr_step step=')
    if fixtures:
        shutil.copyfile(here/"fixture.rs",gpu/"original_gkr_fixture.rs")
        with (gpu/"gpu_gkr_tests.rs").open("a") as out:
            out.write('\n#[path="original_gkr_fixture.rs"] mod original_fixture;\n')

if __name__=="__main__":
    install(sys.argv[1],"--fixtures" in sys.argv[2:])
