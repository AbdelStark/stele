"""Join the compact lookup and original-source observers in an installed archive."""
from pathlib import Path
import shutil


def install(root):
    here = Path(__file__).resolve().parent
    reductions = root / "crates/stele-reductions/src"
    masked = root / "research/gpu-gating/masked/src"
    def replace(f, old, new, count=1):
        text = f.read_text()
        if text.count(old) != count:
            raise ValueError(f"unexpected file {f}: {old[:60]}")
        f.write_text(text.replace(old,new))
    claims = reductions / "zk_claims.rs"
    lookup = reductions / "zk_lookup.rs"
    replace(claims,"lookup::sample(l,lp,columns,", "lookup::sample(l,lp,columns,&projected,",2)
    replace(lookup,"    columns: &[Vec<M31>],\n    beta: K,",
            "    columns: &[Vec<M31>],\n    projected: &[super::t32_alias::Column],\n    beta: K,")
    replace(lookup,"    let inputs = compact_parts(plan, columns)", "    let mut inputs = compact_parts(plan, columns)")
    replace(lookup,'    let normalize = start.elapsed();','''    inputs.originals = plan.original_columns().map(|i| projected[i].descriptor()).collect();
    let normalize = start.elapsed();''')
    replace(lookup,"        variables: plan.n,\n        top_variables: plan.k0,",
            "        originals: Vec::new(),\n        variables: plan.n,\n        top_variables: plan.k0,")
    replace(reductions / "t32_sample.rs","pub struct CompactParts<'a> {",
            "pub struct CompactParts<'a> {\n    pub originals: Vec<[usize;6]>,")
    device = masked / "resident_timing.rs"
    replace(device,"            let input = &crate::compact_lookup::Input::from_parts",
            "            let columns = &input.originals;\n            let input = &crate::compact_lookup::Input::from_parts")
    replace(device,"select::top(dev, input)", "super::originals::with_originals(|owners| select::top_original(dev,input,select::OriginalViews { columns, owners }))")
    replace(device,"select::resident(dev, id, input)", "super::originals::with_originals(|owners| select::resident_original(dev,id,input,select::OriginalViews { columns, owners }))")
    replace(device,'eprintln!("t32_selected kind={kind} id={id}', 'let legs=columns.len(); let view_bytes=24*legs;\n            eprintln!("t32_selected kind={kind} id={id} original_legs={legs} view_bytes={view_bytes}')
    # Seeded proof inputs use source_message itself, including its real mask quadrants.
    with (reductions / "zk_lookup_bench.rs").open("a") as out:
        out.write((here / "fixture.inc.rs").read_text())
    with (masked / "gpu_lookup_compact.rs").open("a") as out:
        out.write('\n#[cfg(test)] #[path="alias_fixture.rs"] mod alias_fixture;\n')
    shutil.copyfile(here / "fixture.rs", masked / "alias_fixture.rs")
    with (masked / "gpu_original.rs").open("a") as out:
        out.write('''
#[cfg(test)]
impl OriginalMessage<'_> {
    pub(crate) fn lift_original_test_words(&mut self) -> Result<(), Error> {
        use crate::Field;
        let mut w = self.dev.stream.clone_dtoh(&self.words)?;
        for x in &mut w { *x += M31::MODULUS; }
        self.dev.stream.memcpy_htod(&w,&mut self.words)?;
        self.dev.sync()
    }
}
''')
