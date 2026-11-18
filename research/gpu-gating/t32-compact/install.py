"""Use borrowed base columns for both real lookup visits in the disposable CLI."""
from pathlib import Path
import runpy
import sys


def install(root):
    root = Path(root).resolve()
    here = Path(__file__).resolve().parent
    runpy.run_path(str(here.parent / "t32-resident/install.py"))["install"](root)

    def replace(path, old, new, count=1):
        source = path.read_text()
        if source.count(old) != count:
            raise ValueError(f"unexpected compact lookup integration point in {path.name}: {old[:64]}")
        path.write_text(source.replace(old, new))

    reductions = root / "crates/stele-reductions/src"
    masked = root / "research/gpu-gating/masked/src"
    lookup = reductions / "zk_lookup.rs"
    original = (here.parent / "t32-stages/lookup.inc.rs").read_text()
    sample = original.replace("data: &[Vec<K>]", "columns: &[Vec<M31>]")
    start = sample.index("    let inputs =")
    stop = sample.index("    let normalize =", start)
    sample = sample[:start] + '    let inputs = compact_parts(plan, columns).expect("validated original lookup columns");\n' + sample[stop:]
    sample = sample.replace("lookup(id, &inputs, layers", "lookup(id, &inputs, beta, alpha, layers")
    replace(lookup, original, (here / "lookup.inc.rs").read_text() + "\n" + sample)
    replace(reductions / "zk_claims.rs", "lookup::sample(l,lp,&data,", "lookup::sample(l,lp,columns,", count=2)

    bench = reductions / "zk_lookup_bench.rs"
    with bench.open("a") as f:
        f.write("""
impl<K> LookupCase<K> {
    pub fn compact_parts<'a>(&'a self, columns: &'a [Vec<M31>])
        -> Result<super::super::t32_sample::CompactParts<'a>, super::Error> {
        super::compact_parts(&self.plan, columns)
    }
}
""")

    observer = reductions / "t32_sample.rs"
    parts = (here / "parts.rs").read_text().split("\n", 1)[1]
    replace(observer, "use super::bench::LookupInputs;", parts.replace("use alloc::vec::Vec;\n", ""))
    replace(observer, "input: &'a LookupInputs<QM31>,", "input: &'a CompactParts<'a>,\n        beta: QM31,\n        alpha: QM31,")
    replace(observer, "input: &LookupInputs<K>,", "input: &CompactParts<'_>,\n    beta: K,\n    alpha: K,")
    replace(observer, "input: field(input),", "input,\n        beta: *field(&beta),\n        alpha: *field(&alpha),")

    resident = masked / "resident_timing.rs"
    replace(resident, "gpu_lookup::select::{self, Resident}", "gpu_lookup::{compact as select, select::Resident}")
    replace(resident, "            input,\n", "            input,\n            beta,\n            alpha,\n")
    replace(resident, "            let now = Instant::now();", """            let now = Instant::now();
            let input = &crate::compact_lookup::Input::from_parts(input, beta, alpha);""")
    with (masked / "gpu_lookup_compact.rs").open("a") as f:
        f.write('\n#[cfg(test)] #[path="gpu_compact_lookup_fixture.rs"] mod fixture;\n')
    with (masked / "compact_lookup.rs").open("a") as f:
        f.write("""
impl<'a> Input<'a> {
    pub fn from_parts(parts: &'a stele_reductions::zk::claims::t32_sample::CompactParts<'a>, beta: K, alpha: K) -> Self {
        Self { variables: parts.variables, top_variables: parts.top_variables, tuples: &parts.tuples,
            selectors: &parts.selectors, multiplicity: parts.multiplicity, table: parts.table,
            valid: parts.valid, beta, alpha }
    }
}
""")


if __name__ == "__main__":
    install(sys.argv[1])
