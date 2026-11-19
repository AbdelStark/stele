"""Borrow every A5 occurrence mask and A7 shared layer window from that proof's M'."""
from pathlib import Path
import shutil
import sys


def install(root, fixtures=False):
    here = Path(__file__).resolve().parent
    root = Path(root).resolve()
    if (root/".git").exists():
        raise ValueError("expected disposable source")
    red = root/"crates/stele-reductions/src"
    gpu = root/"research/gpu-gating/masked/src"
    def sub(path, old, new, count=1):
        s=path.read_text()
        if s.count(old)!=count:
            raise ValueError(f"private source integration point {path.name}: {old[:60]}")
        path.write_text(s.replace(old,new))
    claims=red/"zk_claims.rs"
    c=red/"zk_gkr_construction.rs"
    with claims.open("a") as f:
        f.write((here/"occurrence.inc.rs").read_text())
    sub(c,"    pub column_origins:", "    pub private_windows: Vec<Vec<[usize; 6]>>,\n    pub column_origins:")
    sub(c,"    let mut column_origins=", "    let mut private_windows = Vec::new();\n    let mut column_origins=")
    sub(c,"        let mut legs=", "        let mut masks=Vec::new();\n        let mut legs=")
    sub(c,"Gin::Block(poly) => GkrFactor::Block {","Gin::Block(poly) => {\n                masks.push(plan.shared_mask_origin(lp.block(step.k,*poly),None)?);\n                GkrFactor::Block {")
    sub(c,"                point: run.tstar,\n            },","                point: run.tstar,\n            }},")
    sub(c,"                seen_mult |=", "                masks.push(plan.occurrence_mask_origin(o,0)?);\n                seen_mult |=")
    sub(c,"                let block = block_entries(", "                masks.push(plan.shared_mask_origin(lp.block(step.k+1,*poly),Some(*t))?);\n                let block = block_entries(")
    sub(c,"                        let mut origins=Vec::new();",'''                        let private_members = lp.members.iter().enumerate()
                            .map(|(m,member)| plan.occurrence_mask_origin(members[m*lp.c+i],member.offset))
                            .collect::<Result<Vec<_>,_>>()?;
                        private_windows.push(private_members);
                        let mut origins=Vec::new();''')
    sub(c,"        column_origins.push(legs);","        private_windows.push(masks);\n        column_origins.push(legs);")
    sub(c,"        column_origins,","        private_windows,\n        column_origins,")
    for name in ("gkr_build.rs","gpu_lookup_tests.rs"):
        sub(gpu/name,"column_origins: Vec::new(),","private_windows: Vec::new(),\n            column_origins: Vec::new(),",2)
    case=red/"zk_gkr_bench.rs"
    sub(case,"    pub original_messages:", "    pub private_message: &'a dyn Fn(usize)->Option<&'a [M31]>,\n    pub original_messages:")
    sub(claims,"                original_messages: &messages,",'''                private_message: &|id| if id == plan.shared_id() as usize { Some(&shared_message) }
                else {all.get(id).copied()},
            original_messages: &messages,''')
    shutil.copyfile(here/"check.rs",gpu/"private_source_check.rs")
    if fixtures:
        shutil.copyfile(here/"fixture.rs",gpu/"private_gkr_fixture.rs")
        with (gpu/"gpu_gkr_tests.rs").open("a") as f:
            f.write('\n#[path="private_gkr_fixture.rs"] mod private_fixture;\n')
    else:
        sub(gpu/"t32_timing.rs",'static DEVICE:', '#[path="private_source_check.rs"] mod private_check;\nstatic DEVICE:')
        sub(gpu/"t32_timing.rs","    let mut child = None;", """    let probe=Instant::now();
    let (checked_windows,checked_bytes)=private_check::check(step,&input);
    let qualification_ns=probe.elapsed().as_nanos();
    let mut child = None;""")
        device=gpu/"resident_timing.rs"
        sub(device,'return super::originals::with_originals(|owners| dev.build_gkr_original(input,&input.column_origins,owners));',
            'return super::originals::with_originals(|owners| dev.build_gkr_private(input, Some(&input.column_origins), &input.private_windows, owners, crate::gpu::PrivateChild::Host, false));')
        sub(device,'dev.build_gkr_last_child(input, id, hold.take().expect("final child owner"))',
            'super::originals::with_originals(|owners| dev.build_gkr_private(input,None,&input.private_windows,owners,crate::gpu::PrivateChild::Last(id,hold.take().expect("final child owner")),false))')
        sub(device,'dev.build_gkr_resident(input, id, tree)',
            'super::originals::with_originals(|owners| dev.build_gkr_private(input,None,&input.private_windows,owners,crate::gpu::PrivateChild::Borrowed(id,tree),false))')
        sub(gpu/"t32_timing.rs",'eprintln!("gkr_inputs step=', '''eprintln!("gkr_private checked_windows={checked_windows} checked_bytes={checked_bytes} qualification_ns={qualification_ns} step={} mask_views={} mask_bytes={} block_views={} block_bytes={}",step.step,work.mask_views,work.mask_view_bytes,work.block_views,work.block_view_bytes);
eprintln!("gkr_inputs step=''')


if __name__=="__main__":
    install(sys.argv[1], "--fixtures" in sys.argv[2:])
