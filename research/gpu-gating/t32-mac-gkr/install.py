"""RFC-0014 §5. Time disjoint CPU intervals in a fresh archived T32 producer."""
import sys
from pathlib import Path


def install(root):
    root = root.resolve()
    if (root / '.git').exists():
        raise ValueError('instrument a disposable source archive')

    def replace(path, old, new):
        source = path.read_text()
        if source.count(old) != 1:
            raise ValueError(f'unexpected original source in {path.name}: {old[:60]}')
        path.write_text(source.replace(old, new))

    reductions = root / 'crates/stele-reductions/src'
    claims = reductions / 'zk_claims.rs'
    lookup = reductions / 'zk_lookup.rs'
    (reductions / 'mac_gkr.rs').write_bytes(Path(__file__).with_name('timer.rs').read_bytes())
    replace(claims, '\nuse alloc::vec::Vec;', '\nuse alloc::vec::Vec;\nextern crate std;\n#[path="mac_gkr.rs"] mod mac_gkr;')
    replace(claims, 'let half = self.factors[0].x.len() / 2;',
            'let _round = mac_gkr::Round::start();\n        let half = self.factors[0].x.len() / 2;')
    replace(claims, 'let bound = self.bound;\n        let k = kappa(challenge);',
            'let fold = mac_gkr::Round::start();\n        let bound = self.bound;\n        let k = kappa(challenge);')
    replace(claims, 'self.bound += 1;\n        if let Some(e)',
            'drop(fold);\n        self.bound += 1;\n        if let Some(e)')
    replace(claims, 'detail.lap("zk/detail/gkr_prefix");', '''detail.lap("zk/detail/gkr_prefix");
        mac_gkr::begin();
        let cpu_factors = std::time::Instant::now();''')
    replace(claims, 'detail.lap("zk/detail/gkr_factors");', '''let factor_ns = cpu_factors.elapsed().as_nanos();
        let has_map = summand.expand.is_some();
        detail.lap("zk/detail/gkr_factors");''')
    replace(claims, 'detail.lap("zk/detail/gkr_setup");', '''detail.lap("zk/detail/gkr_setup");
        let cpu_rounds = std::time::Instant::now();''')
    replace(claims, 'detail.lap("zk/detail/gkr_rounds");', '''let rounds_ns = cpu_rounds.elapsed().as_nanos();
        detail.lap("zk/detail/gkr_rounds");
        mac_gkr::end(g,l,step.num_vars,has_map,factor_ns,rounds_ns);''')
    # Each returned factor is replaced by the device table. The two metadata-only
    # branches continue before the timer is charged. The pad branch builds both.
    replace(lookup, 'let factor = match input {', '''let table_started = super::std::time::Instant::now();
        let factor = match input {''')
    replace(lookup, 'map.push(Expanded::Compact(out.len()));', '''super::mac_gkr::table(table_started);
        map.push(Expanded::Compact(out.len()));''')
    replace(lookup, 'out.push(public(both(\n                    (0..half)',
            'let pad_table = super::std::time::Instant::now();\n                out.push(public(both(\n                    (0..half)')
    replace(lookup, '.collect(),\n                )));\n                continue;',
            '.collect(),\n                )));\n                super::mac_gkr::table(pad_table);\n                continue;')


if __name__ == '__main__':
    install(Path(sys.argv[1]))
