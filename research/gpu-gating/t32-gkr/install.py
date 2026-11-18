"""Install read-only CPU GKR observations into the disposable measurement CLI."""
from pathlib import Path
import shutil


def install(root, replace):
    here = Path(__file__).resolve().parent
    claims = "crates/stele-reductions/src/zk_claims.rs"
    relation = "crates/stele-reductions/src/zk_relation.rs"
    shutil.copyfile(here / "record.rs", root / "crates/stele-reductions/src/t32_gkr.rs")
    replace(claims, "mod gkr_bench;", 'mod gkr_bench;\nextern crate std;\n#[path="t32_gkr.rs"] pub mod t32_gkr;')
    replace(claims, "        let half = self.factors[0].x.len() / 2;", "        let t32_round = std::time::Instant::now();\n        let out = (|| -> Result<_, stele_sumcheck::Error> {\n        let half = self.factors[0].x.len() / 2;")
    replace(claims, "        Ok(out)\n    }\n    fn fold(&mut self, challenge: K)", "        Ok(out)\n        })()?;\n        t32_gkr::round(&out, t32_round.elapsed());\n        Ok(out)\n    }\n    fn fold(&mut self, challenge: K)")
    replace(claims, "        let bound = self.bound;\n        let k = kappa(challenge);", "        let t32_fold = std::time::Instant::now();\n        let bound = self.bound;\n        let k = kappa(challenge);")
    replace(claims, "            e.record(challenge);\n        }\n        Ok(())", "            e.record(challenge);\n        }\n        t32_gkr::fold(challenge, t32_fold.elapsed());\n        Ok(())")
    replace(claims, "        match &self.expand {\n            None => Ok(compact),", "        t32_gkr::finals(&compact);\n        match &self.expand {\n            None => Ok(compact),")
    replace(claims, 'detail.lap("zk/detail/gkr_prefix");', 'detail.lap("zk/detail/gkr_prefix");\n        let t32_factors = std::time::Instant::now();')
    replace(claims, 'detail.lap("zk/detail/gkr_factors");', 't32_gkr::begin(t32_factors.elapsed());\n        detail.lap("zk/detail/gkr_factors");')
    replace(claims, 'detail.lap("zk/detail/gkr_setup");', 'detail.lap("zk/detail/gkr_setup");\n        let t32_rounds = std::time::Instant::now();')
    replace(claims, 'detail.lap("zk/detail/gkr_rounds");', 't32_gkr::end(t32_rounds.elapsed());\n        detail.lap("zk/detail/gkr_rounds");')
    replace(relation, "claims::prove_lifetime(&layout.statement, &columns, seed, t, lifetime, model)",
            """let (proof, revealed) = claims::bench::observe_gkr(&layout.statement, &columns, seed, t, Some((lifetime, model)), &mut claims::t32_gkr::observe)?;
    Ok((proof, revealed.ok_or(Error::Statement)?))""")
    return here / "device.rs"
