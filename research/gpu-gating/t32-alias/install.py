"""Borrow original plan geometry and check the real prepared source on a disposable build."""
import shutil
import sys
from pathlib import Path


def install(root, device=False):
    here = Path(__file__).resolve().parent
    root = Path(root).resolve()
    if (root / ".git").exists():
        raise ValueError("expected a disposable source archive")
    reductions = root / "crates/stele-reductions/src"
    def append(path, chunk):
        with (reductions / path).open("a") as out:
            out.write("\n" + (here / chunk).read_text())
    lookup = reductions / "zk_lookup.rs"
    append(lookup, "lookups.inc.rs")
    claims = reductions / "zk_claims.rs"
    append(claims, "original.inc.rs")
    shutil.copyfile(here / "views.rs", reductions / "t32_alias.rs")
    shutil.copyfile(here / "views_tests.rs", reductions / "t32_alias_tests.rs")
    text = claims.read_text()
    anchor = 'laps.lap("zk/sources_prepare_certify");'
    if text.count(anchor) != 1:
        raise ValueError("unexpected original preparation hook")
    hook = (here / "check.inc.rs").read_text()
    if device:
        # Publish the checked plan only after every CPU comparison succeeded. Charge
        # layout construction once and keep this extra full oracle scan separate.
        hook = "let projected = " + hook[hook.index("{") :].rstrip()[:-1] + "    projected\n};\n"
    claims.write_text(text.replace(anchor, anchor + "\n" + hook))
    if device:
        import runpy
        runpy.run_path(str(here / "device.py"))["install"](root)


if __name__ == "__main__":
    install(sys.argv[1], "--device" in sys.argv[2:])
