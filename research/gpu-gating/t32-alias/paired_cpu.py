"""One ordinary proof, followed by separate replays of the packing and view observations."""
import runpy
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
pack = runpy.run_path(str(here.parent / "t32-host-pack/receipt.py"))["summarize"]
aliases = runpy.run_path(str(here / "receipt.py"))["summarize"]
sys.path.insert(0, str(here.parent / "t32-stages"))
runpy.run_path(str(here.parent / "t32-stages/capture.py"))["main"](
    lambda log: {"pack": pack(log), "aliases": aliases(log)})
