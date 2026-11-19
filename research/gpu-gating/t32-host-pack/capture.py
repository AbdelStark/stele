"""Reuse the immutable-input proof/verification controls for the ordinary batches."""
from pathlib import Path
import runpy
import sys

here = Path(__file__).resolve().parent
summarize = runpy.run_path(str(here / "receipt.py"))["summarize"]
sys.path.insert(0, str(here.parent / "t32-stages"))
runpy.run_path(str(here.parent / "t32-stages/capture.py"))["main"](summarize)
