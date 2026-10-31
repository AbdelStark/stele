"""RFC-0020 §5: preserve the research inventory and reject incomplete CI runs."""
import ast
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/research_ci.py'
SPEC = importlib.util.spec_from_file_location('research_ci', SCRIPT)
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


class ResearchCiTests(unittest.TestCase):
    def test_matches_reference_command_inventory(self):
        commands = [command for group in ci.load_groups().values() for command in group]
        # Independent snapshot: inventory through attention normalization.
        self.assertEqual(len(commands), 167)
        digest = hashlib.sha256(json.dumps(sorted(commands), separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(digest, '83ac056c99ca5abdbb13f4db14207e85d084cea0476cd74d7e865da1d25bec70')
