#!/usr/bin/env python3
"""RFC-0020 §5: skipped work is valid only when a successful plan excludes it."""
import json
import os
import sys


def accepts(needs):
    try:
        if any(needs[job]['result'] != 'success' for job in ('plan', 'native', 'native-union')):
            return False
        scope = needs['plan']['outputs']
        for job, name in (('table-parity', 'tables'), ('research', 'research'), ('gpu-parity', 'gpu')):
            required = scope[name]
            if required not in ('true', 'false'):
                return False
            expected = 'success' if required == 'true' else 'skipped'
            if needs[job]['result'] != expected:
                return False
        return True
    except (KeyError, TypeError):
        return False


if __name__ == '__main__':
    if not accepts(json.loads(os.environ['NEEDS'])):
        sys.exit('Required CI checks did not pass')
