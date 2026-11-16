"""RFC-0026 A16: real processes, pinned entries, unchanged full proofs, exact refusal."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

binary, root, mode = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
vectors = json.loads((root / 'research/plan-registry/vectors.json').read_text())


def run(args, code=0, last=None):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True)
    assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
    if last is not None:
        assert result.stdout.splitlines()[-1] == last, (args, result.stdout)
    return result.stdout


with tempfile.TemporaryDirectory(prefix='stele-registered-') as temporary:
    work = Path(temporary)
    if mode == 'options':
        case = vectors['codec_cases'][0]
        for name in ('entry', 'public', 'relation'):
            (work / name).write_bytes(bytes.fromhex(case[name + '_hex']))
        (work / 'proof').write_bytes(b'not read before registry preflight')
        entry = bytearray((work / 'entry').read_bytes())
        entry[len(b'stele-dev-plan-v1') + 32] ^= 1
        (work / 'entry').write_bytes(entry)
        run(['verify-registered', '--public', work / 'public', '--proof', work / 'proof',
             '--relation', work / 'relation', '--trusted-entry', work / 'entry'],
            1, 'NO: RegistryKeyMismatch')
        run(['prove-dev', '--relation', work / 'output'], 2,
            'NO: --relation needs --dev-profile 5')
        # Rejected options precede any attempted state ownership or file reads.
        for command in (['prove-dev', '--zk', '--relation', work / 'output'],
                        ['plan-digest', '--secret', work / 'secret'],
                        ['verify-registered', '--admit']):
            run(command, 2)
        assert not (work / 'output').exists() and not (work / 'secret.lock').exists()
    elif mode == 'windows':
        windows = Path(sys.argv[4])
        for pin in vectors['production_pins']:
            name = pin['name']
            reference = windows / name
            case = work / name
            subprocess.run([sys.executable, str(root / 'research/cqis-model-contract/synthetic_extract.py'),
                            str(root / 'crates/stele-prover/tests/fixtures'), name, str(case)], check=True)
            # This independently pinned reference public model is the registration input.
            run(['plan-digest', '--public', reference / 'public.bin', '--entry', case / 'entry.bin'],
                last='PLAN ENTRY WRITTEN')
            assert (case / 'entry.bin').read_bytes().hex() == pin['entry_hex'], name
            prove = ['prove-dev', '--dev-profile', '5', '--tokens', '1', '--length', pin['T']]
            for item in ('model', 'preparation', 'scales', 'artifact', 'public', 'proof', 'relation'):
                prove += ['--' + item, case / (item + '.bin')]
            shown = run(prove, last='PROOF WRITTEN')
            for item in ('public', 'proof', 'relation'):
                assert (case / (item + '.bin')).read_bytes() == (reference / (item + '.bin')).read_bytes(), (name, item)
            verify = ['verify-registered', '--public', case / 'public.bin', '--proof', case / 'proof.bin',
                      '--relation', case / 'relation.bin', '--trusted-entry', case / 'entry.bin']
            accepted = run([*verify, '--expect-model', pin['model_identity']], last='YES')
            assert 'trusted plan registry; development: no security level' in accepted.splitlines()
            identity = ('cqis_id ', 'model ', 'T ', 'tokens ', 'checked ', 'next ')
            assert [line for line in shown.splitlines() if line.startswith(identity)] == [
                line for line in accepted.splitlines() if line.startswith(identity)]
            run([*verify, '--expect-model', '00' * 32], 1, 'NO: model differs from --expect-model')
            # The full genuine proof remains fixed while one trusted key byte changes.
            entry = bytearray((case / 'entry.bin').read_bytes())
            entry[len(b'stele-dev-plan-v1') + 32] ^= 1
            (case / 'entry.bin').write_bytes(entry)
            run(verify, 1, 'NO: RegistryKeyMismatch')
            run(['verify-dev', '--public', case / 'public.bin', '--proof', case / 'proof.bin'], last='YES')
            print(f'A16 CLI {name}: published pinned entry, identical proof, registered acceptance, wrong entry rejected')
    else:
        raise AssertionError(mode)
print('STELE_REGISTERED_CLI_PASSED')
