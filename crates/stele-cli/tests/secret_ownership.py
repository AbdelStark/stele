"""RFC-0013 A6.5: exercise the real CLI against one disposable, private model state."""
import errno
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time


def reader(fifo, process):
    deadline = time.monotonic() + 30
    while True:
        try:
            return os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        except OSError as error:
            if (error.errno != errno.ENXIO or process.poll() is not None
                    or time.monotonic() >= deadline):
                raise
            time.sleep(0.01)


def main(cli, repository):
    cli, repository = Path(cli), Path(repository)
    env = dict(os.environ, STELE_THREADS='2')
    with tempfile.TemporaryDirectory(prefix='stele-secret-ownership-') as temporary:
        work = Path(temporary)
        subprocess.run([
            sys.executable, str(repository / 'research/cqis-model-contract/synthetic_extract.py'),
            str(repository / 'crates/stele-prover/tests/fixtures'), 'one-layer', str(work),
        ], check=True)
        secret = work / 'model.secret'
        commitment = work / 'commitment.bin'
        common = [value for key in ('preparation', 'scales', 'artifact')
                  for value in ('--' + key, work / (key + '.bin'))]

        def run(args, expected=0):
            result = subprocess.run([str(cli), *map(str, args)], env=env,
                                    capture_output=True, text=True, timeout=180)
            assert result.returncode == expected, result.stdout + result.stderr
            return result.stdout

        def commit(state, model):
            return ['commit-model', '--zk', '--model', model, *common, '--length', '4',
                    '--proofs', '2', '--commitment', commitment, '--secret', state]

        def prove(label, state=secret, model=None):
            return ['prove-dev', '--zk', '--model', model or work / 'model.bin', *common,
                    '--length', '4', '--tokens', '1', '--commitment', commitment,
                    '--secret', state, '--public', work / (label + '.public'),
                    '--proof', work / (label + '.proof')]

        # Invalid ownership paths fail before any model input is read.
        invalid = work / 'invalid.secret'
        invalid.mkdir()
        assert 'regular file' in run(commit(invalid, work / 'missing-model'), expected=2)
        invalid.rmdir()
        invalid.symlink_to(work / 'missing-target')
        assert 'lock ' in run(commit(invalid, work / 'missing-model'), expected=2)
        invalid.unlink()
        invalid_lock = Path(str(invalid) + '.lock')
        target = work / 'untouched'
        target.write_bytes(b'unchanged')
        target.chmod(0o640)
        invalid_lock.symlink_to(target)
        assert 'singly linked regular file' in run(commit(invalid, work / 'missing-model'), expected=2)
        assert target.read_bytes() == b'unchanged'
        assert stat.S_IMODE(target.stat().st_mode) == 0o640
        invalid_lock.unlink()
        os.link(target, invalid_lock)
        assert 'singly linked regular file' in run(commit(invalid, work / 'missing-model'), expected=2)
        invalid_lock.unlink()
        invalid_lock.mkdir()
        assert 'singly linked regular file' in run(commit(invalid, work / 'missing-model'), expected=2)
        invalid_lock.rmdir()
        # Input failure releases ownership, leaving the same private lock for a retry.
        for _ in range(2):
            assert 'read ' in run(commit(invalid, work / 'missing-model'), expected=2)

        output = run(commit(secret, work / 'model.bin'))
        model_pin = re.search(r'^model ([0-9a-f]{64})$', output, re.M)
        assert model_pin, output

        def verify(label):
            run(['verify-dev', '--public', work / (label + '.public'),
                 '--proof', work / (label + '.proof'), '--expect-model', model_pin.group(1)])

        fifo = work / 'model.fifo'
        os.mkfifo(fifo, 0o600)
        writer = None
        with (work / 'first.log').open('w') as log:
            first = subprocess.Popen([str(cli), *map(str, prove('first', model=fifo))],
                                     env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                # File input begins after the state has been loaded. Keep the owner here.
                writer = reader(fifo, first)
                output = run(prove('blocked'), expected=2)
                assert 'secret state is locked' in output, output
                assert not (work / 'blocked.proof').exists()

                # Both final-file and directory symlinks must address the same owner.
                alias = work / 'secret-alias'
                alias.symlink_to(secret)
                directory = work / 'directory-alias'
                directory.symlink_to(work, target_is_directory=True)
                for path in (alias, directory / secret.name, str(work) + '/./' + secret.name):
                    output = run(prove('alias', state=path), expected=2)
                    assert 'secret state is locked' in output, output
                # A competing commitment must stop before trying to read its model.
                output = run(commit(secret, work / 'missing-model'), expected=2)
                assert 'secret state is locked' in output, output

                lock = Path(str(secret) + '.lock')
                lock_inode = lock.stat().st_ino
                with os.fdopen(writer, 'wb') as stream:
                    writer = None
                    stream.write((work / 'model.bin').read_bytes())
                assert first.wait(timeout=180) == 0, (work / 'first.log').read_text()
            finally:
                if writer is not None:
                    os.close(writer)
                if first.poll() is None:
                    first.kill()
                    first.wait()

        assert re.search(r'^proof index 0 of 2$', (work / 'first.log').read_text(), re.M)
        verify('first')
        output = run(prove('second'))
        assert re.search(r'^proof index 1 of 2$', output, re.M), output
        verify('second')
        # The secret is replaced atomically, while the lock's inode remains stable.
        assert lock.stat().st_ino == lock_inode
        for path in (secret, lock):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert not Path(str(secret) + '.tmp').exists()

        # Pre-existing hard links cannot create a second state owner under another name.
        hardlink = work / 'secret-hardlink'
        os.link(secret, hardlink)
        for path in (secret, hardlink):
            output = run(prove('hardlink', state=path, model=work / 'missing-model'), expected=2)
            assert 'hard-linked secret' in output, output
        hardlink.unlink()
        print('STELE_SECRET_OWNERSHIP_PASSED')


if __name__ == '__main__':
    main(*sys.argv[1:3])
