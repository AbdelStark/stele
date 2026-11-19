#!/usr/bin/env python3
"""RFC-0018 §1, RFC-0027 §3 (task E17-04): scripted remote host runner for CPU and GPU rungs.

One command provisions a digest-pinned container image on a remote host (SSH VM or Slurm
node), executes a named ladder rung (`L0`, `L1`, `L2a`, `L2b`, `L2c`, or `gpu-parity`),
records the run cost in the ledger note, and returns the validated ledger, logs, and
proof/receipt SHA-256 digest.

No credential, token, or hostname is stored in this repository. Supply target coordinates
exclusively via CLI flags or environment variables:
  STELE_REMOTE_HOST       SSH host or alias (required unless `--host` is given)
  STELE_REMOTE_IMAGE      Digest-pinned OCI image `ref@sha256:<64-hex>` (or `--image`)
  STELE_REMOTE_DIR        Remote scratch directory (default: `/tmp/stele-remote`)
  STELE_REMOTE_MODEL_DIR  Remote directory containing `model.bin`, `preparation.bin`,
                          `scales.bin`, `artifact.bin` for real-checkpoint rungs (L2a..L2c)
  STELE_REMOTE_NVRTC_DIR  Optional host directory with pinned `libnvrtc.so*` for GPU runs
  STELE_REMOTE_UV_BIN     Optional host path to pinned `uv` binary for GPU parity fixtures
  STELE_SLURM_PARTITION   Optional Slurm partition (when `--executor slurm`)
  STELE_SLURM_NODELIST    Optional Slurm node constraint (when `--executor slurm`)
"""
from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
IMAGE_DIGEST_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[0-9a-f]{64}$')
COMMIT_RE = re.compile(r'^[0-9a-f]{40}$')
HOST_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._@-]*$')
SAFE_PATH_RE = re.compile(r'^[A-Za-z0-9._/+~-]+$')
SLURM_VALUE_RE = re.compile(r'^[A-Za-z0-9._,:+-]+$')

# Rung definitions (RFC-0027 §3).
RUNG_SPECS = {
    'L0': {
        'kind': 'inference',
        'workload': 'dev/synthetic-1layer-t16',
        'synthetic_case': 'one-layer',
        'tokens': '1',
        'prompt_tokens': 1,
        'length': 16,
        'checked': None,
        'needs_gpu': False,
        'model_config': {
            'cqis': 'int8 matrices, dynamic rows, random small codes',
            'fixture': 'crates/stele-prover/tests/fixtures/synthetic-e2e.json',
            'name': 'synthetic-e2e one-layer (L0)',
            'shape': {'context': 16, 'd': 64, 'heads': 4, 'hidden': 128, 'layers': 1, 'vocabulary': 256},
        },
    },
    'L1': {
        'kind': 'inference',
        'workload': 'dev/synthetic-8layer-t64',
        'synthetic_case': 'eight-layer',
        'tokens': '1',
        'prompt_tokens': 1,
        'length': 64,
        'checked': None,
        'needs_gpu': False,
        'model_config': {
            'cqis': 'int8 matrices, dynamic rows, random small codes',
            'fixture': 'crates/stele-prover/tests/fixtures/synthetic-e2e.json',
            'name': 'synthetic-e2e eight-layer (L1)',
            'shape': {'context': 64, 'd': 64, 'heads': 4, 'hidden': 128, 'layers': 8, 'vocabulary': 256},
        },
    },
    'L2a': {
        'kind': 'inference',
        'workload': 'dev/stories42m-t64',
        'synthetic_case': None,
        'tokens': '1,9038,2501,263,931,29892,727,471,263,2217,7826,4257,365,2354,29889,2296,18012,304,1708,5377,297,278,14089,29889',
        'prompt_tokens': 24,
        'length': 64,
        'checked': '23..64',
        'needs_gpu': False,
        'model_config': {
            'cqis': 'int8 matrices, int16 gains (G=8), F=7, A15 groups of 128 on norm-fed inputs and head, direct exp',
            'fidelity': 'agents/reviews/e16-11-stories42m/fidelity.json',
            'name': 'llama2.c stories42M (MIT), converted by research/cqis-model-contract/stories42m.py',
            'shape': {'context': 1024, 'd': 512, 'head_width': 64, 'heads': 8, 'hidden': 1376, 'kv_heads': 8, 'layers': 8, 'vocabulary': 32000},
            'source': 'huggingface.co/karpathy/tinyllamas@0bd21da7698eaf29a0d7de3992de8a46ef624add stories42M.bin sha256 9f65a1000e17d0bc167dd6332e0ce5119a0222a3d920cead5bce413bfab2ee7b',
        },
    },
    'L2b': {
        'kind': 'inference',
        'workload': 'dev/stories42m-t1024',
        'synthetic_case': None,
        'tokens': '1,9038,2501,263,931,29892,727,471,263,2217,7826,4257,365,2354,29889,2296,18012,304,1708,5377,297,278,14089,29889',
        'prompt_tokens': 24,
        'length': 1024,
        'checked': '23..1024',
        'needs_gpu': False,
        'model_config': {
            'cqis': 'int8 matrices, int16 gains (G=8), F=7, A15 groups of 128 on norm-fed inputs and head, direct exp',
            'name': 'llama2.c stories42M (MIT) T=1024 (L2b)',
            'shape': {'context': 1024, 'd': 512, 'head_width': 64, 'heads': 8, 'hidden': 1376, 'kv_heads': 8, 'layers': 8, 'vocabulary': 32000},
        },
    },
    'L2c': {
        'kind': 'inference',
        'workload': 'dev/stories110m-t64',
        'synthetic_case': None,
        'tokens': '1,9038,2501,263,931,29892,727,471,263,2217,7826,4257,365,2354,29889,2296,18012,304,1708,5377,297,278,14089,29889',
        'prompt_tokens': 24,
        'length': 64,
        'checked': '23..64',
        'needs_gpu': False,
        'model_config': {
            'cqis': 'int8 matrices, int16 gains (G=8), F=7, row-blocked matmuls (RFC-0026 A6)',
            'name': 'llama2.c stories110M (MIT) T=64 (L2c)',
            'shape': {'context': 1024, 'd': 768, 'head_width': 64, 'heads': 12, 'hidden': 2048, 'kv_heads': 12, 'layers': 12, 'vocabulary': 32000},
        },
    },
    'gpu-parity': {
        'kind': 'micro',
        'workload': 'micro/remote-gpu-parity-smoke',
        'synthetic_case': None,
        'needs_gpu': True,
    },
}


def validate_pinned_image(image: str) -> str:
    """Require an immutable digest-pinned OCI image (`ref@sha256:<64-hex>`)."""
    if not IMAGE_DIGEST_RE.fullmatch(image):
        raise ValueError(
            f'image must be digest-pinned (<ref>@sha256:<64-hex>), got {image!r}'
        )
    return image


def validate_host(host: str) -> str:
    """Reject leading `-`, whitespace, control chars, or SSH/SCP delimiters in `--host`."""
    if not HOST_RE.fullmatch(host):
        raise ValueError(f'invalid remote host/alias {host!r}')
    return host


def validate_remote_dir(path: str) -> str:
    """Require a safe non-root remote scratch path with no shell/SCP metacharacters."""
    stripped = path.rstrip('/')
    if not stripped or not SAFE_PATH_RE.fullmatch(path) or path.startswith('-'):
        raise ValueError(f'invalid --remote-dir path {path!r}')
    return stripped


def validate_host_mount_path(name: str, path: str | None) -> str | None:
    """Reject `,`, `:`, whitespace, control chars, or shell metacharacters in host mount paths."""
    if path is None:
        return None
    if not path or not SAFE_PATH_RE.fullmatch(path) or path.startswith('-'):
        raise ValueError(f'invalid {name} path {path!r}')
    return path


def validate_slurm_value(name: str, value: str | None) -> str | None:
    """Reject newlines, whitespace, or shell metacharacters in `#SBATCH` directives."""
    if value is None:
        return None
    if not value or not SLURM_VALUE_RE.fullmatch(value) or value.startswith('-'):
        raise ValueError(f'invalid {name} value {value!r}')
    return value


def parse_rate_usd_per_hour(value: str) -> Decimal:
    """Parse a non-negative decimal USD/hour rate without binary floating-point drift."""
    try:
        rate = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f'invalid --cost-usd-per-hour value {value!r}') from exc
    if not rate.is_finite() or rate < 0:
        raise ValueError(f'--cost-usd-per-hour must be finite and non-negative, got {value!r}')
    return rate


def format_cost_note(wall_ns: int, rate_usd_per_hour: Decimal, image: str) -> tuple[str, str]:
    """Compute exact USD cost from wall nanoseconds and return `(cost_usd_str, ledger_note_suffix)`."""
    if type(wall_ns) is not int or wall_ns <= 0:
        raise ValueError(f'wall_ns must be a positive integer, got {wall_ns!r}')
    wall_s = Decimal(wall_ns) / Decimal(1_000_000_000)
    cost = (wall_s * rate_usd_per_hour / Decimal(3600)).quantize(Decimal('0.0001'), rounding=ROUND_HALF_UP)
    wall_s_str = wall_s.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    rate_str = rate_usd_per_hour.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    cost_str = f'{cost:.4f}'
    note = (
        f'Remote host run cost: ${cost_str} USD ({wall_s_str} s at ${rate_str}/hr; '
        f'pinned image {image}).'
    )
    return cost_str, note


def resolve_commit(commit: str | None) -> str:
    if commit is None:
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError(f'invalid 40-hex commit id: {commit!r}')
    return commit


def parse_gnu_time_with_resolution(path: Path) -> tuple[int, int, int]:
    """Return `(wall_ns, max_rss_bytes, resolution_ns)` from the trailing GNU `time -v` block.

    Supports both `m:ss.ss` (10 ms resolution) and `h:mm:ss` (>= 1 hour, 1 s resolution),
    anchoring on GNU time's tab-prefixed lines and taking the final block so child stderr
    lines preceding the timing summary cannot cause false matches.
    """
    text = path.read_text()
    statuses = re.findall(r'^\tExit status:\s*(\d+)\s*$', text, re.M)
    if not statuses or int(statuses[-1]) != 0:
        raise ValueError(f'non-zero or missing Exit status in {path}')
    walls = re.findall(
        r'^\tElapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*(?:(\d+):)?(\d+):(\d+)(?:\.(\d+))?\s*$',
        text, re.M,
    )
    rsses = re.findall(r'^\tMaximum resident set size \(kbytes\):\s*(\d+)\s*$', text, re.M)
    if not walls or not rsses:
        raise ValueError(f'missing wall time or max RSS in {path}')
    hours, mins, secs, frac = walls[-1]
    if frac:
        frac_ns = int((frac + '000000000')[:9])
        res_ns = 10 ** (9 - min(len(frac), 9))
    else:
        frac_ns = 0
        res_ns = 1_000_000_000
    total_ns = ((int(hours or 0) * 3600 + int(mins) * 60 + int(secs)) * 1_000_000_000) + frac_ns
    return total_ns, int(rsses[-1]) * 1024, res_ns


def parse_gnu_time(path: Path) -> tuple[int, int]:
    wall_ns, max_rss, _ = parse_gnu_time_with_resolution(path)
    return wall_ns, max_rss


def resolve_prove_wall_ns(out_dir: Path, time_wall_ns: int, resolution_ns: int) -> int:
    """Use exact `prove.wall_ns` when present and consistent with `prove.time` resolution."""
    wall_path = out_dir / 'prove.wall_ns'
    if not wall_path.is_file():
        return time_wall_ns
    text = wall_path.read_text().strip()
    if not re.fullmatch(r'[0-9]+', text):
        raise ValueError(f'invalid prove.wall_ns: {text!r}')
    exact_ns = int(text)
    if exact_ns <= 0 or abs(exact_ns - time_wall_ns) > resolution_ns:
        raise ValueError(
            f'prove.wall_ns ({exact_ns}ns) disagrees with prove.time ({time_wall_ns}ns ± {resolution_ns}ns)'
        )
    return exact_ns


def render_inner_script(
    *,
    rung: str,
    commit: str,
    threads: int,
    has_model_dir: bool,
) -> str:
    """Render the POSIX shell script that runs inside the digest-pinned container."""
    spec = RUNG_SPECS[rung]
    # Pure-stdlib Python timing fallback emits exact GNU `time -v` tab-prefixed lines using
    # integer centisecond divmod (never emits `:60.00`, supports >= 1h `h:mm:ss`), streams
    # child stderr directly to disk without buffering in RAM, and writes `prove.wall_ns`.
    py_timer = (
        'import pathlib,resource,subprocess,sys,time;'
        ' out_p,t_p,*cmd=sys.argv[1:];'
        ' t0=time.monotonic_ns();'
        ' out_f=open(out_p,"wb"); err_f=open(t_p,"wb");'
        ' p=subprocess.run(cmd,stdout=out_f,stderr=err_f);'
        ' out_f.close(); err_f.close();'
        ' dt=time.monotonic_ns()-t0;'
        ' rss=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss;'
        ' cs=(dt+5_000_000)//10_000_000; secs,c=divmod(cs,100); h,rem=divmod(secs,3600); m,s=divmod(rem,60);'
        ' elapsed=f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}.{c:02d}";'
        ' open(t_p,"a").write(f"\\n\\tElapsed (wall clock) time (h:mm:ss or m:ss): {elapsed}\\n'
        '\\tMaximum resident set size (kbytes): {rss}\\n\\tExit status: {p.returncode}\\n");'
        ' tp=pathlib.Path(t_p);'
        ' (tp.with_name("prove.wall_ns").write_text(f"{dt}\\n") if tp.name=="prove.time" else None);'
        ' sys.exit(p.returncode)'
    )
    lines = [
        '#!/usr/bin/env bash',
        'set -euo pipefail',
        'for tc_bin in /usr/local/rustup/toolchains/*/bin; do',
        '  if [ -d "$tc_bin" ]; then export PATH="$tc_bin:$PATH"; fi',
        'done',
        'if [ -d /work/toolbin ]; then export PATH="/work/toolbin:$PATH"; fi',
        f'export RAYON_NUM_THREADS={threads}',
        'export CARGO_INCREMENTAL=0',
        'unset STELE_STAGE_TIMES CARGO_TARGET_DIR PYTHONOPTIMIZE',
        'run_timed() {',
        '  local out_file="$1" time_file="$2"; shift 2',
        '  if [ -x /usr/bin/time ]; then',
        '    /usr/bin/time -v "$@" > "$out_file" 2> "$time_file"',
        '  else',
        f'    python3 -c {shlex.quote(py_timer)} "$out_file" "$time_file" "$@"',
        '  fi',
        '}',
        'cd /work/src',
        'rustc -V > /work/out/toolchain.txt',
        'uname -m > /work/out/arch.txt',
        "cpu_model=$(lscpu 2>/dev/null | awk -F: '/Model name:/ {gsub(/^[ \\t]+/, \"\", $2); print $2; exit}' || true)",
        'if [ -z "$cpu_model" ]; then cpu_model=$(uname -m); fi',
        'printf "%s\\n" "$cpu_model" > /work/out/cpu_model.txt',
        'cargo fetch --locked',
    ]
    if spec['kind'] == 'micro':
        # GPU parity smoke run (`scripts/gates/parity.sh`).
        lines += [
            'nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader > /work/out/gpu.txt',
            'run_timed /work/out/parity.out /work/out/parity.err bash scripts/gates/parity.sh',
            'cp /work/out/parity.err /work/out/parity.time',
            'sha256sum /work/out/parity.out | awk \'{print $1}\' > /work/out/proof.sha256',
        ]
    else:
        lines += [
            'cargo build --release --frozen -p stele-cli -p stele-bench',
            'cargo test --release --frozen --no-run -p stele-prover --test development',
            'mkdir -p /tmp/run',
        ]
        if spec['synthetic_case']:
            lines.append(
                f'python3 research/cqis-model-contract/synthetic_extract.py '
                f'crates/stele-prover/tests/fixtures {shlex.quote(spec["synthetic_case"])} /tmp/run'
            )
        else:
            if not has_model_dir:
                raise ValueError(f'rung {rung} requires --model-dir / STELE_REMOTE_MODEL_DIR')
            lines.append('cp /models/model.bin /models/preparation.bin /models/scales.bin /models/artifact.bin /tmp/run/')
        prove_cmd = [
            'target/release/stele', 'prove-dev',
            '--model', '/tmp/run/model.bin',
            '--preparation', '/tmp/run/preparation.bin',
            '--scales', '/tmp/run/scales.bin',
            '--artifact', '/tmp/run/artifact.bin',
            '--tokens', spec['tokens'],
            '--length', str(spec['length']),
            '--public', '/tmp/run/public.bin',
            '--proof', '/tmp/run/proof.bin',
        ]
        if spec['checked']:
            prove_cmd += ['--checked', spec['checked']]
        lines += [
            'run_timed /tmp/run/prove.out /tmp/run/prove.time ' + ' '.join(shlex.quote(c) for c in prove_cmd),
            'run_timed /tmp/run/verify.out /tmp/run/verify.time target/release/stele verify-dev --public /tmp/run/public.bin --proof /tmp/run/proof.bin',
            'STELE_DEV_PROOF=/tmp/run cargo test --release --frozen -p stele-prover --test development rejects_tampers_on_a_supplied_proof -- --ignored --nocapture > /tmp/run/controls.log 2>&1',
            'sha256sum /tmp/run/proof.bin | awk \'{print $1}\' > /work/out/proof.sha256',
            'sha256sum /tmp/run/public.bin | awk \'{print $1}\' > /work/out/public.sha256',
            'cp /tmp/run/prove.out /tmp/run/prove.time /tmp/run/verify.out /tmp/run/verify.time /tmp/run/controls.log /tmp/run/proof.bin /tmp/run/public.bin /work/out/',
            'if [ -f /tmp/run/prove.wall_ns ]; then cp /tmp/run/prove.wall_ns /work/out/; fi',
            'for f in model.bin preparation.bin scales.bin artifact.bin; do sha256sum "/tmp/run/$f" | awk \'{print $1}\' > "/work/out/$f.sha256"; done',
        ]
    lines.append('echo "REMOTE_RUN_COMPLETE"')
    return '\n'.join(lines) + '\n'


def render_outer_script(
    *,
    runtime: str,
    image: str,
    remote_run_dir: str,
    needs_gpu: bool,
    model_dir: str | None,
    nvrtc_dir: str | None,
    uv_bin: str | None,
    cargo_cache_dir: str | None,
    executor: str,
    threads: int,
    slurm_partition: str | None,
    slurm_nodelist: str | None,
    slurm_mem: str,
    slurm_time: str,
    slurm_gres: str | None,
) -> str:
    """Render the outer host/Slurm wrapper that provisions the pinned image and invokes inner.sh."""
    validate_pinned_image(image)
    validate_remote_dir(remote_run_dir)
    validate_host_mount_path('--model-dir', model_dir)
    validate_host_mount_path('--nvrtc-dir', nvrtc_dir)
    validate_host_mount_path('--uv-bin', uv_bin)
    validate_host_mount_path('--cargo-cache-dir', cargo_cache_dir)
    header = ['#!/usr/bin/env bash']
    if executor == 'slurm':
        validate_slurm_value('--slurm-mem', slurm_mem)
        validate_slurm_value('--slurm-time', slurm_time)
        validate_slurm_value('--slurm-partition', slurm_partition)
        validate_slurm_value('--slurm-nodelist', slurm_nodelist)
        validate_slurm_value('--slurm-gres', slurm_gres)
        header += [
            '#SBATCH --job-name=stele-remote',
            f'#SBATCH --cpus-per-task={threads}',
            f'#SBATCH --mem={slurm_mem}',
            f'#SBATCH --time={slurm_time}',
            '#SBATCH --no-requeue',
            f'#SBATCH --output={remote_run_dir}/slurm.out',
            f'#SBATCH --error={remote_run_dir}/slurm.err',
        ]
        if slurm_partition:
            header.append(f'#SBATCH --partition={slurm_partition}')
        if slurm_nodelist:
            header.append(f'#SBATCH --nodelist={slurm_nodelist}')
        if needs_gpu:
            header.append(f'#SBATCH --gres={slurm_gres or "gpu:1"}')
    header += [
        'set -euo pipefail',
        'umask 077',
        f'RUN_DIR={shlex.quote(remote_run_dir)}',
        'WORK=$(mktemp -d "${TMPDIR:-/tmp}/stele-remote-XXXXXX")',
        'trap \'rm -rf -- "$WORK"\' EXIT',
        'mkdir -p "$RUN_DIR/out" "$WORK/src" "$WORK/tmp" "$WORK/cargo" "$WORK/uv"',
        'tar -xzf "$RUN_DIR/src.tar.gz" -C "$WORK/src"',
        'chmod 755 "$RUN_DIR/inner.sh"',
    ]
    cargo_bind = shlex.quote(f'{cargo_cache_dir}:/work/cargo:rw') if cargo_cache_dir else '"$WORK/cargo:/work/cargo:rw"'
    if runtime == 'apptainer':
        header += [
            'export APPTAINER_CACHEDIR="$WORK/apptainer-cache"',
            'export APPTAINER_TMPDIR="$WORK/tmp"',
            'mkdir -p "$APPTAINER_CACHEDIR"',
            'if [ -r /run/systemd/resolve/resolv.conf ]; then grep \'^nameserver [0-9a-fA-F.:]*$\' /run/systemd/resolve/resolv.conf > "$WORK/resolv.conf"; else cp /etc/resolv.conf "$WORK/resolv.conf"; fi',
            'SIF="$WORK/image.sif"',
            f'apptainer pull --force "$SIF" {shlex.quote("docker://" + image)}',
        ]
        binds = [
            '"$WORK/src:/work/src:rw"',
            '"$RUN_DIR/out:/work/out:rw"',
            '"$RUN_DIR/inner.sh:/work/inner.sh:ro"',
            '"$WORK/tmp:/tmp:rw"',
            '"$WORK/resolv.conf:/etc/resolv.conf:ro"',
            cargo_bind,
            '"$WORK/uv:/work/uv:rw"',
        ]
        env_pairs = [
            'CARGO_HOME=/work/cargo',
            'RUSTUP_HOME=/usr/local/rustup',
            'UV_CACHE_DIR=/work/uv/cache',
            'UV_PYTHON_INSTALL_DIR=/work/uv/python',
            'PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        ]
        if model_dir:
            binds.append(shlex.quote(f'{model_dir}:/models:ro'))
        if nvrtc_dir:
            binds.append(shlex.quote(f'{nvrtc_dir}:/vendor-nvrtc:ro'))
            env_pairs.append('LD_LIBRARY_PATH=/vendor-nvrtc:/.singularity.d/libs')
        if uv_bin:
            header.append(f'mkdir -p "$WORK/toolbin" && cp -- {shlex.quote(uv_bin)} "$WORK/toolbin/uv" && chmod 755 "$WORK/toolbin/uv"')
            binds.append('"$WORK/toolbin:/work/toolbin:ro"')
        gpu_flag = '--nv ' if needs_gpu else ''
        bind_flags = ' '.join(f'--bind {b}' for b in binds)
        env_arg = ','.join(env_pairs)
        prefix = 'srun --cpu-bind=cores ' if (executor == 'slurm' and not needs_gpu) else ''
        header.append(
            f'{prefix}apptainer exec --containall --cleanenv --no-home --pwd /work/src {gpu_flag}'
            f'{bind_flags} --env {env_arg} "$SIF" /usr/bin/env HOME=/tmp /bin/bash /work/inner.sh'
        )
    elif runtime == 'docker':
        header.append(f'docker pull {shlex.quote(image)}')
        cmd = [
            'docker', 'run', '--rm', '-w', '/work/src',
            '-v', '"$WORK/src:/work/src:rw"',
            '-v', '"$RUN_DIR/out:/work/out:rw"',
            '-v', '"$RUN_DIR/inner.sh:/work/inner.sh:ro"',
            '-v', cargo_bind,
            '-v', '"$WORK/uv:/work/uv:rw"',
            '-e', 'CARGO_HOME=/work/cargo',
            '-e', 'UV_CACHE_DIR=/work/uv/cache',
            '-e', 'UV_PYTHON_INSTALL_DIR=/work/uv/python',
        ]
        if needs_gpu:
            cmd += ['--gpus', 'all']
        if model_dir:
            cmd += ['-v', shlex.quote(f'{model_dir}:/models:ro')]
        if nvrtc_dir:
            cmd += ['-v', shlex.quote(f'{nvrtc_dir}:/vendor-nvrtc:ro'), '-e', 'LD_LIBRARY_PATH=/vendor-nvrtc']
        if uv_bin:
            header.append(f'mkdir -p "$WORK/toolbin" && cp -- {shlex.quote(uv_bin)} "$WORK/toolbin/uv" && chmod 755 "$WORK/toolbin/uv"')
            cmd += ['-v', '"$WORK/toolbin:/work/toolbin:ro"']
        cmd += [shlex.quote(image), '/bin/bash', '/work/inner.sh']
        header.append(' '.join(cmd))
    else:
        raise ValueError(f'unsupported runtime: {runtime}')
    return '\n'.join(header) + '\n'


def build_gpu_parity_ledger(
    *,
    out_dir: Path,
    ledger_out: Path,
    commit: str,
    threads: int,
    image: str,
    rate_usd_per_hour: Decimal,
    host_context: str,
) -> tuple[str, str, int]:
    """Assemble and validate an RFC-0018 micro ledger for a remote GPU parity smoke run."""
    out_dir = out_dir.resolve()
    ledger_out = ledger_out.resolve()
    wall_ns, max_rss = parse_gnu_time(out_dir / 'parity.time')
    gpu_lines = [line.strip() for line in (out_dir / 'gpu.txt').read_text().splitlines() if line.strip()]
    if not gpu_lines:
        raise ValueError(f'empty GPU metadata in {out_dir / "gpu.txt"}')
    gpu_line = gpu_lines[0]
    parts = [p.strip() for p in gpu_line.split(',')]
    device = f'{parts[0]} ({parts[2]})' if len(parts) >= 3 else gpu_line
    driver = parts[1] if len(parts) >= 2 else 'unknown'
    toolchain = (out_dir / 'toolchain.txt').read_text().strip()
    parity_out = (out_dir / 'parity.out').read_bytes()
    parity_err = (out_dir / 'parity.err').read_bytes()
    if 'gate parity:' not in parity_out.decode(errors='replace'):
        raise ValueError('parity.out missing `gate parity:` completion receipt')
    parity_out_sha = hashlib.sha256(parity_out).hexdigest()
    recorded_sha = (out_dir / 'proof.sha256').read_text().strip()
    if parity_out_sha != recorded_sha:
        raise ValueError(f'parity receipt SHA-256 mismatch after transfer: local={parity_out_sha} remote={recorded_sha}')
    parity_err_sha = hashlib.sha256(parity_err).hexdigest()
    cost_str, cost_note = format_cost_note(wall_ns, rate_usd_per_hour, image)
    plan_obj = {
        'command': 'scripts/gates/parity.sh',
        'pinned_image': image,
        'threads': threads,
    }
    ledger = {
        'schema_version': 1,
        'kind': 'micro',
        'workload': RUNG_SPECS['gpu-parity']['workload'],
        'commit': commit,
        'toolchain': toolchain,
        'device': device,
        'driver': driver,
        'model_config': {
            **plan_obj,
            'host_context': host_context,
            'parity_out_sha256': parity_out_sha,
            'parity_err_sha256': parity_err_sha,
        },
        'plan_digest': hashlib.sha256(
            json.dumps(plan_obj, sort_keys=True, separators=(',', ':')).encode()
        ).hexdigest(),
        'profile': 'standard',
        'bindings_all_on': True,
        'batch_size': 1,
        'prompt_tokens': 0,
        'generated_tokens': 0,
        'prover_time_ns': wall_ns,
        'witness_recompute_ns': 0,
        'stage_times_ns': {'gpu_parity_smoke': wall_ns},
        'kernel_counters': {'parity_peak_rss_bytes': max_rss, 'parity_log_bytes': len(parity_out)},
        'proof_size_bytes': 0,
        'verifier_time_ns': {'rust': 0, 'python': 0},
        'controls': {'total': 0, 'passed': 0, 'failed': 0},
        'note': (
            'RFC-0018 §1 remote GPU parity smoke run (task E17-04) executing scripts/gates/parity.sh '
            'inside a digest-pinned image; verifies CPU/CUDA byte parity and negative controls on the '
            'development tier (claims no security level). '
            + cost_note
        ),
    }
    ledger_out.parent.mkdir(parents=True, exist_ok=True)
    ledger_out.write_text(json.dumps(ledger, indent=1, sort_keys=True) + '\n')
    subprocess.run(
        ['cargo', 'run', '-q', '-p', 'stele-bench', '--locked', '--offline', '--', 'ledger', 'validate', str(ledger_out)],
        cwd=ROOT, check=True,
    )
    return parity_out_sha, cost_str, wall_ns


def format_cpu_device(out_dir: Path) -> str:
    """Format CPU device label from actual `arch.txt` and `cpu_model.txt` without assuming x86_64."""
    arch_path = out_dir / 'arch.txt'
    arch = arch_path.read_text().strip() if arch_path.is_file() else ''
    cpu_model = (out_dir / 'cpu_model.txt').read_text().strip()
    if not cpu_model:
        raise ValueError(f'empty cpu_model.txt in {out_dir}')
    if arch and not cpu_model.startswith(arch):
        return f'{arch} {cpu_model}'
    return cpu_model


def build_inference_ledger(
    *,
    rung: str,
    out_dir: Path,
    ledger_out: Path,
    commit: str,
    threads: int,
    image: str,
    rate_usd_per_hour: Decimal,
    host_context: str,
) -> tuple[str, str, int]:
    """Assemble and validate an RFC-0018 A2 inference ledger via `bench/dev_e2e.py`."""
    out_dir = out_dir.resolve()
    ledger_out = ledger_out.resolve()
    spec = RUNG_SPECS[rung]
    time_wall_ns, _, res_ns = parse_gnu_time_with_resolution(out_dir / 'prove.time')
    wall_ns = resolve_prove_wall_ns(out_dir, time_wall_ns, res_ns)
    cost_str, cost_note = format_cost_note(wall_ns, rate_usd_per_hour, image)
    toolchain = (out_dir / 'toolchain.txt').read_text().strip()
    device = format_cpu_device(out_dir)
    mc = dict(spec['model_config'])
    mc['pinned_image'] = image
    for fname, key in [
        ('model.bin.sha256', 'model_sha256'),
        ('preparation.bin.sha256', 'preparation_sha256'),
        ('scales.bin.sha256', 'scales_sha256'),
        ('artifact.bin.sha256', 'artifact_sha256'),
    ]:
        p = out_dir / fname
        if p.is_file():
            mc[key] = p.read_text().strip()
    mc_path = out_dir / 'model_config.json'
    mc_path.write_text(json.dumps(mc, indent=2, sort_keys=True) + '\n')
    ledger_out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable, str(ROOT / 'bench/dev_e2e.py'),
            str(out_dir), str(ledger_out),
            '--workload', spec['workload'],
            '--rung', rung,
            '--commit', commit,
            '--device', device,
            '--toolchain', toolchain,
            '--prompt-tokens', str(spec['prompt_tokens']),
            '--threads', str(threads),
            '--model-config', str(mc_path),
            '--host-context', f'{host_context} (pinned image {image})',
            '--note-suffix', cost_note,
        ],
        cwd=ROOT, check=True,
    )
    proof_sha = hashlib.sha256((out_dir / 'proof.bin').read_bytes()).hexdigest()
    recorded_sha = (out_dir / 'proof.sha256').read_text().strip()
    if proof_sha != recorded_sha:
        raise ValueError(f'proof SHA-256 mismatch after transfer: local={proof_sha} remote={recorded_sha}')
    return proof_sha, cost_str, wall_ns


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--rung', required=True, choices=sorted(RUNG_SPECS), help='named rung or gpu-parity')
    p.add_argument('--out-dir', required=True, type=Path, help='local directory for downloaded logs and proof artifacts')
    p.add_argument('--ledger-out', required=True, type=Path, help='output path for the validated RFC-0018 ledger JSON')
    p.add_argument('--host', default=os.environ.get('STELE_REMOTE_HOST'), help='SSH host/alias (or STELE_REMOTE_HOST)')
    p.add_argument('--image', default=os.environ.get('STELE_REMOTE_IMAGE'), help='digest-pinned OCI image ref@sha256:... (or STELE_REMOTE_IMAGE)')
    p.add_argument('--runtime', choices=('apptainer', 'docker'), default='apptainer')
    p.add_argument('--executor', choices=('ssh', 'slurm'), default='ssh')
    p.add_argument('--remote-dir', default=os.environ.get('STELE_REMOTE_DIR', '/tmp/stele-remote'))
    p.add_argument('--model-dir', default=os.environ.get('STELE_REMOTE_MODEL_DIR'))
    p.add_argument('--nvrtc-dir', default=os.environ.get('STELE_REMOTE_NVRTC_DIR'))
    p.add_argument('--uv-bin', default=os.environ.get('STELE_REMOTE_UV_BIN'))
    p.add_argument('--cargo-cache-dir', default=os.environ.get('STELE_REMOTE_CARGO_CACHE'))
    p.add_argument('--threads', type=int, default=24)
    p.add_argument('--commit', help='40-hex git commit to archive (default: HEAD)')
    p.add_argument('--cost-usd-per-hour', required=True, help='host hourly USD rate recorded in the ledger note')
    p.add_argument('--host-context', required=True, help='non-sensitive hardware/allocation description for the ledger')
    p.add_argument('--slurm-partition', default=os.environ.get('STELE_SLURM_PARTITION'))
    p.add_argument('--slurm-nodelist', default=os.environ.get('STELE_SLURM_NODELIST'))
    p.add_argument('--slurm-mem', default='128G')
    p.add_argument('--slurm-time', default='01:30:00')
    p.add_argument('--slurm-gres', default='gpu:1')
    p.add_argument('--dry-run', action='store_true', help='print generated scripts and commands without executing SSH')
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.host:
        raise ValueError('remote host required via --host or STELE_REMOTE_HOST (never stored in repo)')
    if not args.image:
        raise ValueError('pinned container image required via --image or STELE_REMOTE_IMAGE')
    if args.threads <= 0:
        raise ValueError('--threads must be positive')
    host = validate_host(args.host)
    remote_dir = validate_remote_dir(args.remote_dir)
    image = validate_pinned_image(args.image)
    rate = parse_rate_usd_per_hour(args.cost_usd_per_hour)
    commit = resolve_commit(args.commit)
    out_dir = args.out_dir.resolve()
    ledger_out = args.ledger_out.resolve()
    spec = RUNG_SPECS[args.rung]
    run_id = f'{args.rung.lower()}-{commit[:12]}-{os.getpid()}'
    remote_run_dir = f'{remote_dir}/{run_id}'
    inner_script = render_inner_script(
        rung=args.rung, commit=commit, threads=args.threads, has_model_dir=bool(args.model_dir),
    )
    outer_script = render_outer_script(
        runtime=args.runtime, image=image, remote_run_dir=remote_run_dir,
        needs_gpu=spec['needs_gpu'], model_dir=args.model_dir, nvrtc_dir=args.nvrtc_dir,
        uv_bin=args.uv_bin, cargo_cache_dir=args.cargo_cache_dir,
        executor=args.executor, threads=args.threads,
        slurm_partition=args.slurm_partition, slurm_nodelist=args.slurm_nodelist,
        slurm_mem=args.slurm_mem, slurm_time=args.slurm_time, slurm_gres=args.slurm_gres,
    )
    if args.dry_run:
        print(json.dumps({
            'dry_run': True, 'rung': args.rung, 'commit': commit, 'image': image,
            'executor': args.executor, 'runtime': args.runtime,
            'remote_run_dir': remote_run_dir, 'inner_script': inner_script, 'outer_script': outer_script,
        }, indent=2))
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as stage_str:
        stage = Path(stage_str)
        tarball = stage / 'src.tar.gz'
        subprocess.run(['git', 'archive', '--format=tar.gz', '-o', str(tarball), commit], cwd=ROOT, check=True)
        (stage / 'inner.sh').write_text(inner_script)
        (stage / 'outer.sh').write_text(outer_script)
        subprocess.run(['ssh', '--', host, f'mkdir -p {shlex.quote(remote_run_dir)}'], check=True)
        subprocess.run(
            ['scp', '--', str(tarball), str(stage / 'inner.sh'), str(stage / 'outer.sh'),
             f'{host}:{remote_run_dir}/'],
            check=True,
        )
    if args.executor == 'slurm':
        subprocess.run(['ssh', '--', host, f'sbatch --wait {shlex.quote(remote_run_dir + "/outer.sh")}'], check=True)
    else:
        subprocess.run(['ssh', '--', host, f'bash {shlex.quote(remote_run_dir + "/outer.sh")}'], check=True)

    subprocess.run(
        ['scp', '-r', '--', f'{host}:{remote_run_dir}/out/.', str(out_dir)],
        check=True,
    )
    if spec['kind'] == 'micro':
        digest, cost_str, wall_ns = build_gpu_parity_ledger(
            out_dir=out_dir, ledger_out=ledger_out, commit=commit,
            threads=args.threads, image=image, rate_usd_per_hour=rate, host_context=args.host_context,
        )
    else:
        digest, cost_str, wall_ns = build_inference_ledger(
            rung=args.rung, out_dir=out_dir, ledger_out=ledger_out, commit=commit,
            threads=args.threads, image=image, rate_usd_per_hour=rate, host_context=args.host_context,
        )
    print(json.dumps({
        'rung': args.rung,
        'commit': commit,
        'image': image,
        'ledger': str(ledger_out),
        'logs_dir': str(out_dir),
        'digest_sha256': digest,
        'wall_ns': wall_ns,
        'cost_usd': cost_str,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except ValueError as err:
        print(f'bench/remote.py: {err}', file=sys.stderr)
        sys.exit(2)
