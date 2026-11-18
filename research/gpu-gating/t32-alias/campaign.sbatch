#!/bin/bash
#SBATCH --job-name=stele-cpu-alias
#SBATCH --partition=main
#SBATCH --constraint=rtxpro6000
#SBATCH --cpus-per-task=16
#SBATCH --mem=160G
#SBATCH --time=01:10:00
#SBATCH --no-requeue
set -euo pipefail
umask 077
export PATH="$HOME/.cargo/bin:$PATH" CARGO_INCREMENTAL=0 RAYON_NUM_THREADS=16
unset STELE_STAGE_TIMES CARGO_TARGET_DIR PYTHONOPTIMIZE
cd "$SLURM_SUBMIT_DIR"
sha256sum -c SHA256SUMS
run="$PWD/job-$SLURM_JOB_ID"
mkdir -p "$run/source"
tar -xzf source.tar.gz -C "$run/source" --no-same-owner
cd "$run/source"
rustc -Vv > "$run/toolchain.txt"
lscpu > "$run/cpu.txt"
python3 -B research/gpu-gating/t32-alias/install.py .
cargo fetch --locked
cargo test --frozen -p stele-reductions --lib t32_alias::tests > "$run/controls.txt"
grep -F '2 passed; 0 failed' "$run/controls.txt"
cargo build --frozen --release -p stele-cli
scratch=$(mktemp -d /tmp/stele-alias.XXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
export STELE_PROVE_STDERR="$scratch/prove.err"
srun --cpu-bind=cores python3 -B research/gpu-gating/t32-alias/capture.py
