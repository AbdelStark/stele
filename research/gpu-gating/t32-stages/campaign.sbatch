#!/bin/bash
#SBATCH --job-name=stele-t32-stages
#SBATCH --partition=main
#SBATCH --constraint=h100|h100nvl
#SBATCH --gres=gpu:1
#SBATCH --cpus-per-task=16
#SBATCH --mem=160G
#SBATCH --time=01:45:00
#SBATCH --no-requeue
set -euo pipefail
umask 077
export PATH="$HOME/.cargo/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/stele-codex/cuda-env/lib/python3.12/site-packages/nvidia/cuda_nvrtc/lib:${LD_LIBRARY_PATH:-}"
export CARGO_INCREMENTAL=0 RAYON_NUM_THREADS=16
unset STELE_STAGE_TIMES CARGO_TARGET_DIR PYTHONOPTIMIZE
stage=$SLURM_SUBMIT_DIR
cd "$stage"
sha256sum -c SHA256SUMS
run="$stage/job-$SLURM_JOB_ID"
mkdir -p "$run/source"
tar -xzf source.tar.gz -C "$run/source" --no-same-owner
cd "$run/source"
nvidia-smi --query-gpu=name,uuid,driver_version,memory.total --format=csv > "$run/gpu.txt"
rustc -Vv > "$run/toolchain.txt"
lscpu > "$run/cpu.txt"
python3 -B research/gpu-gating/t32-stages/install.py . "$@"
cargo fetch --locked
cargo build --frozen --release -p stele-cli
srun --cpu-bind=cores python3 -B research/gpu-gating/t32-stages/capture.py "$@"
