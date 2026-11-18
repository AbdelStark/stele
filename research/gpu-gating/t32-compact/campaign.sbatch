#!/bin/bash
#SBATCH --job-name=stele-t32-compact-lookups
#SBATCH --partition=main
#SBATCH --gres=gpu:1
#SBATCH --constraint=h100nvl
#SBATCH --nodelist=h100-nvl-1-1-cc
#SBATCH --cpus-per-task=16
#SBATCH --mem=160G
#SBATCH --time=01:45:00
#SBATCH --no-requeue
set -euo pipefail
umask 077
export PATH="$HOME/.cargo/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/stele-codex/cuda-env/lib/python3.12/site-packages/nvidia/cuda_nvrtc/lib:${LD_LIBRARY_PATH:-}"
export CARGO_INCREMENTAL=0 RAYON_NUM_THREADS=16
unset CARGO_TARGET_DIR PYTHONOPTIMIZE STELE_STAGE_TIMES
cd "$SLURM_SUBMIT_DIR"
sha256sum -c SHA256SUMS
job="$SLURM_SUBMIT_DIR/job-$SLURM_JOB_ID"
mkdir -m 700 "$job"
mkdir "$job/source"
tar -xzf source.tar.gz -C "$job/source" --no-same-owner
cd "$job/source"
nvidia-smi --query-gpu=name,uuid,driver_version,memory.total --format=csv > "$job/gpu.txt"
rustc -Vv > "$job/toolchain.txt"
lscpu > "$job/cpu.txt"
python3 -B research/gpu-gating/t32-compact/install.py .
cargo fetch --locked
manifest=research/gpu-gating/masked/Cargo.toml
cargo fetch --locked --manifest-path "$manifest"
# Compile the exact measured binary before running the seeded hardware gate.
cargo build --release --frozen -p stele-cli
for test in matches_reference_compact_leaf_expressions accepts_borrowed_base_inputs_and_rejects_bad_projection; do
    srun --cpu-bind=cores cargo test --frozen --manifest-path "$manifest" --features cuda --lib "$test" > "$job/$test.out" 2> "$job/$test.err"
    grep -q '1 passed; 0 failed; 0 ignored' "$job/$test.out"
done
srun --cpu-bind=cores cargo test --frozen --manifest-path "$manifest" --features cuda --lib matches_reference_compact_lookups_on_h100 -- --ignored --nocapture > "$job/device.out" 2> "$job/device.err"
grep -q '1 passed; 0 failed; 0 ignored' "$job/device.out"
grep -q 'compact_lookup_cases=1000 raw_leaf_cases=1000 raw_top_cases=1000 complete_trees=2000 near_miss_cases=1000 zero_denominator_cases=1' "$job/device.err"
srun --cpu-bind=cores cargo test --frozen -p stele-reductions --features bench --lib matches_reference_base_and_extension_rounds > "$job/mixed.out" 2> "$job/mixed.err"
grep -q '1 passed; 0 failed; 0 ignored' "$job/mixed.out"
export STELE_STAGE_TIMES=1
nvidia-smi --query-gpu=timestamp,memory.used,utilization.gpu --format=csv -l 5 > "$job/gpu-memory.csv" &
sampler=$!
trap 'kill "$sampler" 2>/dev/null || true' EXIT
srun --cpu-bind=cores python3 -B research/gpu-gating/t32-resident/capture.py
