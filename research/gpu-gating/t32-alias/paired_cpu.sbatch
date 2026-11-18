#!/bin/bash
#SBATCH --job-name=stele-cpu-original-inputs
#SBATCH --partition=main
#SBATCH --constraint=rtxpro6000
#SBATCH --cpus-per-task=16
#SBATCH --mem=160G
#SBATCH --time=01:20:00
#SBATCH --no-requeue
set -euo pipefail
umask 077
stage="$SLURM_SUBMIT_DIR"
run="$stage/job-$SLURM_JOB_ID"
local_run=$(mktemp -d "/tmp/stele-original-inputs-$SLURM_JOB_ID.XXXXXX")
exec >"$local_run/campaign.log" 2>&1
save_public() {
    local status=$?
    set +e
    mkdir -p "$run/run" "$run/source/target/release"
    cp "$local_run/campaign.log" "$run/campaign.log"
    for name in toolchain.txt cpu.txt controls.txt ; do
        test ! -f "$local_run/$name" || cp "$local_run/$name" "$run/"
    done
    for label in commit prove verify wrong; do
        for suffix in err out json time; do
            file="$local_run/run/$label.$suffix"
            test ! -f "$file" || cp "$file" "$run/run/"
        done
    done
    for name in result.json proof.bin public.bin; do
        test ! -f "$local_run/run/$name" || cp "$local_run/run/$name" "$run/run/"
    done
    if test -f "$local_run/source/target/release/stele"; then
        cp "$local_run/source/target/release/stele" "$run/source/target/release/"
    fi
    if test "$status" -eq 0; then
        cmp "$local_run/run/result.json" "$run/run/result.json" &&
        cmp "$local_run/run/proof.bin" "$run/run/proof.bin" &&
        cmp "$local_run/run/public.bin" "$run/run/public.bin" || status=1
    fi
    if test "$status" -eq 0; then rm -rf -- "$local_run"; fi
    exit "$status"
}
trap save_public EXIT
export PATH="$HOME/.cargo/bin:$PATH" CARGO_INCREMENTAL=0 RAYON_NUM_THREADS=16
unset STELE_STAGE_TIMES CARGO_TARGET_DIR STELE_PROVE_STDERR PYTHONOPTIMIZE
cd "$stage"
sha256sum --check SHA256SUMS
mkdir "$local_run/source"
tar -xzf source.tar.gz -C "$local_run/source" --no-same-owner
cd "$local_run/source"
lscpu > "$local_run/cpu.txt"
rustc -Vv > "$local_run/toolchain.txt"
python3 -B research/gpu-gating/t32-host-pack/install.py .
python3 -B research/gpu-gating/t32-alias/install.py .
cargo fetch --locked
cargo test --frozen -p stele-reductions --lib t32_alias::tests > "$local_run/controls.txt"
grep -F '2 passed; 0 failed' "$local_run/controls.txt"
cargo build --frozen --release -p stele-cli
srun --cpu-bind=cores python3 -B research/gpu-gating/t32-alias/paired_cpu.py
