#!/usr/bin/env bash
# E16-35 box script: build, parity, timings. Output in ~/out.
set -uo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
mkdir -p ~/out
{ nvidia-smi; nproc; lscpu | head -20; free -g; } > ~/out/host.txt 2>&1
for tree in main pr364; do
  (cd ~/$tree/research/gpu-gating/masked && cargo build --release --features cuda 2>&1 | tail -2) >> ~/out/build.txt
done
B=~/main/research/gpu-gating/masked
(cd $B && STELE_E16_35_LOGN=20,22,24,26,27 cargo test --release --features cuda -- --nocapture) > ~/out/parity.txt 2>&1
echo "parity exit $?" >> ~/out/parity.txt
for shape in relation gkr; do
  for n in 20 22 24 26 27; do
    $B/target/release/stele-masked-gpu-bench $shape $n check > ~/out/check-$shape-$n.txt 2>&1
    for rep in 1 2 3; do
      $B/target/release/stele-masked-gpu-bench $shape $n gpu > ~/out/gpu-$shape-$n-$rep.txt 2>&1
      $B/target/release/stele-masked-gpu-bench $shape $n cpu > ~/out/cpu-main-$shape-$n-$rep.txt 2>&1
      ~/pr364/research/gpu-gating/masked/target/release/stele-masked-gpu-bench $shape $n cpu > ~/out/cpu-pr364-$shape-$n-$rep.txt 2>&1
    done
  done
done
echo ALLDONE > ~/out/done.txt
