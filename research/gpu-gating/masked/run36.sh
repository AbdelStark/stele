#!/usr/bin/env bash
# E16-36 box script. Output in ~/out.
set -uo pipefail
export PATH="$HOME/.cargo/bin:$PATH" LD_LIBRARY_PATH=/usr/local/cuda/lib64
mkdir -p ~/out
{ nvidia-smi; nproc; lscpu | head -20; free -g; nvidia-smi -q | grep -A4 "Link Width"; } > ~/out/host.txt 2>&1
B=~/tree/research/gpu-gating/masked
(cd $B && cargo build --release --features cuda --locked 2>&1 | tail -2) > ~/out/build.txt
(cd $B && STELE_E16_36_SOURCES=4:10,6:12,11:16 cargo test --release --features cuda --locked -- --nocapture) > ~/out/parity.txt 2>&1
echo "parity exit $?" >> ~/out/parity.txt
X=$B/target/release/stele-masked-gpu-bench
for m in 15 16 17; do
  $X source 11 $m check > ~/out/source-check-11-$m.txt 2>&1
  for rep in 1 2 3; do
    $X source 11 $m gpu > ~/out/source-gpu-11-$m-$rep.txt 2>&1
    $X source 11 $m cpu > ~/out/source-cpu-11-$m-$rep.txt 2>&1
  done
done
for shape in relation gkr; do
  for n in 24 26 27; do
    for rep in 1 2 3; do
      $X $shape $n gpu > ~/out/gpu-$shape-$n-$rep.txt 2>&1
      $X $shape $n cpu > ~/out/cpu-main-$shape-$n-$rep.txt 2>&1
    done
  done
done
for r in 1 2 3; do $X h2d 28; done > ~/out/h2d.txt 2>&1
echo ALLDONE > ~/out/done.txt
