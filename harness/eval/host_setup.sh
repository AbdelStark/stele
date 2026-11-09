#!/usr/bin/env bash
# Prepare a rented GPU host (image pytorch/pytorch:2.5.1-cuda12.4-cudnn9-devel, run as
# root) to execute modal_e505.py without Modal: the repository at /root/stele, data in
# /vol. Mirrors the Modal image pins. HF_TOKEN is passed per command, never written here.
set -euo pipefail
apt-get update -qq && apt-get install -y -qq curl build-essential pkg-config git rsync tmux >/dev/null
command -v cargo >/dev/null || curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.90.0 --profile minimal
pip install -q torch==2.5.1 numpy==1.26.4 blake3==1.0.11 python-flint==0.9.0 \
  safetensors==0.6.2 transformers==4.46.3 accelerate==1.1.1 datasets==3.1.0 \
  huggingface_hub==0.26.2 lm_eval==0.4.5 langdetect==1.0.9 immutabledict==4.2.1 \
  nltk==3.9.1 pyarrow==17.0.0
mkdir -p /vol
echo 'export HF_HOME=/vol/hf PYTHONUNBUFFERED=1 PATH=/root/.cargo/bin:$PATH' >> /root/.bashrc
