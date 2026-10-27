# Workflow 00 — Bootstrap a fresh clone (first agent on a new machine)
1. `scripts/scaffold.sh` (idempotent) creates the Cargo workspace from RFC-0020 if `crates/` is empty.
2. Install the pinned toolchain (`rust-toolchain.toml`), `uv` for `harness/`, CUDA 12.x if a GPU is present.
3. `cargo build --workspace && cargo test --workspace` must pass on the skeleton (empty tests).
4. `scripts/gates/*.sh` must each exit 0 with "nothing to check" on the skeleton.
5. Open `agents/tasks/graph.yaml`; claim the first `ready` task of epic E0.
