# Workflow 07 — Release
Gates: all CI gates; Workflow 05 complete; `CHANGELOG.md` lists ADRs and amendments; verifier crate builds reproducibly
(`scripts/reproducible-verifier.sh` digest matches on two machines); SBOM generated; proof format version bumped if the
container changed; passports from the previous release still verify (compatibility test) or a migration note exists.
