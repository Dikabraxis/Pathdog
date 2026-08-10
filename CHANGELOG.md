# Changelog

All notable changes to Pathdog are documented here.

## 1.1.0 - 2026-08-10

### Added

- Fail-closed BloodHound 9.5.1 relationship classification.
- Separate raw, post-processed, and traversable attack-graph stages.
- Group-aware `DCSync` and `SyncLAPSPassword` synthesis.
- SharpHound 2.14 metadata, archive safety limits, and `--compat` reporting.
- Vendored `valid_edges.json` snapshot for advisory source/target validation.
- Object-aware abuse guidance, prerequisites, and command confidence.
- Support for all current BloodHound traversable AD edge names.
- Installable `pathdog` console command and Python 3.11-3.14 CI.

### Changed

- Unknown and unsupported relationships are context-only instead of attack paths.
- Domain Admin target selection fails safely when multiple domains are ambiguous.
- Disabled accounts are excluded from roasting findings.
- Protected Users membership and the non-delegable account flag are separate findings.
- LAPS deployment alone no longer creates a confirmed pivot.
- Certipy templates use the Certipy 5.x `certipy` command.

### Security

- Added ZIP expansion, file-count, per-file, and compression-ratio limits.
- Dynamic AD labels containing shell syntax are replaced with explicit placeholders.
- Removed embedded example passwords from generated command templates.
