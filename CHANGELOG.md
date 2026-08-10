# Changelog

All notable changes to Pathdog are documented here.

## 1.2.0 - 2026-08-10

### Added

- Current SharpHound Version 6 extraction for sessions, local groups, user
  rights, SPN targets, primary groups, containment and AD CS relationships.
- BloodHound-compatible `OwnsRaw` / `WriteOwnerRaw` processing with
  `BlockOwnerImplicitRights` handling.
- AD CS topology synthesis for `EnterpriseCAFor`, `IssuedSignedBy`,
  `TrustedForNTAuth`, `ExtendedByPolicy` and `EnrollOnBehalfOf`.
- Conservative raw-data synthesis for ESC1, ESC3, ESC4, ESC13 and
  `GoldenCert`, including group-effective enrollment rights.
- Calculated-edge evidence so reports can place the actual CA/template names
  into Certipy commands.
- `HasTrustKeys` synthesis from trust direction, domain NetBIOS name and the
  collected trust account.
- A checksum-pinned official BloodHound Version 6 ADCS oracle job in CI.

### Changed

- The Version 6 ADCS fixture now ingests the same 2,560 raw relationships as
  BloodHound and reproduces its fixture's ESC1/topology outputs.
- `CanApplyGPO` and `WritePublicInformation` now include executable,
  prerequisite-aware guidance instead of description-only output.
- Calculated ESC and GoldenCert commands no longer confuse the destination
  domain with the vulnerable CA or certificate template.

### Fixed

- Current collector `Owns`/`WriteOwner` ACEs are retained as raw rights and
  are no longer treated as already post-processed edges.
- Bare sessions, `RemoteInteractiveLogonRight`, CA registry ACLs and several
  embedded Version 6 relationship arrays are no longer dropped.

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
