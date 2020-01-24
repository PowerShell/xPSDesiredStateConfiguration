# Change log for xPSDesiredStateConfiguration

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- DSC_xRegistryResource
  - Fixed an issue that failed to create a registry with ":" in the path.
    [issue #671](https://github.com/dsccommunity/xPSDesiredStateConfiguration/issues/671)

- xPSDesiredStateConfiguration
  - Export `Publish-*` functions in DscPullServerSetup module - Fixes
    [issue #673](https://github.com/PowerShell/PSDscResources/issues/673).

## [9.0.0] - 2020-01-15

### Added

- xPSDesiredStateConfiguration
  - Added support for Checksum on xRemoteFile - [issue #423](https://github.com/PowerShell/PSDscResources/issues/423)
  - Added `Test-DscParameterState` support function to `xPSDesiredStateConfiguration.Common.psm1`.
  - Added standard unit tests for `xPSDesiredStateConfiguration.Common.psm1`.
  - Added automatic release with a new CI pipeline.

### Changed

- xPSDesiredStateConfiguration
  - PublishModulesAndMofsToPullServer.psm1:
    - Fixes issue in Publish-MOFToPullServer that incorrectly tries to create a
      new MOF file instead of reading the existing one.
      [issue #575](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/575)
  - Fix minor style issues with missing spaces between `param` statements and '('.
  - MSFT_xDSCWebService:
    - Removal of commented out code.
    - Updated to meet HQRM style guidelines - Fixes [issue #623](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/623)
    - Added MOF descriptions.
  - Corrected minor style issues.
  - Fix minor style issues in hashtable layout.
  - Shared modules moved to `source/Module` folder and renamed:
    - `CommonResourceHelper.psm1` -> `xPSDesiredStateConfiguration.Common.psm1`
  - Moved functions from `ResourceSetHelper.psm1` into
    `xPSDesiredStateConfiguration.Common.psm1`.
  - BREAKING CHANGE: Changed resource prefix from MSFT to DSC.
  - Pinned `ModuleBuilder` to v1.0.0.
  - Updated build badges in README.MD.
  - Remove unused localization strings.
  - Adopt DSC Community Code of Conduct.
  - DSC_xPSSessionConfiguration:
    - Moved strings to localization file.
  - DSC_xScriptResource
    - Updated parameter descriptions to match MOF file.
  - Correct miscellaneous style issues.
  - DSC_xWindowsOptionalFeature
    - Fix localization strings.
  - DSC_xEnvironmentResource
    - Remove unused localization strings.
  - DSC_xRemoteFile
    - Updated end-to-end tests to use the same pattern as the other end-to-end
      tests in this module.
  - DSC_xDSCWebService
    - Moved `PSWSIISEndpoint.psm1` module into `xPSDesiredStateConfiguration.PSWSIIS`.
    - Moved `Firewall.psm1` module into `xPSDesiredStateConfiguration.Firewall`.
    - Moved `SecureTLSProtocols.psm1` and `UseSecurityBestPractices.psm1` module
      into `xPSDesiredStateConfiguration.Security`.
    - Fix issue with `Get-TargetResource` when a DSC Pull Server website is not
      installed.
  - DSC_xWindowsFeature
    - Changed tests to be able to run on machines without `*-WindowsFeature` cmdlets.
    - Changed `Assert-SingleInstanceOfFeature` to accept an array.
  - BREAKING CHANGE: Renamed `PublishModulesAndMofsToPullServer` module to
    `DscPullServerSetup` and moved to Modules folder.
  - Moved test helper modules into `tests\TestHelpers` folder.
- DSCPullServerSetup
  - Fixed markdown errors in README.MD.
  - Moved strings to Localization file.
  - Corrected style violations.
- Updated build badges to reflect correct Azure DevOps build Definition Id - fixes
  [issue #656](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/656).
- Set `testRunTitle` for PublishTestResults steps so that a helpful name is
  displayed in Azure DevOps for each test run.
- Set a display name on all the jobs and tasks in the CI
  pipeline - fixes [issue #663](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/663).

### Deprecated

- None

### Removed

- xPSDesiredStateConfiguration
  - Removed files no longer required by new CI process.

### Fixed

- MSFT_xRegistryResource
  - Fixes issue that the `Set-TargetResource` does not determine
    the type of registry value correctly.
    [issue #436](https://github.com/dsccommunity/xPSDesiredStateConfiguration/issues/436)
- Fixed Pull Server example links in `README.MD` - fixes
  [issue #659](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/659).
- Fixed `GitVersion.yml` feature and fix Regex - fixes
  [issue #660](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/660).
- Fix import statement in all tests, making sure it throws if module
  DscResource.Test cannot be imported - fixes
  [issue #666](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/666).
- Fix deploy stage in CI pipeline to prevent it executing against forks
  of the repository - fixes [issue #665](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/665).
- Fix deploy fork detection in CI pipeline - fixes [issue #668](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/668).

### Security

- None
