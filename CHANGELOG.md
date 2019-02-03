# Versions

## Unreleased

- Corrected GitHub Pull Request template to remove referral to
  `BestPractices.MD` which has been combined into `StyleGuidelines.md`
  ([issue #520](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/520)).
- xWindowsOptionalFeature
  - Suppress useless verbose output from `Import-Module` cmdlet.
    ([issue #453](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/453)).
- Changes to xRemoteFile
  - Corrected a resource name in the example xRemoteFile_DownloadFileConfig.ps1
- Fix `MSFT_xDSCWebService` to find
 `Microsoft.Powershell.DesiredStateConfiguration.Service.Resources.dll`
  when server is configured with pt-BR Locales
  ([issue #284](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/284)).
- Changes to xDSCWebService
  - Fixed an issue which prevented the removal of the IIS Application Pool
    created during deployment of an DSC Pull Server instance.
    ([issue #464](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/464))
  - Fixed an issue where a Pull Server cannot be deployed on a machine when IIS
    Express is installed aside a full blown IIS
    ([issue #191](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/191))
- Update `CommonResourceHelper` unit tests to meet Pester 4.0.0
  standards
  ([issue #473](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/473)).
- Update `ResourceHelper` unit tests to meet Pester 4.0.0
  standards
  ([issue #473](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/473)).
- Update `MSFT_xDSCWebService` unit tests to meet Pester 4.0.0
  standards
  ([issue #473](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/473)).
- Update `MSFT_xDSCWebService` integration tests to meet Pester 4.0.0
  standards
  ([issue #473](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/473)).
- Refactored `MSFT_xDSCWebService` integration tests to meet current
  standards and to use Pester TestDrive.
- xArchive
  - Fix end-to-end tests
    ([issue #457](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/457)).
  - Update integration tests to meet Pester 4.0.0 standards.
  - Update end-to-end tests to meet Pester 4.0.0 standards.
  - Update unit and integration tests to meet Pester 4.0.0 standards.
  - Wrapped all path and identifier strings in verbose messages with
    quotes to make it easier to identify the limit of the string when
    debugging.
  - Refactored date/time checksum code to improve testability and ensure
    tests can run on machines with localized datetime formats that are not
    US.
  - Fix 'Get-ArchiveEntryLastWriteTime' to return `[datetime]`
    ([issue #471](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/471)).
  - Improved verbose logging to make debugging path issues easier.
  - Added handling for '/' as a path seperator by backporting code from
    PSDscResources -
    ([issue #469](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/469)).
  - Copied unit tests from
    [PSDscResources](https://github.com/PowerShell/PSDscResources).
  - Added .gitattributes file and removed git configuration from AppVeyor
    to ensure CRLF settings are configured correctly for the repository.
- Updated '.vscode\settings.json' to refer to AnalyzerSettings.psd1 so that
  custom syntax problems are highlighted in Visual Studio Code.
- Fixed style guideline violations in `CommonResourceHelper.psm1`.
- Changes to xService
  - Fixes issue where Get-TargetResource or Test-TargetResource will throw an
    exception if the target service is configured with a non-existent
    dependency.
  - Refactored Get-TargetResource Unit tests.
- Changes to xPackage
  - Fixes an issue where incorrect verbose output was displayed if product
    found.
    ([issue #446](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/446))
- Fixes files which are getting triggered for re-encoding after recent pull
  request (possibly #472).
- Moves version and change history from README.MD to new file, CHANGELOG.MD.
- Fixes markdown issues in README.MD and HighQualityResourceModulePlan.md.
- Opted in to 'Common Tests - Validate Markdown Files'
- Changes to xPSDesiredStateConfiguration
  - In AppVeyor CI the tests are split into three separate jobs, and also
    run tests on two different build worker images (Windows Server 2012R2
    and Windows Server 2016). The common tests are only run on the
    Windows Server 2016 build worker image. Helps with
    [issue #477](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/477).
- xGroup
  - Corrected style guideline violations. ([issue #485](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/485))

## 8.5.0.0

- Changes to xRegistry
  - Fixed an issue that fails to remove reg key when the `Key` is specified as
    common registry path.
    ([issue #444](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/444))
- Changes to xService
  - Added support for Group Managed Service Accounts

## 8.4.0.0

- Changes to xPSDesiredStateConfiguration
  - Opt-in for the common tests validate module files and script files.
  - All files change to encoding UTF-8 (without byte order mark).
  - Opt-in for the common test for example validation.
  - Added Visual Studio Code workspace settings that helps with formatting
    against the style guideline.
  - Update all examples for them to be able pass the common test validation.
- xEnvironment path documentation update demonstrating usage with multiple
  values
  ([issue #415](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/415).
  [Alex Kokkinos (@alexkokkinos)](https://github.com/alexkokkinos)
- Changes to xWindowsProcess
  - Increased the wait time in the integration tests since the tests
    still failed randomly
    ([issue #420](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/420)).
- Renamed and updated examples to be able to publish them to PowerShell
  Gallery.
  - Sample\_xScript.ps1 → xScript\_WatchFileContentConfig.ps1
  - Sample\_xService\_UpdateStartupTypeIgnoreState.ps1 →
    xService\_UpdateStartupTypeIgnoreStateConfig.ps1
  - Sample\_xWindowsProcess\_Start.ps1 →
    xWindowsProcess\_StartProcessConfig.ps1
  - Sample\_xWindowsProcess\_StartUnderUser.ps1 →
    xWindowsProcess\_StartProcessUnderUserConfig.ps1
  - Sample\_xWindowsProcess\_Stop.ps1 → xWindowsProcess\_StopProcessConfig.ps1
  - Sample\_xWindowsProcess\_StopUnderUser.ps1 →
    xWindowsProcess\_StopProcessUnderUserConfig.ps1
  - Sample\_xUser\_CreateUser.ps1.ps1 → xUser\_CreateUserConfig.ps1
  - Sample\_xUser\_Generic.ps1.ps1 → xUser\_CreateUserDetailedConfig.ps1
  - Sample\_xWindowsFeature.ps1 → xWindowsFeature\_AddFeatureConfig.ps1
  - Sample\_xWindowsFeatureSet\_Install.ps1 →
    xWindowsFeatureSet\_AddFeaturesConfig.ps1
  - Sample\_xWindowsFeatureSet\_Uninstall.ps1 →
    xWindowsFeatureSet\_RemoveFeaturesConfig.ps1
  - Sample\_xRegistryResource\_AddKey.ps1 → xRegistryResource\_AddKeyConfig.ps1
  - Sample\_xRegistryResource\_RemoveKey.ps1 →
    xRegistryResource\_RemoveKeyConfig.ps1
  - Sample\_xRegistryResource\_AddOrModifyValue.ps1 →
    xRegistryResource\_AddOrModifyValueConfig.ps1
  - Sample\_xRegistryResource\_RemoveValue.ps1 →
    xRegistryResource\_RemoveValueConfig.ps1
  - Sample\_xService\_CreateService.ps1 → xService\_CreateServiceConfig.ps1
  - Sample\_xService\_DeleteService.ps1 → xService\_RemoveServiceConfig.ps1
  - Sample\_xServiceSet\_StartServices.ps1 →
    xServiceSet\_StartServicesConfig.ps1
  - Sample\_xServiceSet\_BuiltInAccount →
    xServiceSet\_EnsureBuiltInAccountConfig.ps1
  - Sample\_xWindowsPackageCab → xWindowsPackageCab\_InstallPackageConfig
  - Sample\_xWindowsOptionalFeature.ps1 →
    xWindowsOptionalFeature\_EnableConfig.ps1
  - Sample\_xWindowsOptionalFeatureSet\_Enable.ps1 →
    xWindowsOptionalFeatureSet\_EnableConfig.ps1
  - Sample\_xWindowsOptionalFeatureSet\_Disable.ps1 →
    xWindowsOptionalFeatureSet\_DisableConfig.ps1
  - Sample\_xRemoteFileUsingProxy.ps1 →
    xRemoteFile\_DownloadFileUsingProxyConfig.ps1
  - Sample\_xRemoteFile.ps1 → xRemoteFile\_DownloadFileConfig.ps1
  - Sample\_xProcessSet\_Start.ps1 → xProcessSet\_StartProcessConfig.ps1
  - Sample\_xProcessSet\_Stop.ps1 → xProcessSet\_StopProcessConfig.ps1
  - Sample\_xMsiPackage\_UninstallPackageFromHttps.ps1 →
    xMsiPackage\_UninstallPackageFromHttpsConfig.ps1
  - Sample\_xMsiPackage\_UninstallPackageFromFile.ps1 →
    xMsiPackage\_UninstallPackageFromFileConfig.ps1
  - Sample\_xMsiPackage\_InstallPackageFromFile →
    xMsiPackage\_InstallPackageConfig.ps1
  - Sample\_xGroup\_SetMembers.ps1 → xGroup\_SetMembersConfig.ps1
  - Sample\_xGroup\_RemoveMembers.ps1 → xGroup\_RemoveMembersConfig.ps1
  - Sample\_xGroupSet\_AddMembers.ps1 → xGroupSet\_AddMembersConfig.ps1
  - Sample\_xFileUpload.ps1 → xFileUpload\_UploadToSMBShareConfig.ps1
  - Sample\_xEnvironment\_CreateMultiplePathVariables.ps1 →
    xEnvironment\_AddMultiplePathsConfig.ps1
  - Sample\_xEnvironment\_RemovePathVariables.ps1 →
    xEnvironment\_RemoveMultiplePathsConfig.ps1
  - Sample\_xEnvironment\_CreateNonPathVariable.ps1 →
    xEnvironment\_CreateNonPathVariableConfig.ps1
  - Sample\_xEnvironment\_Remove.ps1 → xEnvironment\_RemoveVariableConfig.ps1
  - Sample\_xArchive\_ExpandArchiveChecksumAndForce.ps1 →
    xArchive\_ExpandArchiveChecksumAndForceConfig.ps1
  - Sample\_xArchive\_ExpandArchiveDefaultValidationAndForce.ps1 →
    xArchive\_ExpandArchiveDefaultValidationAndForceConfig.ps1
  - Sample\_xArchive\_ExpandArchiveNoValidation.ps1 →
    xArchive\_ExpandArchiveNoValidationConfig.ps1
  - Sample\_xArchive\_ExpandArchiveNoValidationCredential.ps1 →
    xArchive\_ExpandArchiveNoValidationCredentialConfig.ps1
  - Sample\_xArchive\_RemoveArchiveChecksum.ps1 →
    xArchive\_RemoveArchiveChecksumConfig.ps1
  - Sample\_xArchive\_RemoveArchiveNoValidation.ps1 →
    xArchive\_RemoveArchiveNoValidationConfig.ps1
  - Sample\_InstallExeCreds\_xPackage.ps1 →
    xPackage\_InstallExeUsingCredentialsConfig.ps1
  - Sample\_InstallExeCredsRegistry\_xPackage.ps1 →
    xPackage\_InstallExeUsingCredentialsAndRegistryConfig.ps1
  - Sample\_InstallMSI\_xPackage.ps1 → xPackage\_InstallMsiConfig.ps1
  - Sample\_InstallMSIProductId\_xPackage.ps1 →
    xPackage\_InstallMsiUsingProductIdConfig.ps1
- New examples
  - xUser\_RemoveUserConfig.ps1
  - xWindowsFeature\_AddFeatureUsingCredentialConfig.ps1
  - xWindowsFeature\_AddFeatureWithLogPathConfig.ps1
  - xWindowsFeature\_RemoveFeatureConfig.ps1
  - xService\_ChangeServiceStateConfig.ps1
  - xWindowsOptionalFeature\_DisableConfig.ps1
  - xPSEndpoint\_NewConfig.ps1
  - xPSEndpoint\_NewWithDefaultsConfig.ps1
  - xPSEndpoint\_RemoveConfig.ps1
  - xPSEndpoint\_NewCustomConfig.ps1
- Removed examples
  - Sample\_xPSSessionConfiguration.ps1 - This file was split up in several
    examples, those starting with 'xPSEndpoint*'.
  - Sample\_xMsiPackage\_InstallPackageFromHttp - This was added to the example
    xMsiPackage\_InstallPackageConfig.ps1 so the example sows either URI
    scheme.
  - Sample\_xEnvironment\_CreatePathVariable.ps1 - Same as the new example
    xEnvironment\_AddMultiplePaths.ps1

## 8.3.0.0

- Changes to xPSDesiredStateConfiguration
  - README.md: Fixed typo.
    [Steve Banik (@stevebanik-ndsc)](https://github.com/stevebanik-ndsc)
  - Adding a Branches section to the README.md with Codecov badges for both
    master and dev branch
    ([issue #416](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/416)).
- Changes to xWindowsProcess
  - Integration tests for this resource should no longer fail randomly. A
    timing issue made the tests fail in certain scenarios
    ([issue #420](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/420)).
- Changes to xDSCWebService
  - Added the option to use a certificate based on it's subject and template
    name instead of it's thumbprint. Resolves
    [issue #205](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/205).
  - xDSCWebService: Fixed an issue where Test-WebConfigModulesSetting would
    return $true when web.config contains a module and the desired state was
    for it to be absent. Resolves
    [issue #418](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/418).
- Updated the main DSCPullServerSetup readme to read easier, then updates the
  PowerShell comment based help for each function to follow normal help
  standards. [James Pogran (@jpogran)](https://github.com/jpogran)
- xRemoteFile: Remove progress bar for file download. This resolves issues
  [#165](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/165)
  and
  [#383](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/383)
  [Claudio Spizzi (@claudiospizzi)](https://github.com/claudiospizzi)

## 8.2.0.0

- xDSCWebService: Disable installing
  Microsoft.Powershell.Desiredstateconfiguration.Service.Resources.dll as a
  temporary workaround since the binary is missing on the latest Windows
  builds.

## 8.1.0.0

- xDSCWebService: Enable SQL provider configuration

## 8.0.0.0

- xDSCWebService
  - BREAKING CHANGE: The Pull Server will now run in a 64 bit IIS process by
    default. Enable32BitAppOnWin64 needs to be set to TRUE for the Pull
    Server to run in a 32 bit process.

## 7.0.0.0

- xService
  - BREAKING CHANGE: The service will now return as compliant if the service
    is not installed and the StartupType is set to Disabled regardless of the
    value of the Ensure property.
- Fixed misnamed certificate thumbprint variable in example
  Sample_xDscWebServiceRegistrationWithSecurityBestPractices

## 6.4.0.0

- xGroup:
  - Added updates from PSDscResources:
    - Added support for domain based group members on Nano server

## 6.3.0.0

- xDSCWebService
  - Fixed an issue where all 64bit IIS application pools stop working after
    installing DSC Pull Server, because IISSelfSignedCertModule(32bit) module
    was registered without bitness32 precondition.

## 6.2.0.0

- xMsiPackage:
  - Created high quality MSI package manager resource
- xArchive:
  - Fixed a minor bug in the unit tests where sometimes the incorrect
    DateTime format was used.
- xWindowsFeatureSet:
  - Had the wrong parameter name in one test case.

## 6.1.0.0

- Moved DSC pull server setup tests to DSCPullServerSetup folder for new common
  tests.
- xArchive:
  - Updated the resource to be a high quality resource
  - Transferred the existing "unit" tests to integration tests
  - Added unit and end-to-end tests
  - Updated documentation and examples
- xUser
  - Fixed error handling in xUser
- xRegistry
  - Fixed bug where an error was thrown when running Get-DscConfiguration if
    the registry key already existed
- Updated Test-IsNanoServer cmdlet to properly test for a Nano server rather
  than the core version of PowerShell

## 6.0.0.0

- xEnvironment
  - Updated resource to follow HQRM guidelines.
  - Added examples.
  - Added unit and end-to-end tests.
  - Significantly cleaned the resource.
  - Minor Breaking Change where the resource will now throw an error if no
    value is provided, Ensure is set to present, and the variable does not
    exist, whereas before it would create an empty registry key on the
    machine in this case (if this is the desired outcome then use the
    Registry resource).
  - Added a new Write property 'Target', which specifies whether the user
    wants to set the machine variable, the process variable, or both
    (previously it was setting both in most cases).
- xGroup:
  - Group members in the "NT Authority", "BuiltIn" and "NT Service" scopes
    should now be resolved without an error. If you were seeing the errors
    "Exception calling ".ctor" with "4" argument(s): "Server names cannot
    contain a space character."" or "Exception calling ".ctor" with "2"
    argument(s): "Server names cannot contain a space character."", this fix
    should resolve those errors. If you are still seeing one of the errors,
    there is probably another local scope we need to add. Please let us know.
  - The resource will no longer attempt to resolve group members if Members,
    MembersToInclude, and MembersToExclude are not specified.

## 5.2.0.0

- xWindowsProcess
  - Minor updates to integration tests because one of the tests was flaky.
- xRegistry:
  - Added support for forward slashes in registry key names. This resolves
    issue
    [#285](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/285).

## 5.1.0.0

- xWindowsFeature:
  - Added Catch to ignore RuntimeException when importing ServerManager
    module. This resolves issue
    [#69](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/69).
  - Updated unit tests.
- xPackage:
  - No longer checks for package installation when a reboot is required. This
    resolves issue
    [#52](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/52).
  - Ensures a space is added to MSI installation arguments. This resolves
    issue
    [#195](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/195).
  - Adds RunAsCredential parameter to permit installing packages with
    specific user account. This resolves issue
    [#221](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/221).
  - Fixes null verbose log output error. This resolves issue
    [#224](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/224).
- xDSCWebService
  - Fixed issue where resource would fail to read redirection.config file.
    This resolves issue
    [#191] (https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/191)
- xArchive
  - Fixed issue where resource would throw exception when file name contains
    brackets. This resolves issue
    [#255](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/255).
- xScript
  - Cleaned resource for high quality requirements
  - Added unit tests
  - Added integration tests
  - Updated documentation and example
- ResourceSetHelper:
  - Updated common functions for all 'Set' resources.
  - Added unit tests
- xGroupSet:
  - Updated resource to use new ResouceSetHelper functions and added
    integration tests.
- xGroup:
  - Cleaned module imports, fixed PSSA issues, and set ErrorActionPreference
    to stop.
- xService:
  - Cleaned resource functions to enable StrictMode.
  - Fixed bug in which Set-TargetResource would create a service when Ensure
    set to Absent and Path specified.
  - Added unit tests.
  - Added integration tests for BuiltInAccount and Credential.
- xServiceSet:
  - Updated resource to use new ResouceSetHelper functions and added
    integration tests.
  - Updated documentation and example
- xWindowsProcess
  - Cleaned resource as per high quality guidelines.
  - Added unit tests.
  - Added integration tests.
  - Updated documentation.
  - Updated examples.
  - Fixed bug in Get-TargetResource.
  - Added a 'Count' value to the hashtable returned by Get-TargetResource so
    that the user can see how many instances of the process are running.
  - Fixed bug in finding the path to the executable.
  - Changed name to be xWindowsProcess everywhere.
- xWindowsOptionalFeatureSet
  - Updated resource to use new ResouceSetHelper functions and added
    integration tests.
  - Updated documentation and examples
- xWindowsFeatureSet
  - Updated resource to use new ResouceSetHelper functions and added
    integration tests.
  - Updated documentation and examples
- xProcessSet
  - Updated resource to use new ResouceSetHelper functions and added
    integration tests.
  - Updated documentation and examples
- xRegistry
  - Updated resource to be high-quality
  - Fixed bug in which the user could not set a Binary registry value to 0
  - Added unit and integration tests
  - Added examples and updated documentation

## 5.0.0.0

- xWindowsFeature:
  - Cleaned up resource (PSSA issues, formatting, etc.)
  - Added/Updated Tests and Examples
  - BREAKING CHANGE: Removed the unused Source parameter
  - Updated to a high quality resource
- xDSCWebService:
  - Add DatabasePath property to specify a custom database path and enable
    multiple pull server instances on one server.
  - Rename UseUpToDateSecuritySettings property to UseSecurityBestPractices.
  - Add DisableSecurityBestPractices property to specify items that are
    excepted from following best practice security settings.
- xGroup:
  - Fixed PSSA issues
  - Formatting updated as per style guidelines
  - Missing comment-based help added for Get-/Set-/Test-TargetResource
  - Typos fixed in Unit test script
  - Unit test 'Get-TargetResource/Should return hashtable with correct values
    when group has no members' updated to handle the expected empty Members
    array correctly
  - Added a lot of unit tests
  - Cleaned resource
- xUser:
  - Fixed PSSA/Style violations
  - Added/Updated Tests and Examples
- Added xWindowsPackageCab
- xService:
  - Fixed PSSA/Style violations
  - Updated Tests
  - Added 'Ignore' state

## 4.0.0.0

- xDSCWebService:
  - Added setting of enhanced security
  - Cleaned up Examples
  - Cleaned up pull server verification test
- xProcess:
  - Fixed PSSA issues
  - Corrected most style guideline issues
- xPSSessionConfiguration:
  - Fixed PSSA and style issues
  - Renamed internal functions to follow verb-noun formats
  - Decorated all functions with comment-based help
- xRegistry:
  - Fixed PSSA and style issues
  - Renamed internal functions to follow verb-noun format
  - Decorated all functions with comment-based help
  - Merged with in-box Registry
  - Fixed registry key and value removal
  - Added unit tests
- xService:
  - Added descriptions to MOF file.
  - Added additional details to parameters in Readme.md in a format that can
    be generated from the MOF.
  - Added DesktopInteract parameter.
  - Added standard help headers to *-TargetResource functions.
  - Changed indent/format of all function help headers to be consistent.
  - Fixed line length violations.
  - Changed localization code so only a single copy of localization strings
    are required.
  - Removed localization strings from inside module file.
  - Updated unit tests to use standard test enviroment configuration and
    header.
  - Recreated unit tests to be non-destructive.
  - Created integration tests.
  - Allowed service to be restarted immediately rather than wait for next LCM
    run.
  - Changed helper function names to valid verb-noun format.
  - Removed New-TestService function from
    MSFT_xServiceResource.TestHelper.psm1 because it should not be used.
  - Fixed error calling Get-TargetResource when service does not exist.
  - Fixed bug with Get-TargetResource returning StartupType 'Auto' instead of
    'Automatic'.
  - Converted to HQRM standards.
  - Removed obfuscation of exception in Get-Win32ServiceObject function.
  - Fixed bug where service start mode would be set to auto when it already
    was set to auto.
  - Fixed error message content when start mode can not be changed.
  - Removed shouldprocess from functions as not required.
  - Optimized Test-TargetResource and Set-TargetResource by removing repeated
    calls to Get-Service and Get-CimInstance.
  - Added integration test for testing changes to additional service
    properties as well as changing service binary path.
  - Modified Set-TargetResource so that newly created service created with
    minimal properties and then all additional properties updated
    (simplification of code).
  - Added support for changing Service Description and DisplayName
    parameters.
  - Fixed bug when changing binary path of existing service.
- Removed test log output from repo.
- xWindowsOptionalFeature:
  - Cleaned up resource (PSSA issues, formatting, etc.)
  - Added example script
  - Added integration test
  - BREAKING CHANGE: Removed the unused Source parameter
  - Updated to a high quality resource
- Removed test log output from repo.
- Removed the prefix MSFT_ from all files and folders of the composite
  resources in this module because they were unavailable to Get-DscResource and
  Import-DscResource.
  - xFileUpload
  - xGroupSet
  - xProcessSet
  - xServiceSet
  - xWindowsFeatureSet
  - xWindowsOptionalFeatureSet

## 3.13.0.0

- Converted appveyor.yml to install Pester from PSGallery instead of from
  Chocolatey.
- Updated appveyor.yml to use the default image.
- Merged xPackage with in-box Package resource and added tests.
- xPackage: Re-implemented parameters for installation check from registry key
  value.
- xGroup:
  - Fixed Verbose output in Get-MembersAsPrincipals function.
  - Fixed bug when credential parameter passed does not contain local or
    domain context.
  - Fixed logic bug in MembersToInclude and MembersToExclude.
  - Fixed bug when trying to include the built-in Administrator in Members.
  - Fixed bug where Test-TargetResource would check for members when none
    specified.
  - Fix bug in Test-TargetResourceOnFullSKU function when group being set to
    a single member.
  - Fix bug in Set-TargetResourceOnFullSKU function when group being set to a
    single member.
  - Fix bugs in Assert-GroupNameValid to throw correct exception.
- xService
  - Updated xService resource to allow empty string for Description
    parameter.
- Merged xProcess with in-box Process resource and added tests.
- Fixed PSSA issues in xPackageResource.

## 3.12.0.0

- Removed localization for now so that resources can run on non-English
  systems.

## 3.11.0.0

- xRemoteFile:
  - Added parameters:
    - TimeoutSec
    - Proxy
    - ProxyCredential
  - Added unit tests.
  - Corrected Style Guidelines issues.
  - Added Localization support.
  - URI parameter supports File://.
  - Get-TargetResource returns URI parameter.
  - Fixed logging of error message reported when download fails.
  - Added new example Sample_xRemoteFileUsingProxy.ps1.
- Examples: Fixed missing newline at end of PullServerSetupTests.ps1.
- xFileUpload: Added PSSA rule suppression attribute.
- xPackageResource: Removed hardcoded ComputerName 'localhost' parameter from
  Get-WMIObject to eliminate PSSA rule violation. The parameter is not
  required.
- Added .gitignore to prevent DSCResource.Tests from being commited to repo.
- Updated AppVeyor.yml to use WMF 5 build OS so that latest test methods work.
- Updated xWebService resource to not deploy Devices.mdb if esent provider is
  used
- Fixed $script:netsh parameter initialization in xWebService resource that was
  causing CIM exception when EnableFirewall flag was specified.
- xService:
  - Fixed a bug where, despite no state specified in the config, the resource
    test returns false if the service is not running
  - Fixed bug in which Automatice StartupType did not match the 'Auto'
    StartMode in Test-TargetResource.
- xPackage: Fixes bug where CreateCheckRegValue was not being removed when
  uninstalling packages
- Replaced New-NetFirewallRule cmdlets with netsh as this cmdlet is not
  available by default on some downlevel OS such as Windows 2012 R2 Core.
- Added the xEnvironment resource
- Added the xWindowsFeature resource
- Added the xScript resource
- Added the xUser resource
- Added the xGroupSet resource
- Added the xProcessSet resource
- Added the xServiceSet resource
- Added the xWindowsFeatureSet resource
- Added the xWindowsOptionalFeatureSet resource
- Merged the in-box Service resource with xService and added tests for xService
- Merged the in-box Archive resource with xArchive and added tests for xArchive
- Merged the in-box Group resource with xGroup and added tests for xGroup

## 3.10.0.0

- **Publish-ModuleToPullServer**
- **Publish-MOFToPullServer**

## 3.9.0.0

- Added more information how to use Publish-DSCModuleAndMof cmdlet and samples
- Removed compliance server samples

## 3.8.0.0

- Added Pester tests to validate pullserver deployement.
- Removed Compliance Server deployment from xWebservice resource. Fixed
  database provider selection issue depending on OS flavor
- Added Publish-DSCModuleAndMof cmdlet to package DSC modules and mof and
  publish them on DSC enterprise pull server
- xRemoteFile resource: Added size verification in cache

## 3.7.0.0

- xService:
  - Fixed a bug where 'Dependencies' property was not picked up and caused
    exception when set.
- xWindowsOptionalFeature:
  - Fixed bug where Test-TargetResource method always failed.
  - Added support for Windows Server 2012 (and later) SKUs.
- Added xRegistry resource

## 3.6.0.0

- Added CreateCheckRegValue parameter to xPackage resource
- Added MatchSource parameter to xRemoteFile resource

## 3.5.0.0

- MSFT_xPackageResource: Added ValidateSet to Get/Set/Test-TargetResource to
  match MSFT_xPackageResource.schema.mof
- Fixed bug causing xService to throw error when service already exists
- Added StartupTimeout to xService resource
- Removed UTF8 BOM
- Added code for pull server removal

## 3.4.0.0

- Added logging inner exception messages in xArchive and xPackage resources
- Fixed hash calculation in Get-CacheEntry
- Fixed issue with PSDSCComplianceServer returning HTTP Error 401.2

## 3.3.0.0

- Add support to xPackage resource for checking different registry hives
- Added support for new registration properties in xDscWebService resource

## 3.2.0.0

- xArchive:
  - Fix problems with file names containing square brackets.
- xDSCWebService:
  - Fix default culture issue.
- xPackage:
  - Security enhancements.

## 3.0.3.4

- Multiple issues addressed
  - Corrected output type for Set- and Test-TargetResource functions in
    xWebSite, xPackage, xArchive, xGroup, xProcess, xService
  - xRemoteFile modified to support creating a directory that does not exist
    when specified, ensuring idempotency. Also improved error messages.
  - xDSCWebService updated so that Get-TargetResource returns the OData
    Endpoint URL correctly.
  - In xWindowsOptionalFeature, fixed Test-TargetResource issue requiring
    Ensure = True. Note: this change requires the previous Ensure values of
    Enable and Disable to change to Present and Absent

## 3.0.2.0

- Adding following resources:
  - xGroup

## 3.0.1.0

- Adding following resources:
  - xFileUpload

## 2.0.0.0

- Adding following resources:
  - xWindowsProcess
  - xService
  - xRemoteFile
  - xPackage

## 1.1.0.0

- Fix to remove and recreate the SSL bindings when performing a new HTTPS IIS
  Endpoint setup.
- Fix in the resource module to consume WebSite Name parameter correctly

## 1.0.0.0

- Initial release with the following resources:
  - DscWebService
