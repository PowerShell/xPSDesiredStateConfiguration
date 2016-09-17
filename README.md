[![Build status](https://ci.appveyor.com/api/projects/status/s35s7sxuyym8yu6c/branch/master?svg=true)](https://ci.appveyor.com/project/PowerShell/xpsdesiredstateconfiguration/branch/master)

# xPSDesiredStateConfiguration

The **xPSDesiredStateConfiguration** module is a more recent, experimental version of the PSDesiredStateConfiguration module that ships in Windows as part of PowerShell 4.0.
The module contains the **xDscWebService**, **xWindowsProcess**, **xService**, **xPackage**, **xRemoteFile**, **xWindowsOptionalFeature** and **xGroup** DSC resources, as well as the **xFileUpload** composite DSC resource.

**This module is currently in the process of becoming one of our first experimental High Quality Resource Modules (HQRMs). The plan for updating this module is available [here](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/HighQualityResourceModulePlan.md). Any comments or questions about this process/plan can be submitted under issue [#160](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/160).**

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Contributing
Please check out common DSC Resources [contributing guidelines](https://github.com/PowerShell/DscResource.Kit/blob/master/CONTRIBUTING.md).


## Resources

* **xArchive** provides a mechanism to unpack archive (.zip) files or removed unpacked archive (.zip) files at a specific path.
* **xDscWebService** configures an OData endpoint for DSC service to make a node a DSC pull server.
* **xWindowsProcess** configures and manages Windows processes.
* **xService** configures and manages Windows services.
* **xRemoteFile** ensures the presence of remote files on a local machine.
* **xPackage** manages the installation of .msi and .exe packages.
* **xGroup** provides a mechanism to manage local groups on the target node.
* **xFileUpload** is a composite resource which ensures that local files exist on an SMB share.
* **xWindowsOptionalFeature** configures optional Windows features.
* **xRegistry** provides a mechanism to manage registry keys and values on a target node.
* **xEnvironment** configures and manages environment variables.
* **xWindowsFeature** provides a mechanism to ensure that roles and features are added or removed on a target node.
* **xScript** provides a mechanism to run Windows PowerShell script blocks on target nodes.
* **xGroupSet** configures multiple xGroups with common settings but different names.
* **xProcessSet** allows starting and stopping of a group of windows processes with no arguments.
* **xServiceSet** allows starting, stopping and change in state or account type for a group of services.
* **xWindowsFeatureSet** allows installation and uninstallation of a group of Windows features and their subfeatures.
* **xWindowsOptionalFeatureSet** allows installation and uninstallation of a group of optional Windows features.

### xArchive

* **Destination**: (Key) Specifies the location where you want to ensure the archive contents are extracted.
* **Path**: (Key) Specifies the source path of the archive file.
* **Ensure**: Determines whether to check if the content of the archive exists at the Destination. Set this property to Present to ensure the contents exist. Set it to Absent to ensure they do not exist.
   - Supported values: Present, Absent
   - Default Value: Present
* **Validate**: Uses the Checksum property to determine if the archive matches the signature. If Validate is false, only the file or directory name is used for comparison. If you specify Checksum without Validate, the configuration will fail. If you specify Validate without Checksum, a SHA-256 checksum is used by default.
   - Supported values: true, false
   - Default Value: false
* **Checksum**: Defines the type to use when determining whether two files are the same. If you specify Checksum without Validate, the configuration will fail.
   - Suported values: CreatedDate, ModifiedDate, SHA-1, SHA-256, SHA-512
   - Default value: SHA-256
* **Force**: Setting Force to true with override certain file operations (such as overwriting a file or deleting a directory that is not empty) that would normally result in an error.
   - Supported values: true, false
   - Default Value: false

### xDscWebService

* **EndpointName**: The desired web service name.
* **CertificateThumbPrint**: Certificate thumbprint for creating an HTTPS endpoint. Use "AllowUnencryptedTraffic" for setting up a non SSL based endpoint.
* **Port**: Port for web service.
* **PhysicalPath**: Folder location where the content of the web service resides.
* **Ensure**: Ensures that the web service is **Present** or **Absent**
* **State**: State of the web service: { Started | Stopped }
* **ModulePath**: Folder location where DSC resources are stored.
* **ConfigurationPath**: Folder location where DSC configurations are stored.
* **RegistrationKeyPath**: Folder location where DSC pull server registration key file is stored.
* **AcceptSelfSignedCertificate**: Whether self signed certificate can be used to setup pull server.
* **UseUpToDateSecuritySettings**: Whether to use enhanced security settings for the node where pull server resides on.

### xWindowsProcess

For a complete list of properties, please use Get-DscResource

* **Path**: The full path or the process executable
* **Arguments**: This is a mandatory parameter for passing arguments to the process executable.
Specify an empty string if you don't want to pass any arguments.
* **Credential**: The credentials of the user under whose context you want to run the process.
* **Ensure**: Ensures that the process is running or stopped: { Present | Absent }

### xService

For a complete list of properties, please use Get-DscResource

* **[String] Name** _(Key)_: Indicates the service name. Note that sometimes this is different from the display name. You can get a list of the services and their current state with the Get-Service cmdlet.
* **[String] Ensure** _(Write)_: Ensures that the service is present or absent. Defaults to Present. { *Present* | Absent }.
* **[String] Path** _(Write)_: The path to the service executable file.
* **[String] StartupType** _(Write)_: Indicates the startup type for the service. { Automatic | Disabled | Manual }.
* **[String] BuiltInAccount** _(Write)_: Indicates the sign-in account to use for the service. { LocalService | LocalSystem | NetworkService }.
* **[PSCredential] Credential** _(Write)_: The credential to run the service under.
* **[Boolean] DesktopInteract** _(Write)_: The service can create or communicate with a window on the desktop. Must be false for services not running as LocalSystem. Defaults to False.
* **[String] State** _(Write)_: Indicates the state you want to ensure for the service. Defaults to Running. { *Running* | Stopped }.
* **[String] DisplayName** _(Write)_: The display name of the service.
* **[String] Description** _(Write)_: The description of the service.
* **[String[]] Dependencies** _(Write)_: An array of strings indicating the names of the dependencies of the service.
* **[Uint32] StartupTimeout** _(Write)_: The time to wait for the service to start in milliseconds. Defaults to 30000.
* **[Uint32] TerminateTimeout** _(Write)_: The time to wait for the service to stop in milliseconds. Defaults to 30000.
* **[String] Status** _(Read)_: The current status of the service.

### xRemoteFile

* **DestinationPath**: Path where the remote file should be downloaded. Required.
* **Uri**: URI of the file which should be downloaded. It must be a HTTP, HTTPS or FILE resource. Required.
* **UserAgent**: User agent for the web request. Optional.
* **Headers**: Headers of the web request. Optional.
* **Credential**: Specifies credential of a user which has permissions to send the request. Optional.
* **MatchSource**: Determines whether the remote file should be re-downloaded if file in the DestinationPath was modified locally. Optional.
* **TimeoutSec**: Specifies how long the request can be pending before it times out. Optional.
* **Proxy**: Uses a proxy server for the request, rather than connecting directly to the Internet resource. Should be the URI of a network proxy server (e.g 'http://10.20.30.1'). Optional.
* **ProxyCredential**: Specifies a user account that has permission to use the proxy server that is specified by the Proxy parameter. Optional.
* **Ensure**: Says whether DestinationPath exists on the machine. It's a read only property.

### xPackage

* **Ensure**: Ensures that the package is **Present** or **Absent**.
* **Name**: The name of the package.
* **Path**: The source path of the package.
* **ProductId**: The product ID of the package (usually a GUID).
* **Arguments**: Command line arguments passed on the installation command line.
* **Credential**: PSCredential needed to access Path.
* **ReturnCode**: An array of return codes that are returned after a successful installation.
* **LogPath**: The destination path of the log.
* **FileHash**: The hash that should match the hash of the package file.
* **HashAlgorithm**: The algorithm to use to get the hash of the package file.
    - Supported values: SHA1, SHA256, SHA384, SHA512, MD5, RIPEMD160
* **SignerSubject**: The certificate subject that should match that of the package file's signing certificate.
* **SignerThumbprint**: The certificate thumbprint that should match that of the package file's signing certificate.
* **ServerCertificateValidationCallback**: A callback function to validate the server certificate.

Read-Only Properties:
* **PackageDescription**: A text description of the package being installed.
* **Publisher**: Publisher's name.
* **InstalledOn**: Date of installation.
* **Size**: Size of the installation.
* **Version**: Version of the package.
* **Installed**: Is the package installed?

### xGroup

* **GroupName**: (Key) The name of the group for which you want to ensure a specific state.
* **Ensure**: Indicates if the group exists. Set this property to "Absent" to ensure that the group does not exist. Setting it to "Present" (the default value) ensures that the group exists.
   - Supported values: Present, Absent
   - Default Value: Present
* **Description**: The description of the group.
* **Members**: Use this property to replace the current group membership with the specified members. The value of this property is an array of strings of the form Domain\UserName. If you set this property in a configuration, do not use either the MembersToExclude or MembersToInclude property. Doing so will generate an error. Note: If the group already exists, the listed items in this property replaces what is in the group.
* **MembersToInclude**: Use this property to add members to the existing membership of the group. The value of this property is an array of strings of the form Domain\UserName. If you set this property in a configuration, do not use the Members property. Doing so will generate an error. Note: This property is ignored if 'Members' is specified.
* **MembersToExclude**: Use this property to remove members from the existing membership of the group. The value of this property is an array of strings of the form Domain\UserName. If you set this property in a configuration, do not use the Members property. Doing so will generate an error. Note: This property is ignored if 'Members' is specified.
* **Credential**: The credentials required to access remote resources. Note: This account must have the appropriate Active Directory permissions to add all non-local accounts to the group; otherwise, an error will occur.

Local accounts may be specified in one of the following ways:

* The simple name of the account of the group or local user.
* The account name scoped to the explicit machine name (eg. myserver\users or myserver\username).
* The account name scoped using the explicit local machine qualifier (eg. .\users or .\username).

Domain members may be specified using domain\name or User Principal Name (UPN) formatting. The following illustrates the various formats

* Domain joined machines: mydomain\myserver or myserver@mydomain.com
* Domain user accounts: mydomain\username or username@mydomain.com
* Domain group accounts: mydomain\groupname or groupname@mydomain.com

### xFileUpload

* **DestinationPath**: Path where the local file should be uploaded.
* **SourcePath**: Path to the local file which should be uploaded.
* **Credential**: PSCredential for the user with access to DestinationPath.
* **CertificateThumbprint**: Thumbprint of the certificate which should be used for encryption/decryption.

### xRegistry

xRegistry provides a mechanism to manage registry keys and values on a target node.

* **[String] Key** _(Key)_: Indicates the path of the registry key for which you want to ensure a specific state. This path must include the hive.
* **[String] ValueName** _(Key)_: Indicates the name of the registry value.
* **[String] Ensure** _(Write)_: Indicates if the key and value exist. To ensure that they do, set this property to "Present". To ensure that they do not exist, set the property to "Absent". The default value is "Present". { *Present* | Absent }.
* **[String] ValueData** _(Write)_: The data for the registry value.
* **[String] ValueType** _(Write)_: Indicates the type of the value. { String | Binary | DWord | QWord | MultiString | ExpandString }
* **[Boolean] Hex** _(Write)_: Indicates if data will be expressed in hexadecimal format. If specified, the DWORD/QWORD value data is presented in hexadecimal format. Not valid for other types. The default value is $false.
* **[Boolean] Force** _(Write)_: If the specified registry key is present, Force overwrites it with the new value.

### xWindowsOptionalFeature
Note: _the xWindowsOptionalFeature is only supported on Windows client or Windows Server 2012 (and later) SKUs._

* **Name**: Name of the optional Windows feature.
* **Source**: Specifies the location of the files that are required to restore a feature that has been removed from the image.
   - You can specify the Windows directory of a mounted image or a running Windows installation that is shared on the network.
   - If you specify multiple Source arguments, the files are gathered from the first location where they are found and the rest of the locations are ignored.
* **RemoveFilesOnDisable**: Removes the files for an optional feature without removing the feature's manifest from the image.
   - Suported values: $true, $false.
   - Default value: $false.
* **LogPath**: Specifies the full path and file name to log to.
   - If not set, the default is %WINDIR%\Logs\Dism\dism.log.
* **Ensure**: Ensures that the feature is present or absent.
   - Supported values: Present, Absent.
   - Default Value: Present.
* **NoWindowsUpdateCheck**: Prevents DISM from contacting Windows Update (WU) when searching for the source files to restore a feature on an online image.
   - Suported values: $true, $false.
   - Default value: $false.
* **LogLevel**: Specifies the maximum output level shown in the logs.
   - Suported values: ErrorsOnly, ErrorsAndWarning, ErrorsAndWarningAndInformation.
   - Default value: ErrorsOnly.

### xEnvironment

* **Name**: Indicates the name of the environment variable for which you want to ensure a specific state.
* **Value**: The value to assign to the environment variable.
   - Supported values: Non-null strings
   - Default Value: [String]::Empty
* **Ensure**: Ensures that the feature is present or absent.
   - Supported values: Present, Absent.
   - Default Value: Present.
* **Path**: Defines the environment variable that is being configured. Set this property to $true if the variable is the Path variable; otherwise, set it to $false. If the variable being configured is the Path variable, the value provided through the Value property will be appended to the existing value.
   - Suported values: $true, $false.
   - Default value: $false.

### xWindowsFeature
* **Name**: Indicates the name of the role or feature that you want to ensure is added or removed. This is the same as the Name property from the Get-WindowsFeature cmdlet, and not the display name of the role or feature.
* **Credential**: Indicates the credentials to use to add or remove the role or feature.
* **Ensure**: Ensures that the feature is present or absent.
   - Supported values: Present, Absent.
   - Default Value: Present.
* **IncludeAllSubFeature**: Set this property to $true to ensure the state of all required subfeatures with the state of the feature you specify with the Name property.
   - Suported values: $true, $false.
   - Default value: $false.
* **LogPath**: Indicates the path to a log file where you want the resource provider to log the operation.
* **Source**: Indicates the location of the source file to use for installation, if necessary.

### xScript
* **GetScript**: Provides a block of Windows PowerShell script that runs when you invoke the Get-DscConfiguration cmdlet. This block must return a hash table.
* **SetScript**: Provides a block of Windows PowerShell script. When you invoke the Start-DscConfiguration cmdlet, the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run. If the TestScript block returns $true, the SetScript block will not run.
* **TestScript**: Provides a block of Windows PowerShell script. When you invoke the Start-DscConfiguration cmdlet, this block runs. If it returns $false, the SetScript block will run. If it returns $true, the SetScript block will not run. The TestScript block also runs when you invoke the Test-DscConfiguration cmdlet. However, in this case, the SetScript block will not run, no matter what value the TestScript block returns. The TestScript block must return True if the actual configuration matches the current desired state configuration, and False if it does not match. (The current desired state configuration is the last configuration enacted on the node that is using DSC.)
* **Credential**: Indicates the credentials to use for running this script, if credentials are required.

### xUser
* **UserName**: Indicates the account name for which you want to ensure a specific state.
* **Description**: Indicates the description you want to use for the user account.
* **Disabled**: Indicates if the account is enabled. Set this property to $true to ensure that this account is disabled, and set it to $false to ensure that it is enabled.
   - Suported values: $true, $false
   - Default value: $false
* **Ensure**: Ensures that the feature is present or absent.
   - Supported values: Present, Absent
   - Default Value: Present
* **FullName**: Represents a string with the full name you want to use for the user account.
* **Password**: Indicates the password you want to use for this account.
* **PasswordChangeNotAllowed**: Indicates if the user can change the password. Set this property to $true to ensure that the user cannot change the password, and set it to $false to allow the user to change the password.
   - Suported values: $true, $false
   - Default value: $false
* **PasswordChangeRequired**: Indicates if the user must change the password at the next sign in. Set this property to $true if the user must change the password.
   - Suported values: $true, $false
   - Default value: $true
* **PasswordNeverExpires**: Indicates if the password will expire. To ensure that the password for this account will never expire, set this property to $true, and set it to $false if the password will expire.
   - Suported values: $true, $false
   - Default value: $false

### xGroupSet
* **GroupName**: Defines the names of the groups in the set.

These parameters will be the same for each group in the set. Please refer to the xGroup section above for more details on these parameters:
* **Ensure**: Ensures that the group specified is **Present** or **Absent**.
* **Description**: Description of the group.
* **Members**: The members that form the group.
Note: If the group already exists, the listed items in this property replaces what is in the group.
* **MembersToInclude**: List of users to add to the group.
Note: This property is ignored if 'Members' is specified.
* **MembersToExclude**: List of users you want to ensure are not members of the group.
Note: This property is ignored if 'Members' is specified.
* **Credential**: Indicates the credentials required to access remote resources.
Note: This account must have the appropriate Active Directory permissions to add all non-local accounts to the group or an error will occur.

### xProcessSet
Note: All processes in a process set will run without arguments.

* **Path**: Defines the path to each process in the set.

These parameters will be the same for each process in the set. Please refer to the xWindowsProcess section above for more details on these parameters:
* **Credential**: The credentials of the user under whose context you want to run the process.
* **Ensure**: Ensures that the process is running or stopped.
   - Supported values: Present, Absent
   - Default Value: Present
* **StandardOutputPath**: The path to write the standard output stream to.
* **StandardErrorPath**: The path to write the standard error stream to.
* **StandardInputPath**: The path to receive standard input from.
* **WorkingDirectory**: The directory to run the processes under.

### xServiceSet
Note: xServiceSet should not be used to create services. Please use xService instead.

* **Name**: Defines the names of the services in the set.

These parameters will be the same for each service in the set. Please refer to the xService section above for more details on these parameters:
* **StartupType**: Indicates the startup type for the service.
   - Suported values: Automatic, Disabled, and Manual
* **BuiltInAccount**: Indicates the sign-in account to use for the service.
   - Suported values: LocalService, LocalSystem, and NetworkService
* **State**: Indicates the state you want to ensure for the service.
   - Suported values: Running, Stopped
   - Default value: Running
* **Ensure**: Ensures that the group specified is **Present** or **Absent**.
   - Suported values: Present, Absent
   - Default value: Present
* **Credential**: Indicates credentials for the account that the service will run under. This property and the BuiltinAccount property cannot be used together.

### xWindowsFeatureSet
* **Name**: Defines the names of the Windows features in the set.

These parameters will be the same for each Windows feature in the set. Please refer to the xWindowsFeature section above for more details on these parameters:
* **Ensure**: Ensures that the set of features is present or absent.
   - Supported values: Present, Absent.
   - Default Value: Present.
* **Credential**: Indicates the credentials to use to add or remove the role or feature.
* **IncludeAllSubFeature**: Set this property to $true to ensure the state of all required subfeatures matches the state of the Ensure property.
   - Suported values: $true, $false.
   - Default value: $false.
* **LogPath**: Indicates the path to a log file where you want the resource provider to log the operation.
* **Source**: Indicates the location of the source file to use for installation, if necessary.

### xWindowsOptionalFeatureSet
Note: xWindowsOptionalFeature is only supported on Windows client or Windows Server 2012 (and later) SKUs.

* **Name**: Defines the names of the Windows optional features in the set.

These parameters will be the same for each Windows optional feature in the set. Please refer to the xWindowsOptionalFeature section above for more details on these parameters:
* **Ensure**: Ensures that the set of features is present or absent.
   - Supported values: Present, Absent.
   - Default Value: Present.
* **Source**: Specifies the location of the files that are required to restore a feature that has been removed from the image.
   - You can specify the Windows directory of a mounted image or a running Windows installation that is shared on the network.
   - If you specify multiple Source arguments, the files are gathered from the first location where they are found and the rest of the locations are ignored.
* **RemoveFilesOnDisable**: Removes the files for an optional feature without removing the feature's manifest from the image.
   - Suported values: $true, $false.
   - Default value: $false.
* **LogPath**: Specifies the full path and file name to log to.
   - If not set, the default is %WINDIR%\Logs\Dism\dism.log.
* **NoWindowsUpdateCheck**: Prevents DISM from contacting Windows Update (WU) when searching for the source files to restore a feature on an online image.
   - Suported values: $true, $false.
   - Default value: $false.
* **LogLevel**: Specifies the maximum output level shown in the logs.
   - Suported values: ErrorsOnly, ErrorsAndWarning, ErrorsAndWarningAndInformation.
   - Default value: ErrorsOnly.

## Functions

### Publish-ModuleToPullServer
    Publishes a 'ModuleInfo' object(s) to the pullserver module repository or user provided path. It accepts its input from a pipeline so it can be used in conjunction with Get-Module as Get-Module <ModuleName> | Publish-Module

### Publish-MOFToPullServer
    Publishes a 'FileInfo' object(s) to the pullserver configuration repository. Its accepts FileInfo input from a pipeline so it can be used in conjunction with Get-ChildItem .*.mof | Publish-MOFToPullServer

## Versions

### Unreleased

* xGroup:
    * Fixed PSSA issues
    * Formatting updated as per style guidelines
    * Missing comment-based help added for Get-/Set-/Test-TargetResource
    * Typos fixed in Unit test script
    * Unit test 'Get-TargetResource/Should return hashtable with correct values when group 
    has no members' updated to handle the expected empty Members array correctly
* xProcess:
    * Fixed PSSA issues
    * Corrected most style guideline issues
* xRegistry:
    * Fixed PSSA and style issues
    * Renamed internal functions to follow verb-noun format
    * Decorated all functions with comment-based help
    * Merged with in-box Registry
    * Fixed registry key and value removal
    * Added unit tests
* xPSSessionConfiguration:
    * Fixed PSSA and style issues
    * Renamed internal functions to follow verb-noun formats
    * Decorated all functions with comment-based help
* xWindowsOptionalFeature:
    * Cleaned up resource (PSSA issues, formatting, etc.)
    * Added example script
    * Added integration test
* xService:
    * Added descriptions to MOF file.
    * Added additional details to parameters in Readme.md in a format that can be generated from the MOF.
    * Added DesktopInteract parameter.
    * Added standard help headers to *-TargetResource functions.
    * Changed indent/format of all function help headers to be consistent.
    * Fixed line length violations.
    * Changed localization code so only a single copy of localization strings are required.
    * Removed localization strings from inside module file.
    * Updated unit tests to use standard test enviroment configuration and header.
    * Recreated unit tests to be non-destructive.
    * Created integration tests.
    * Allowed service to be restarted immediately rather than wait for next LCM run.
    * Changed helper function names to valid verb-noun format.
    * Removed New-TestService function from MSFT_xServiceResource.TestHelper.psm1 because it should not be used.
    * Fixed error calling Get-TargetResource when service does not exist.
    * Fixed bug with Get-TargetResource returning StartupType 'Auto' instead of 'Automatic'.
    * Converted to HQRM standards.
    * Removed obfuscation of exception in Get-Win32ServiceObject function.
    * Fixed bug where service start mode would be set to auto when it already was set to auto.
    * Fixed error message content when start mode can not be changed.
    * Removed shouldprocess from functions as not required.
    * Optimized Test-TargetResource and Set-TargetResource by removing repeated calls to Get-Service and Get-CimInstance.
* Removed test log output from repo.
* xDSCWebService:
    * Added setting of enhanced security
    * Cleaned up Examples
    * Cleaned up pull server verification test 

### 3.13.0.0

* Converted appveyor.yml to install Pester from PSGallery instead of from Chocolatey.
* Updated appveyor.yml to use the default image.
* Merged xPackage with in-box Package resource and added tests.
* xPackage: Re-implemented parameters for installation check from registry key value.
* xGroup:
    * Fixed Verbose output in Get-MembersAsPrincipals function.
    * Fixed bug when credential parameter passed does not contain local or domain context.
    * Fixed logic bug in MembersToInclude and MembersToExclude.
    * Fixed bug when trying to include the built-in Administrator in Members.
    * Fixed bug where Test-TargetResource would check for members when none specified.
    * Fix bug in Test-TargetResourceOnFullSKU function when group being set to a single member.
    * Fix bug in Set-TargetResourceOnFullSKU function when group being set to a single member.
    * Fix bugs in Assert-GroupNameValid to throw correct exception.
* xService
    * Updated xService resource to allow empty string for Description parameter.
* Merged xProcess with in-box Process resource and added tests.
* Fixed PSSA issues in xPackageResource.

### 3.12.0.0

* Removed localization for now so that resources can run on non-English systems.

### 3.11.0.0

* xRemoteFile: Added parameters:
                - TimeoutSec
                - Proxy
                - ProxyCredential
               Added unit tests.
               Corrected Style Guidelines issues.
               Added Localization support.
               URI parameter supports File://.
               Get-TargetResource returns URI parameter.
               Fixed logging of error message reported when download fails.
               Added new example Sample_xRemoteFileUsingProxy.ps1.
* Examples: Fixed missing newline at end of PullServerSetupTests.ps1.
* xFileUpload: Added PSSA rule suppression attribute.
* xPackageResource: Removed hardcoded ComputerName 'localhost' parameter from Get-WMIObject to eliminate PSSA rule violation. The parameter is not required.
* Added .gitignore to prevent DSCResource.Tests from being commited to repo.
* Updated AppVeyor.yml to use WMF 5 build OS so that latest test methods work.
* Updated xWebService resource to not deploy Devices.mdb if esent provider is used
* Fixed $script:netsh parameter initialization in xWebService resource that was causing CIM exception when EnableFirewall flag was specified.
* xService:
    - Fixed a bug where, despite no state specified in the config, the resource test returns false if the service is not running
    - Fixed bug in which Automatice StartupType did not match the 'Auto' StartMode in Test-TargetResource.
* xPackage: Fixes bug where CreateCheckRegValue was not being removed when uninstalling packages
* Replaced New-NetFirewallRule cmdlets with netsh as this cmdlet is not available by default on some downlevel OS such as Windows 2012 R2 Core.
* Added the xEnvironment resource
* Added the xWindowsFeature resource
* Added the xScript resource
* Added the xUser resource
* Added the xGroupSet resource
* Added the xProcessSet resource
* Added the xServiceSet resource
* Added the xWindowsFeatureSet resource
* Added the xWindowsOptionalFeatureSet resource
* Merged the in-box Service resource with xService and added tests for xService
* Merged the in-box Archive resource with xArchive and added tests for xArchive
* Merged the in-box Group resource with xGroup and added tests for xGroup

### 3.10.0.0

* **Publish-ModuleToPullServer**
* **Publish-MOFToPullServer**

### 3.9.0.0

* Added more information how to use Publish-DSCModuleAndMof cmdlet and samples
* Removed compliance server samples

### 3.8.0.0

* Added Pester tests to validate pullserver deployement.
* Removed Compliance Server deployment from xWebservice resource. Fixed database provider selection issue depending on OS flavor
* Added Publish-DSCModuleAndMof cmdlet to package DSC modules and mof and publish them on DSC enterprise pull server
* xRemoteFile resource: Added size verification in cache

### 3.7.0.0

* xService:
    - Fixed a bug where 'Dependencies' property was not picked up and caused exception when set.
* xWindowsOptionalFeature:
    - Fixed bug where Test-TargetResource method always failed.
    - Added support for Windows Server 2012 (and later) SKUs.
* Added xRegistry resource

### 3.6.0.0
* Added CreateCheckRegValue parameter to xPackage resource
* Added MatchSource parameter to xRemoteFile resource

### 3.5.0.0

* MSFT_xPackageResource: Added ValidateSet to Get/Set/Test-TargetResource to match MSFT_xPackageResource.schema.mof
* Fixed bug causing xService to throw error when service already exists
* Added StartupTimeout to xService resource
* Removed UTF8 BOM
* Added code for pull server removal

### 3.4.0.0

* Added logging inner exception messages in xArchive and xPackage resources
* Fixed hash calculation in Get-CacheEntry
* Fixed issue with PSDSCComplianceServer returning HTTP Error 401.2


### 3.3.0.0

* Add support to xPackage resource for checking different registry hives
* Added support for new registration properties in xDscWebService resource

### 3.2.0.0

* xArchive:
    - Fix problems with file names containing square brackets.
* xDSCWebService:
    - Fix default culture issue.
* xPackage:
    - Security enhancements.

### 3.0.3.4

* Multiple issues addressed
    - Corrected output type for Set- and Test-TargetResource functions in xWebSite, xPackage, xArchive, xGroup, xProcess, xService
    - xRemoteFile modified to support creating a directory that does not exist when specified, ensuring idempotency.
    Also improved error messages.
    - xDSCWebService updated so that Get-TargetResource returns the OData Endpoint URL correctly.
    - In xWindowsOptionalFeature, fixed Test-TargetResource issue requiring Ensure = True.
        + Note: this change requires the previous Ensure values of Enable and Disable to change to Present and Absent

### 3.0.2.0

* Adding following resources:
    * xGroup

### 3.0.1.0

* Adding following resources:
    * xFileUpload

### 2.0.0.0

* Adding following resources:
    * xWindowsProcess
    * xService
    * xRemoteFile
    * xPackage

### 1.1.0.0

* Fix to remove and recreate the SSL bindings when performing a new HTTPS IIS Endpoint setup.
* Fix in the resource module to consume WebSite Name parameter correctly

### 1.0.0.0

* Initial release with the following resources:
    * DscWebService

## Examples
### Change the name and the workgroup name

This configuration will set a machine name and change its workgroup.

### Switch from a workgroup to a domain

This configuration sets the machine name and joins a domain.
Note: this requires a credential.

### Change the name while staying on the domain

This example will change the machines name while remaining on the domain.
Note: this requires a credential.

### Change the name while staying on the workgroup

This example will change a machine's name while remaining on the workgroup.

### Switch from a domain to a workgroup

This example switches the computer from a domain to a workgroup.
Note: this requires a credential.

### Download file from URI, specifying headers and user agent

This configuration will download a file from a specific URI to DestinationPath.
The web request will contain specific headers and will be sent using a specified user agent.

### Upload file to an SMB share

This configuration will upload a file from SourcePath to the remote DestinationPath.
Username and password will be used to access the DestinationPath.

### Sample1.ps1 installs a package that uses an .exe file

This configuration will install a .exe package, verifying the package using the package name.

### Sample1.ps2 installs a package that uses an .exe file

This configuration will install a .exe package and verify the package using the product ID and package name.

### Sample1.ps3 installs a package that uses an .msi file.

This configuration will install a .msi package and verify the package using the product ID and package name and requires credentials to read the share and install the package.

### Sample1.ps4 installs a package that uses an .exe file

This configuration will install a .exe package and verify the package using the product ID and package name and requires credentials to read the share and install the package. It also uses custom registry values to check for the package presence.

### Validate pullserver deployement.
If Sample_xDscWebService.ps1 is used to setup a DSC pull and reporting endpoint, the service endpoint can be validated by performing Invoke-WebRequest -URI http://localhost:8080/PSDSCPullServer.svc/$metadata in Powershll or http://localhost:8080/PSDSCPullServer.svc/ when using InternetExplorer.

[Pullserver Validation Pester Tests](Examples/PullServerDeploymentVerificationTest)
