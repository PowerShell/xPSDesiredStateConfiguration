# xPSDesiredStateConfiguration

The **xPSDesiredStateConfiguration** module is a more recent, experimental version of the PSDesiredStateConfiguration module that ships in Windows as part of PowerShell 4.0.

The high quality, supported version of this module is available as [PSDscResources](https://github.com/PowerShell/PSDscResources).

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Branches

### master

[![Build status](https://ci.appveyor.com/api/projects/status/s35s7sxuyym8yu6c/branch/master?svg=true)](https://ci.appveyor.com/project/PowerShell/xPSDesiredStateConfiguration/branch/master)
[![codecov](https://codecov.io/gh/PowerShell/xPSDesiredStateConfiguration/branch/master/graph/badge.svg)](https://codecov.io/gh/PowerShell/xPSDesiredStateConfiguration/branch/master)

This is the branch containing the latest release -
no contributions should be made directly to this branch.

### dev

[![Build status](https://ci.appveyor.com/api/projects/status/s35s7sxuyym8yu6c/branch/dev?svg=true)](https://ci.appveyor.com/project/PowerShell/xPSDesiredStateConfiguration/branch/dev)
[![codecov](https://codecov.io/gh/PowerShell/xPSDesiredStateConfiguration/branch/dev/graph/badge.svg)](https://codecov.io/gh/PowerShell/xPSDesiredStateConfiguration/branch/dev)

This is the development branch
to which contributions should be proposed by contributors as pull requests.
This development branch will periodically be merged to the master branch,
and be released to [PowerShell Gallery](https://www.powershellgallery.com/).

## Contributing

If you would like to contribute to this module, please review the common DSC Resources [contributing guidelines](https://github.com/PowerShell/DscResource.Kit/blob/master/CONTRIBUTING.md).

## Resources

* **xArchive** provides a mechanism to expand an archive (.zip) file to a specific path or remove an expanded archive (.zip) file from a specific path on a target node.
* **xDscWebService** configures an OData endpoint for DSC service to make a node a DSC pull server.
* **xEnvironment** provides a mechanism to configure and manage environment variables for a machine or process.
* **xFileUpload** is a composite resource which ensures that local files exist on an SMB share.
* **xGroup** provides a mechanism to manage local groups on a target node.
* **xGroupSet** provides a mechanism to configure and manage multiple xGroup resources with common settings but different names.
* **xMsiPackage** provides a mechanism to install and uninstall .msi packages.
* **xPackage** manages the installation of .msi and .exe packages.
* **xRegistry** provides a mechanism to manage registry keys and values on a target node.
* **xRemoteFile** ensures the presence of remote files on a local machine.
* **xScript** provides a mechanism to run PowerShell script blocks on a target node.
* **xService** provides a mechanism to configure and manage Windows services.
* **xServiceSet** provides a mechanism to configure and manage multiple xService resources with common settings but different names.
* **xUser** provides a mechanism to manage local users on the target node.
* **xWindowsFeature** provides a mechanism to install or uninstall Windows roles or features on a target node.
* **xWindowsFeatureSet** provides a mechanism to configure and manage multiple xWindowsFeature resources on a target node.
* **xWindowsOptionalFeature** provides a mechanism to enable or disable optional features on a target node.
* **xWindowsOptionalFeatureSet** provides a mechanism to configure and manage multiple xWindowsOptionalFeature resources on a target node.
* **xWindowsPackageCab** provides a mechanism to install or uninstall a package from a Windows cabinet (cab) file on a target node.
* **xWindowsProcess** provides a mechanism to start and stop a Windows process.
* **xProcessSet** allows starting and stopping of a group of windows processes with no arguments.

Resources that work on Nano Server:

* xGroup
* xService
* xScript
* xUser
* xWindowsOptionalFeature
* xWindowsOptionalFeatureSet
* xWindowsPackageCab

### xArchive

Provides a mechanism to expand an archive (.zip) file to a specific path or remove an expanded archive (.zip) file from a specific path on a target node.

#### Requirements

* The System.IO.Compression type assembly must be available on the machine.
* The System.IO.Compression.FileSystem type assembly must be available on the machine.

#### Parameters

* **[String] Path** _(Key)_: The path to the archive file that should be expanded to or removed from the specified destination.
* **[String] Destination** _(Key)_: The path where the specified archive file should be expanded to or removed from.
* **[String] Ensure** _(Write)_: Specifies whether or not the expanded content of the archive file at the specified path should exist at the specified destination. To update the specified destination to have the expanded content of the archive file at the specified path, specify this property as Present. To remove the expanded content of the archive file at the specified path from the specified destination, specify this property as Absent. The default value is Present. { *Present* | Absent }.
* **[Boolean] Validate** _(Write)_: Specifies whether or not to validate that a file at the destination with the same name as a file in the archive actually matches that corresponding file in the archive by the specified checksum method. If the file does not match and Ensure is specified as Present and Force is not specified, the resource will throw an error that the file at the desintation cannot be overwritten. If the file does not match and Ensure is specified as Present and Force is specified, the file at the desintation will be overwritten. If the file does not match and Ensure is specified as Absent, the file at the desintation will not be removed. The default Checksum method is ModifiedDate. The default value is false.
* **[String] Checksum** _(Write)_: The Checksum method to use to validate whether or not a file at the destination with the same name as a file in the archive actually matches that corresponding file in the archive. An invalid argument exception will be thrown if Checksum is specified while Validate is specified as false. ModifiedDate will check that the LastWriteTime property of the file at the destination matches the LastWriteTime property of the file in the archive. CreatedDate will check that the CreationTime property of the file at the destination matches the CreationTime property of the file in the archive. SHA-1, SHA-256, and SHA-512 will check that the hash of the file at the destination by the specified SHA method matches the hash of the file in the archive by the specified SHA method. The default value is ModifiedDate. { *ModifiedDate* | CreatedDate | SHA-1 | SHA-256 | SHA-512 }
* **[System.Management.Automation.PSCredential] Credential** _(Write)_: The credential of a user account with permissions to access the specified archive path and destination if needed.
* **[Boolean] Force** _(Write)_: Specifies whether or not any existing files or directories at the destination with the same name as a file or directory in the archive should be overwritten to match the file or directory in the archive. When this property is false, an error will be thrown if an item at the destination needs to be overwritten. The default value is false.

#### Read-Only Properties from Get-TargetResource

None

#### Examples

* [Expand an archive without file validation](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xArchive_ExpandArchiveNoValidationConfig.ps1)
* [Expand an archive under a credential without file validation](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xArchive_ExpandArchiveNoValidationCredentialConfig.ps1)
* [Expand an archive with default file validation and file overwrite allowed](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xArchive_ExpandArchiveDefaultValidationAndForceConfig.ps1)
* [Expand an archive with SHA-256 file validation and file overwrite allowed](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xArchive_ExpandArchiveChecksumAndForceConfig.ps1)
* [Remove an archive without file validation](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xArchive_RemoveArchiveNoValidationConfig.ps1)
* [Remove an archive with SHA-256 file validation](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xArchive_RemoveArchiveChecksumConfig.ps1)

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
* **AcceptSelfSignedCertificates**: Whether self signed certificate can be used to setup pull server.
* **UseSecurityBestPractices**: Whether to use best practice security settings for the node where pull server resides on.
Caution: Setting this property to $true will reset registry values under "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL". This environment change enforces the use of stronger encryption cypher and may affect legacy applications. More information can be found at https://support.microsoft.com/en-us/kb/245030 and https://technet.microsoft.com/en-us/library/dn786418(v=ws.11).aspx.
* **DisableSecurityBestPractices**: The items that are excepted from following best practice security settings.
* **Enable32BitAppOnWin64**: When this property is set to true, Pull Server will run on a 32 bit process on a 64 bit machine.

### xGroup

Provides a mechanism to manage local groups on the target node.
This resource works on Nano Server.

#### Requirements

None

#### Parameters

* **[String] GroupName** _(Key)_: The name of the group to create, modify, or remove.
* **[String] Ensure** _(Write)_: Indicates if the group should exist or not. To add a group or modify an existing group, set this property to Present. To remove a group, set this property to Absent. The default value is Present. { *Present* | Absent }.
* **[String] Description** _(Write)_: The description the group should have.
* **[String[]] Members** _(Write)_: The members the group should have. This property will replace all the current group members with the specified members. Members should be specified as strings in the format of their domain qualified name (domain\username), their UPN (username@domainname), their distinguished name (CN=username,DC=...), or their username (for local machine accounts). Using either the MembersToExclude or MembersToInclude properties in the same configuration as this property will generate an error.
* **[String[]] MembersToInclude** _(Write)_: The members the group should include. This property will only add members to a group. Members should be specified as strings in the format of their domain qualified name (domain\username), their UPN (username@domainname), their distinguished name (CN=username,DC=...), or their username (for local machine accounts). Using the Members property in the same configuration as this property will generate an error.
* **[String[]] MembersToExclude** _(Write)_: The members the group should exclude. This property will only remove members from a group. Members should be specified as strings in the format of their domain qualified name (domain\username), their UPN (username@domainname), their distinguished name (CN=username,DC=...), or their username (for local machine accounts). Using the Members property in the same configuration as this property will generate an error.
* **[System.Management.Automation.PSCredential] Credential** _(Write)_: A credential to resolve non-local group members.

#### Read-Only Properties from Get-TargetResource

None

#### Examples

* [Remove members from a group](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xGroup_RemoveMembersConfig.ps1)
* [Set the members of a group](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xGroup_SetMembersConfig.ps1)

### xGroupSet

Provides a mechanism to configure and manage multiple xGroup resources with common settings but different names

#### Requirements

None

#### Parameters

* **[String] GroupName** _(Key)_: The names of the groups to create, modify, or remove.

The following parameters will be the same for each group in the set:

* **[String] Ensure** _(Write)_: Indicates if the groups should exist or not. To add groups or modify existing groups, set this property to Present. To remove groups, set this property to Absent. { Present | Absent }.
* **[String[]] MembersToInclude** _(Write)_: The members the groups should include. This property will only add members to groups. Members should be specified as strings in the format of their domain qualified name (domain\username), their UPN (username@domainname), their distinguished name (CN=username,DC=...), or their username (for local machine accounts).
* **[String[]] MembersToExclude** _(Write)_: The members the groups should exclude. This property will only remove members groups. Members should be specified as strings in the format of their domain qualified name (domain\username), their UPN (username@domainname), their distinguished name (CN=username,DC=...), or their username (for local machine accounts).
* **[System.Management.Automation.PSCredential] Credential** _(Write)_: A credential to resolve non-local group members.

#### Read-Only Properties from Get-TargetResource

None

#### Examples

* [Add members to multiple groups](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xGroupSet_AddMembersConfig.ps1)

### xWindowsProcess

Provides a mechanism to start and stop a Windows process.

#### Requirements

None

#### Parameters

* **[String] Path** _(Key)_: The executable file of the process. This can be defined as either the full path to the file or as the name of the file if it is accessible through the environment path. Relative paths are not supported.
* **[String] Arguments** _(Key)_: A single string containing all the arguments to pass to the process. Pass in an empty string if no arguments are needed.
* **[PSCredential] Credential** _(Write)_: The credential of the user account to run the process under. If this user is from the local system, the StandardOutputPath, StandardInputPath, and WorkingDirectory parameters cannot be provided at the same time.
* **[String] Ensure** _(Write)_: Specifies whether or not the process should be running. To start the process, specify this property as Present. To stop the process, specify this property as Absent. { *Present* | Absent }.
* **[String] StandardOutputPath** _(Write)_: The file path to which to write the standard output from the process. Any existing file at this file path will be overwritten. This property cannot be specified at the same time as Credential when running the process as a local user.
* **[String] StandardErrorPath** _(Write)_: The file path to which to write the standard error output from the process. Any existing file at this file path will be overwritten.
* **[String] StandardInputPath** _(Write)_: The file path from which to receive standard input for the process. This property cannot be specified at the same time as Credential when running the process as a local user.
* **[String] WorkingDirectory** _(Write)_: The file path to the working directory under which to run the process. This property cannot be specified at the same time as Credential when running the process as a local user.

#### Read-Only Properties from Get-TargetResource

* **[UInt64] PagedMemorySize** _(Read)_: The amount of paged memory, in bytes, allocated for the process.
* **[UInt64] NonPagedMemorySize** _(Read)_: The amount of nonpaged memory, in bytes, allocated for the process.
* **[UInt64] VirtualMemorySize** _(Read)_: The amount of virtual memory, in bytes, allocated for the process.
* **[SInt32] HandleCount** _(Read)_: The number of handles opened by the process.
* **[SInt32] ProcessId** _(Read)_: The unique identifier of the process.
* **[SInt32] ProcessCount** _(Read)_: The number of instances of the given process that are currently running.

#### Examples

* [Start a process](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsProcess_StartProcessConfig.ps1)
* [Stop a process](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsProcess_StopProcessConfig.ps1)
* [Start a process under a user](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsProcess_StartProcessUnderUserConfig.ps1)
* [Stop a process under a user](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsProcess_StopProcessUnderUserConfig.ps1)

### xProcessSet

Provides a mechanism to configure and manage multiple xWindowsProcess resources on a target node.

#### Requirements

None

#### Parameters

* **[String[]] Path** _(Key)_: The file paths to the executables of the processes to start or stop. Only the names of the files may be specified if they are all accessible through the environment path. Relative paths are not supported.

The following parameters will be the same for each process in the set:

* **[PSCredential] Credential** _(Write)_: The credential of the user account to run the processes under. If this user is from the local system, the StandardOutputPath, StandardInputPath, and WorkingDirectory parameters cannot be provided at the same time.
* **[String] Ensure** _(Write)_: Specifies whether or not the processes should be running. To start the processes, specify this property as Present. To stop the processes, specify this property as Absent. { Present | Absent }.
* **[String] StandardOutputPath** _(Write)_: The file path to which to write the standard output from the processes. Any existing file at this file path will be overwritten. This property cannot be specified at the same time as Credential when running the processes as a local user.
* **[String] StandardErrorPath** _(Write)_: The file path to which to write the standard error output from the processes. Any existing file at this file path will be overwritten.
* **[String] StandardInputPath** _(Write)_: The file path from which to receive standard input for the processes. This property cannot be specified at the same time as Credential when running the processes as a local user.
* **[String] WorkingDirectory** _(Write)_: The file path to the working directory under which to run the process. This property cannot be specified at the same time as Credential when running the processes as a local user.

#### Read-Only Properties from Get-TargetResource

* **[UInt64] PagedMemorySize** _(Read)_: The amount of paged memory, in bytes, allocated for the processes.
* **[UInt64] NonPagedMemorySize** _(Read)_: The amount of nonpaged memory, in bytes, allocated for the processes.
* **[UInt64] VirtualMemorySize** _(Read)_: The amount of virtual memory, in bytes, allocated for the processes.
* **[SInt32] HandleCount** _(Read)_: The number of handles opened by the processes.
* **[SInt32] ProcessId** _(Read)_: The unique identifier of the processes.
* **[SInt32] ProcessCount** _(Read)_: The number of instances of the given processes that are currently running.

#### Examples

* [Start multiple processes](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xProcessSet_StartProcessConfig.ps1)
* [Stop multiple processes](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xProcessSet_StopProcessConfig.ps1)

### xService

Provides a mechanism to configure and manage Windows services.
This resource works on Nano Server.

#### Requirements

None

#### Parameters

* **[String] Name** _(Key)_: Indicates the service name. This may be different from the service's display name. To retrieve a list of all services with their names and current states, use the Get-Service cmdlet.
* **[String] Ensure** _(Write)_: Indicates whether the service is present or absent. { *Present* | Absent }.
* **[String] Path** _(Write)_: The path to the service executable file. Required when creating a service. The user account specified by BuiltInAccount or Credential must have access to this path in order to start the service.
* **[String] DisplayName** _(Write)_: The display name of the service.
* **[String] Description** _(Write)_: The description of the service.
* **[String[]] Dependencies** _(Write)_: The names of the dependencies of the service.
* **[String] BuiltInAccount** _(Write)_: The built-in account the service should start under. Cannot be specified at the same time as Credential or GroupManagedServiceAccount. The user account specified by this property must have access to the service executable path defined by Path in order to start the service. { LocalService | LocalSystem | NetworkService }.
* **[String] GroupManagedServiceAccount** _(Write)_: The Group Managed Service Account the service should start under. Cannot be specified at the same time as Credential or BuiltinAccount. The user account specified by this property must have access to the service executable path defined by Path in order to start the service. When specified in a DOMAIN\User$ form, remember to also input the trailing dollar sign. Get-TargetResource outputs the name of the user to the BuiltinAccount property.
* **[PSCredential] Credential** _(Write)_: The credential of the user account the service should start under. Cannot be specified at the same time as BuiltInAccount or GroupManagedServiceAccount. The user specified by this credential will automatically be granted the Log on as a Service right. The user account specified by this property must have access to the service executable path defined by Path in order to start the service. Get-TargetResource outputs the name of the user to the BuiltinAccount property.
* **[Boolean] DesktopInteract** _(Write)_: Indicates whether or not the service should be able to communicate with a window on the desktop. Must be false for services not running as LocalSystem. The default value is False.
* **[String] StartupType** _(Write)_: The startup type of the service. { Automatic | Disabled | Manual }. If StartupType is "Disabled" and Service is not installed the resource will complete as being DSC compliant.
* **[String] State** _(Write)_: The state of the service. { *Running* | Stopped | Ignore }.
* **[Uint32] StartupTimeout** _(Write)_: The time to wait for the service to start in milliseconds. Defaults to 30000 (30 seconds).
* **[Uint32] TerminateTimeout** _(Write)_: The time to wait for the service to stop in milliseconds. Defaults to 30000 (30 seconds).

#### Read-Only Properties from Get-TargetResource

None

#### Examples

* [Create a service](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xService_CreateServiceConfig.ps1)
* [Delete a service](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xService_RemoveServiceConfig.ps1)
* [Change the state of a service to started or stopped](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xService_ChangeServiceStateConfig.ps1.ps1)
* [Update startup type for a service, and ignoring the current state](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xService_UpdateStartupTypeIgnoreStateConfig.ps1)

### xServiceSet
Provides a mechanism to configure and manage multiple xService resources with common settings but different names.
This resource can only modify or delete existing services. It cannot create services.

#### Requirements

None

#### Parameters

* **[String[]] Name** _(Key)_: The names of the services to modify or delete. This may be different from the service's display name. To retrieve a list of all services with their names and current states, use the Get-Service cmdlet.

The following parameters will be the same for each service in the set:

* **[String] Ensure** _(Write)_: Indicates whether the services are present or absent. { *Present* | Absent }.
* **[String] BuiltInAccount** _(Write)_: The built-in account the services should start under. Cannot be specified at the same time as Credential. The user account specified by this property must have access to the service executable paths in order to start the services. { LocalService | LocalSystem | NetworkService }.
* **[PSCredential] Credential** _(Write)_: The credential of the user account the services should start under. Cannot be specified at the same time as BuiltInAccount. The user specified by this credential will automatically be granted the Log on as a Service right. The user account specified by this property must have access to the service executable paths in order to start the services.
* **[String] StartupType** _(Write)_: The startup type of the services. { Automatic | Disabled | Manual }.
* **[String] State** _(Write)_: The state the services. { *Running* | Stopped | Ignore }.

#### Read-Only Properties from Get-TargetResource

None

#### Examples

* [Ensure that multiple services are running](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xServiceSet_StartServicesConfig.ps1)
* [Set multiple services to run under the built-in account LocalService](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xServiceSet_EnsureBuiltInAccountConfig.ps1)

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

#### Examples

* [Download a file](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xRemoteFile_DownloadFileConfig.ps1)
* [Download a file using proxy](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xRemoteFile_DownloadFileUsingProxyConfig.ps1)

### xPackage

* **Ensure**: Ensures that the package is **Present** or **Absent**.
* **Name**: The name of the package.
* **Path**: The source path of the package.
* **ProductId**: The product ID of the package (usually a GUID).
* **Arguments**: Command line arguments passed on the installation command line.
    - When installing MSI packages, the `/quiet` and `/norestart` arguments are automatically applied.
* **Credential**: PSCredential needed to access Path.
* **ReturnCode**: An array of return codes that are returned after a successful installation.
* **LogPath**: The destination path of the log.
* **FileHash**: The hash that should match the hash of the package file.
* **HashAlgorithm**: The algorithm to use to get the hash of the package file.
    - Supported values: SHA1, SHA256, SHA384, SHA512, MD5, RIPEMD160
* **SignerSubject**: The certificate subject that should match that of the package file's signing certificate.
* **SignerThumbprint**: The certificate thumbprint that should match that of the package file's signing certificate.
* **ServerCertificateValidationCallback**: A callback function to validate the server certificate.
* **RunAsCredential**: Credential used to install the package on the local system.
* **CreateCheckRegValue**: If a registry value should be created.
* **InstalledCheckRegHive**: The hive in which to create the registry key. Defaults to 'LocalMachine'. { LocalMachine | CurrentUser }
* **InstalledCheckRegKey**: That path in the registry where the value should be created.
* **InstalledCheckRegValueName**: The name of the registry value to create.
* **InstalledCheckRegValueData**: The data that should be set to the registry value.

### Read-Only Properties from Get-TargetResource

* **PackageDescription**: A text description of the package being installed.
* **Publisher**: Publisher's name.
* **InstalledOn**: Date of installation.
* **Size**: Size of the installation.
* **Version**: Version of the package.
* **Installed**: Is the package installed?

#### Examples

* [Install an .exe using credentials](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xPackage_InstallExeUsingCredentialsConfig.ps1)
* [Install an .exe using credentials and using custom registry data to discover the package](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xPackage_InstallExeUsingCredentialsAndRegistryConfig.ps1)
* [Simple installer for an msi package that matches via the Name](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xPackage_InstallMsiConfig.ps1)
* [Simple installer for an msi package and matches based on the product id](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xPackage_InstallMsiUsingProductIdConfig.ps1)

### xPSEndpoint (xPSSessionConfiguration)

Creates and registers a new session configuration endpoint.

* **Ensure**: Indicates if the session configuration is **Present** or **Absent**.
* **Name**: Specifies the name of the session configuration.
* **StartupScript**: Specifies the startup script for the configuration. Enter
  the fully qualified path of a Windows PowerShell script.
* **RunAsCredential**: Specifies the credential for commands of this session
  configuration. By default, commands run with the permissions of the current user.
* **SecurityDescriptorSDDL**: Specifies the Security Descriptor Definition
  Language (SDDL) string for the configuration. This string determines the
  permissions that are required to use the new session configuration. To use a
  session configuration in a session, users must have at least Execute(Invoke)
  permission for the configuration.
* **AccessMode**: Enables and disables the session configuration and determines
  whether it can be used for remote or local sessions on the computer. The
  default value is "Remote". { Local | *Remote* | Disabled }

### Read-Only Properties from Get-TargetResource

*None.*

#### Examples

* [Register a new session configuration endpoint with optional access mode](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xPSEndpoint_NewConfig.ps1)
* [Register a new session configuration endpoint with default values](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xPSEndpoint_NewWithDefaultsConfig.ps1)
* [Register a new session configuration endpoint with custom values](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xPSEndpoint_NewCustomConfig.ps1)
* [Removes an existing session configuration endpoint](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xPSEndpoint_RemoveConfig.ps1)

### xMsiPackage

Provides a mechanism to install and uninstall .msi packages.

#### Requirements

None

#### Parameters

* **[String] ProductId** _(Key)_: The identifying number used to find the package, usually a GUID.
* **[String] Path** _(Required)_: The path to the MSI file that should be installed or uninstalled.
* **[String] Ensure** _(Write)_: Specifies whether or not the MSI file should be installed or not. To install the MSI file, specify this property as Present. To uninstall the .msi file, specify this property as Absent. The default value is Present. { *Present* | Absent }.
* **[String] Arguments** _(Write)_: The arguments to be passed to the MSI package during installation or uninstallation if needed.
* **[System.Management.Automation.PSCredential] Credential** _(Write)_: The credential of a user account to be used to mount a UNC path if needed.
* **[String] LogPath** _(Write)_: The path to the log file to log the output from the MSI execution.
* **[String] FileHash** _(Write)_: The expected hash value of the MSI file at the given path.
* **[String] HashAlgorithm** _(Write)_: The algorithm used to generate the given hash value.
* **[String] SignerSubject** _(Write)_: The subject that should match the signer certificate of the digital signature of the MSI file.
* **[String] SignerThumbprint** _(Write)_: The certificate thumbprint that should match the signer certificate of the digital signature of the MSI file.
* **[String] ServerCertificateValidationCallback** _(Write)_: PowerShell code that should be used to validate SSL certificates for paths using HTTPS.
* **[System.Management.Automation.PSCredential] RunAsCredential** _(Write)_: The credential of a user account under which to run the installation or uninstallation of the MSI package.

#### Read-Only Properties from Get-TargetResource

* **[String] Name** _(Read)_: The display name of the MSI package.
* **[String] InstallSource** _(Read)_: The path to the MSI package.
* **[String] InstalledOn** _(Read)_: The date that the MSI package was installed on or serviced on, whichever is later.
* **[UInt32] Size** _(Read)_: The size of the MSI package in MB.
* **[String] Version** _(Read)_: The version number of the MSI package.
* **[String] PackageDescription** _(Read)_: The description of the MSI package.
* **[String] Publisher** _(Read)_: The publisher of the MSI package.

#### Examples

* [Install the MSI file with the given ID at the given file path or HTTP URL](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xMsiPackage_InstallPackageConfig.ps1)
* [Uninstall the MSI file with the given ID at the given Path](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xMsiPackage_UninstallPackageFromFileConfig.ps1)
* [Uninstall the MSI file with the given ID at the given HTTPS URL](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xMsiPackage_UninstallPackageFromHttpsConfig.ps1)

### xFileUpload

* **DestinationPath**: Path where the local file should be uploaded.
* **SourcePath**: Path to the local file which should be uploaded.
* **Credential**: PSCredential for the user with access to DestinationPath.
* **CertificateThumbprint**: Thumbprint of the certificate which should be used for encryption/decryption.

#### Examples

* [Upload file or folder to a SMB share](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xFileUpload_UploadToSMBShareConfig.ps1)

### xEnvironment

Provides a mechanism to configure and manage environment variables for a machine or process.

#### Requirements

None

#### Parameters

* **[String] Name** _(Key)_: The name of the environment variable to create, modify, or remove.
* **[String] Value** _(Write)_: The desired value for the environment variable. The default value is an empty string which either indicates that the variable should be removed entirely or that the value does not matter when testing its existence. Multiple entries can be entered and separated by semicolons (see [Examples](./Examples)).
* **[String] Ensure** _(Write)_: Specifies if the environment varaible should exist. { *Present* | Absent }.
* **[Boolean] Path** _(Write)_: Indicates whether or not the environment variable is a path variable. If the variable being configured is a path variable, the value provided will be appended to or removed from the existing value, otherwise the existing value will be replaced by the new value. When configured as a Path variable, multiple entries separated by semicolons are ensured to be either present or absent without affecting other Path entries (see [Examples](./Examples)). The default value is False.
* **[String[]] Target** _(Write)_: Indicates the target where the environment variable should be set. { Process | Machine | *Process, Machine* }.

#### Read-Only Properties from Get-TargetResource

None

#### Examples

* [Create a regular (non-path) environment variable](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xEnvironment_CreateNonPathVariableConfig.ps1)
* [Create or update a path environment variable](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xEnvironment_AddMultiplePathsConfig.ps1)
* [Remove paths from a path environment variable](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xEnvironment_RemoveMultiplePathsConfig.ps1)
* [Remove an environment variable](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xEnvironment_RemoveVariableConfig.ps1)

xEnvironment_AddMultiplePaths
### xScript

Provides a mechanism to run PowerShell script blocks on a target node.
This resource works on Nano Server.

#### Requirements

None

#### Parameters

* **[String] GetScript** _(Key)_: A string that can be used to create a PowerShell script block that retrieves the current state of the resource. This script block runs when the Get-DscConfiguration cmdlet is called. This script block should return a hash table containing one key named Result with a string value.
* **[String] SetScript** _(Key)_: A string that can be used to create a PowerShell script block that sets the resource to the desired state. This script block runs conditionally when the Start-DscConfiguration cmdlet is called. The TestScript script block will run first. If the TestScript block returns False, this script block will run. If the TestScript block returns True, this script block will not run. This script block should not return.
* **[String] TestScript** _(Key)_: A string that can be used to create a PowerShell script block that validates whether or not the resource is in the desired state. This script block runs when the Start-DscConfiguration cmdlet is called or when the Test-DscConfiguration cmdlet is called. This script block should return a boolean with True meaning that the resource is in the desired state and False meaning that the resource is not in the desired state.
* **[PSCredential] Credential** _(Write)_: The credential of the user account to run the script under if needed.

#### Read-Only Properties from Get-TargetResource

* **[String] Result** _(Read)_: The result from the GetScript script block.

#### Examples

* [Create a file with content through xScript](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xScript_WatchFileContentConfig.ps1)

### xRegistry

Provides a mechanism to manage registry keys and values on a target node.

#### Requirements

None

#### Parameters

* **[String] Key** _(Key)_: The path of the registry key to add, modify, or remove. This path must include the registry hive/drive (e.g. HKEY_LOCAL_MACHINE, HKLM:).
* **[String] ValueName** _(Key)_: The name of the registry value. To add or remove a registry key, specify this property as an empty string without specifying ValueType or ValueData. To modify or remove the default value of a registry key, specify this property as an empty string while also specifying ValueType or ValueData.
* **[String] Ensure** _(Write)_: Specifies whether or not the registry key or value should exist. To add or modify a registry key or value, set this property to Present. To remove a registry key or value, set this property to Absent. { *Present* | Absent }.
* **[String] ValueData** _(Write)_: The data the specified registry key value should have as a string or an array of strings (MultiString only).
* **[String] ValueType** _(Write)_: The type the specified registry key value should have. { *String* | Binary | DWord | QWord | MultiString | ExpandString }
* **[Boolean] Hex** _(Write)_: Specifies whether or not the specified DWord or QWord registry key data is provided in a hexadecimal format. Not valid for types other than DWord and QWord. The default value is $false.
* **[Boolean] Force** _(Write)_: Specifies whether or not to overwrite the specified registry key value if it already has a value or whether or not to delete a registry key that has subkeys. The default value is $false.

#### Read-Only Properties from Get-TargetResource

None

#### Examples

* [Add a registry key](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xRegistryResource_AddKeyConfig.ps1)
* [Add or modify a registry key value](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xRegistryResource_AddOrModifyValueConfig.ps1)
* [Remove a registry key value](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xRegistryResource_RemoveValueConfig.ps1)
* [Remove a registry key](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xRegistryResource_RemoveKeyConfig.ps1)

### xUser

Provides a mechanism to manage local users on a target node.

#### Requirements

None

#### Parameters

* **[String] UserName** _(Key)_: Indicates the account name for which you want to ensure a specific state.
* **[String] Description** _(Write)_: Indicates the description you want to use for the user account.
* **[Boolean] Disabled** _(Write)_: Indicates if the account is enabled. Set this property to $true to ensure that this account is disabled, and set it to $false to ensure that it is enabled.
   - Suported values: $true, $false
   - Default value: $false
* **[String] Ensure** _(Write)_: Ensures that the feature is present or absent.
   - Supported values: Present, Absent
   - Default Value: Present
* **[String] FullName** _(Write)_: Represents a string with the full name you want to use for the user account.
* **[PSCredential] Password** _(Write)_: Indicates the password you want to use for this account.
* **[Boolean] PasswordChangeNotAllowed** _(Write)_: Indicates if the user can change the password. Set this property to $true to ensure that the user cannot change the password, and set it to $false to allow the user to change the password.
   - Suported values: $true, $false
   - Default value: $false
* **[Boolean] PasswordChangeRequired** _(Write)_: Indicates if the user must change the password at the next sign in. Set this property to $true if the user must change the password.
   - Suported values: $true, $false
   - Default value: $true
* **[Boolean] PasswordNeverExpires** _(Write)_: Indicates if the password will expire. To ensure that the password for this account will never expire, set this property to $true, and set it to $false if the password will expire.
   - Suported values: $true, $false
   - Default value: $false

#### Examples

* [Create a new local user account](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xUser_CreateUserConfig.ps1)
* [Remove a local user account](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xUser_RemoveUserConfig.ps1)
* [Create a new detailed local user account](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xUser_CreateUserDetailedConfig.ps1)

### xWindowsFeature

Provides a mechanism to install or uninstall Windows roles or features on a target node.

#### Requirements

* Target machine must be running Windows Server 2008 or later.
* Target machine must have access to the DISM PowerShell module.
* Target machine must have access to the ServerManager module.

#### Parameters

* **[String] Name** _(Key)_: Indicates the name of the role or feature that you want to ensure is added or removed. This is the same as the Name property from the Get-WindowsFeature cmdlet, and not the display name of the role or feature.
* **[PSCredential] Credential** _(Write)_: Indicates the credential to use to add or remove the role or feature if needed.
* **[String] Ensure** _(Write)_: Specifies whether the feature should be installed (Present) or uninstalled (Absent) { *Present* | Absent }.
* **[Boolean] IncludeAllSubFeature** _(Write)_: Set this property to $true to ensure the state of all required subfeatures with the state of the feature you specify with the Name property. The default value is $false.
* **[String] LogPath** _(Write)_: Indicates the path to a log file to log the operation.

#### Read-Only Properties from Get-TargetResource

* **[String] DisplayName** _(Read)_: The display name of the retrieved role or feature.

#### Examples

* [Install a Windows feature](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsFeature_AddFeatureConfig.ps1)
* [Uninstall a Windows feature](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsFeature_RemoveFeatureConfig.ps1)
* [Install a Windows feature using credentials](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsFeature_AddFeatureUsingCredentialConfig.ps1)
* [Install a Windows feature, output the log to file](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsFeature_AddFeatureWithLogPathConfig.ps1)

### xWindowsFeatureSet

Provides a mechanism to configure and manage multiple xWindowsFeature resources on a target node.

#### Requirements

* Target machine must be running Windows Server 2008 or later.
* Target machine must have access to the DISM PowerShell module.
* Target machine must have access to the ServerManager module.

#### Parameters

* **[String] Name** _(Key)_: The names of the roles or features to install or uninstall. This may be different from the display name of the feature/role. To retrieve the names of features/roles on a machine use the Get-WindowsFeature cmdlet.
* **[String] Ensure** _(Write)_: Specifies whether the feature should be installed or uninstalled. To install features, set this property to Present. To uninstall features, set this property to Absent. { Present | Absent }.
* **[Boolean] IncludeAllSubFeature** _(Write)_: Specifies whether or not all subfeatures should be installed or uninstalled alongside the specified roles or features. If this property is true and Ensure is set to Present, all subfeatures will be installed. If this property is false and Ensure is set to Present, subfeatures will not be installed or uninstalled. If Ensure is set to Absent, all subfeatures will be uninstalled.
* **[PSCredential] Credential** _(Write)_: The credential of the user account under which to install or uninstall the roles or features.
* **[String] LogPath** _(Write)_: The custom file path to which to log this operation. If not passed in, the default log path will be used (%windir%\logs\ServerManager.log).

#### Read-Only Properties from Get-TargetResource

* **[String] DisplayName** _(Read)_: The display names of the retrieved roles or features.

#### Examples

* [Install multiple Windows features](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsFeatureSet_AddFeaturesConfig.ps1)
* [Uninstall multiple Windows features](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsFeatureSet_RemoveFeaturesConfig.ps1)

### xWindowsOptionalFeature

Provides a mechanism to enable or disable optional features on a target node.
This resource works on Nano Server.

#### Requirements

* Target machine must be running a Windows client operating system, Windows Server 2012 or later, or Nano Server.
* Target machine must have access to the DISM PowerShell module.

#### Parameters

* **[String] Name** _(Key)_: The name of the Windows optional feature to enable or disable.
* **[String] Ensure** _(Write)_: Specifies whether the feature should be enabled or disabled. To enable the feature, set this property to Present. To disable the feature, set the property to Absent. The default value is Present. { *Present* | Absent }.
* **[Boolean] RemoveFilesOnDisable** _(Write)_: Specifies that all files associated with the feature should be removed if the feature is being disabled.
* **[Boolean] NoWindowsUpdateCheck** _(Write)_: Specifies whether or not DISM contacts Windows Update (WU) when searching for the source files to enable the feature. If $true, DISM will not contact WU.
* **[String] LogPath** _(Write)_: The path to the log file to log this operation. There is no default value, but if not set, the log will appear at %WINDIR%\Logs\Dism\dism.log.
* **[String] LogLevel** _(Write)_: The maximum output level to show in the log. ErrorsOnly will log only errors. ErrorsAndWarning will log only errors and warnings. ErrorsAndWarningAndInformation will log errors, warnings, and debug information). The default value is "ErrorsAndWarningAndInformation".  { ErrorsOnly | ErrorsAndWarning | *ErrorsAndWarningAndInformation* }.

#### Read-Only Properties from Get-TargetResource

* **[String[]] CustomProperties** _(Read)_: The custom properties retrieved from the Windows optional feature as an array of strings.
* **[String] Description** _(Read)_: The description retrieved from the Windows optional feature.
* **[String] DisplayName** _(Read)_: The display name retrieved from the Windows optional feature.

#### Examples

* [Enable the specified windows optional feature and output logs to the specified path](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsOptionalFeature_EnableConfig.ps1)
* [Disables the specified windows optional feature and output logs to the specified path](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsOptionalFeature_DisableConfig.ps1)

### xWindowsOptionalFeatureSet

Provides a mechanism to configure and manage multiple xWindowsOptionalFeature resources on a target node.
This resource works on Nano Server.

#### Requirements

* Target machine must be running a Windows client operating system, Windows Server 2012 or later, or Nano Server.
* Target machine must have access to the DISM PowerShell module.

#### Parameters

* **[String[]] Name** _(Key)_: The names of the Windows optional features to enable or disable.

The following parameters will be the same for each Windows optional feature in the set:

* **[String] Ensure** _(Write)_: Specifies whether the Windows optional features should be enabled or disabled. To enable the features, set this property to Present. To disable the features, set this property to Absent. { Present | Absent }.
* **[Boolean] RemoveFilesOnDisable** _(Write)_: Specifies whether or not to remove the files associated with the Windows optional features when they are disabled.
* **[Boolean] NoWindowsUpdateCheck** _(Write)_: Specifies whether or not DISM should contact Windows Update (WU) when searching for the source files to restore Windows optional features on an online image.
* **[String] LogPath** _(Write)_: The file path to which to log the operation.
* **[String] LogLevel** _(Write)_: The level of detail to include in the log. { ErrorsOnly | ErrorsAndWarning | ErrorsAndWarningAndInformation }.

#### Read-Only Properties from Get-TargetResource

None

#### Examples

* [Enable multiple features](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsOptionalFeatureSet_EnableConfig.ps1)
* [Disable multiple features](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsOptionalFeatureSet_DisableConfig.ps1)

### xWindowsPackageCab
Provides a mechanism to install or uninstall a package from a windows cabinet (cab) file on a target node.
This resource works on Nano Server.

#### Requirements

* Target machine must have access to the DISM PowerShell module

#### Parameters

* **[String] Name** _(Key)_: The name of the package to install or uninstall.
* **[String] Ensure** _(Required)_: Specifies whether the package should be installed or uninstalled. To install the package, set this property to Present. To uninstall the package, set the property to Absent. { *Present* | Absent }.
* **[String] SourcePath** _(Required)_: The path to the cab file to install or uninstall the package from.
* **[String] LogPath** _(Write)_: The path to a file to log the operation to. There is no default value, but if not set, the log will appear at %WINDIR%\Logs\Dism\dism.log.

#### Read-Only Properties from Get-TargetResource

None

#### Examples

* [Install a cab file with the given name from the given path](https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/dev/Examples/xWindowsPackageCab_InstallPackageConfig.ps1)

## Functions

### Publish-ModuleToPullServer

Publishes a 'ModuleInfo' object(s) to the pullserver module repository or user provided path. It accepts its input from a pipeline so it can be used in conjunction with Get-Module as Get-Module <ModuleName> | Publish-Module

### Publish-MOFToPullServer

Publishes a 'FileInfo' object(s) to the pullserver configuration repository. It accepts FileInfo input from a pipeline so it can be used in conjunction with Get-ChildItem .*.mof | Publish-MOFToPullServer

## Versions

### Unreleased

* xWindowsOptionalFeature
  * Suppress useless verbose output from `Import-Module` cmdlet. ([issue 453](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/453))
* Changes to xRemoteFile
  * Corrected a resource name in the example xRemoteFile_DownloadFileConfig.ps1
* Fix `MSFT_xDSCWebService` to find
 `Microsoft.Powershell.DesiredStateConfiguration.Service.Resources.dll`
  when server is configured with pt-BR Locales ([issue #284](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/284)).  
* Changes to xDSCWebService
  * Fixed an issue which prevented the removal of the IIS Application Pool created during deployment of an DSC Pull Server instance. ([issue #464](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/464))
  * Fixed an issue where a Pull Server cannot be deployed on a machine when IIS Express is installed aside a full blown IIS ([issue #191](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/191))
* Update `CommonResourceHelper` unit tests to meet Pester 4.0.0
  standards ([issue #473](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/473)).
* Update `ResourceHelper` unit tests to meet Pester 4.0.0
  standards ([issue #473](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/473)).
* Update `MSFT_xDSCWebService` unit tests to meet Pester 4.0.0
  standards ([issue #473](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/473)).
* Update `MSFT_xDSCWebService` integration tests to meet Pester 4.0.0
  standards ([issue #473](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/473)).
* Refactored `MSFT_xDSCWebService` integration tests to meet current
  standards and to use Pester TestDrive.
* xArchive
  * Fix end-to-end tests ([issue #457](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/457)).
  * Update integration tests to meet Pester 4.0.0 standards.
  * Update end-to-end tests to meet Pester 4.0.0 standards.
  * Update unit and integration tests to meet Pester 4.0.0 standards.
  * Wrapped all path and identifier strings in verbose messages with
    quotes to make it easier to identify the limit of the string when
    debugging.
  * Refactored date/time checksum code to improve testability and ensure
    tests can run on machines with localized datetime formats that are not
    US.
  * Fix 'Get-ArchiveEntryLastWriteTime' to return `[datetime]` ([issue #471](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/471)).
  * Improved verbose logging to make debugging path issues easier.
  * Added handling for '/' as a path seperator by backporting code from
    PSDscResources - ([issue #469](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/469)).
  * Copied unit tests from [PSDscResources](https://github.com/PowerShell/PSDscResources).
    * Added .gitattributes file and removed git configuration from AppVeyor
  to ensure CRLF settings are configured correctly for the repository.
* Updated '.vscode\settings.json' to refer to AnalyzerSettings.psd1 so that
  custom syntax problems are highlighted in Visual Studio Code.
* Fixed style guideline violations in `CommonResourceHelper.psm1`.
* Changes to xService
  * Fixes issue where Get-TargetResource or Test-TargetResource will throw an
    exception if the target service is configured with a non-existent dependency.
  * Refactored Get-TargetResource Unit tests.
* Fixes files which are getting triggered for re-encoding after recent pull
  request (possibly #472).
* Changes to PSWSIISEndpoint.psm1
  * Fixes most PSScriptAnalyzer issues.

### 8.5.0.0

* Changes to xRegistry
  * Fixed an issue that fails to remove reg key when the `Key` is specified as common registry path. ([issue #444](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/444))
* Changes to xService
  * Added support for Group Managed Service Accounts

### 8.4.0.0

* Changes to xPSDesiredStateConfiguration
  * Opt-in for the common tests validate module files and script files.
  * All files change to encoding UTF-8 (without byte order mark).
  * Opt-in for the common test for example validation.
  * Added Visual Studio Code workspace settings that helps with formatting
    against the style guideline.
  * Update all examples for them to be able pass the common test validation.
* xEnvironment path documentation update demonstrating usage with multiple values  ([issue #415](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/415). [Alex Kokkinos (@alexkokkinos)](https://github.com/alexkokkinos)
* Changes to xWindowsProcess
  * Increased the wait time in the integration tests since the tests
    still failed randomly ([issue #420](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/420)).
* Renamed and updated examples to be able to publish them to PowerShell Gallery.
  * Sample\_xScript.ps1 → xScript\_WatchFileContentConfig.ps1
  * Sample\_xService\_UpdateStartupTypeIgnoreState.ps1 → xService\_UpdateStartupTypeIgnoreStateConfig.ps1
  * Sample\_xWindowsProcess\_Start.ps1 → xWindowsProcess\_StartProcessConfig.ps1
  * Sample\_xWindowsProcess\_StartUnderUser.ps1 → xWindowsProcess\_StartProcessUnderUserConfig.ps1
  * Sample\_xWindowsProcess\_Stop.ps1 → xWindowsProcess\_StopProcessConfig.ps1
  * Sample\_xWindowsProcess\_StopUnderUser.ps1 → xWindowsProcess\_StopProcessUnderUserConfig.ps1
  * Sample\_xUser\_CreateUser.ps1.ps1 → xUser\_CreateUserConfig.ps1
  * Sample\_xUser\_Generic.ps1.ps1 → xUser\_CreateUserDetailedConfig.ps1
  * Sample\_xWindowsFeature.ps1 → xWindowsFeature\_AddFeatureConfig.ps1
  * Sample\_xWindowsFeatureSet\_Install.ps1 → xWindowsFeatureSet\_AddFeaturesConfig.ps1
  * Sample\_xWindowsFeatureSet\_Uninstall.ps1 → xWindowsFeatureSet\_RemoveFeaturesConfig.ps1
  * Sample\_xRegistryResource\_AddKey.ps1 → xRegistryResource\_AddKeyConfig.ps1
  * Sample\_xRegistryResource\_RemoveKey.ps1 → xRegistryResource\_RemoveKeyConfig.ps1
  * Sample\_xRegistryResource\_AddOrModifyValue.ps1 → xRegistryResource\_AddOrModifyValueConfig.ps1
  * Sample\_xRegistryResource\_RemoveValue.ps1 → xRegistryResource\_RemoveValueConfig.ps1
  * Sample\_xService\_CreateService.ps1 → xService\_CreateServiceConfig.ps1
  * Sample\_xService\_DeleteService.ps1 → xService\_RemoveServiceConfig.ps1
  * Sample\_xServiceSet\_StartServices.ps1 → xServiceSet\_StartServicesConfig.ps1
  * Sample\_xServiceSet\_BuiltInAccount → xServiceSet\_EnsureBuiltInAccountConfig.ps1
  * Sample\_xWindowsPackageCab → xWindowsPackageCab\_InstallPackageConfig
  * Sample\_xWindowsOptionalFeature.ps1 → xWindowsOptionalFeature\_EnableConfig.ps1
  * Sample\_xWindowsOptionalFeatureSet\_Enable.ps1 → xWindowsOptionalFeatureSet\_EnableConfig.ps1
  * Sample\_xWindowsOptionalFeatureSet\_Disable.ps1 → xWindowsOptionalFeatureSet\_DisableConfig.ps1
  * Sample\_xRemoteFileUsingProxy.ps1 → xRemoteFile\_DownloadFileUsingProxyConfig.ps1
  * Sample\_xRemoteFile.ps1 → xRemoteFile\_DownloadFileConfig.ps1
  * Sample\_xProcessSet\_Start.ps1 → xProcessSet\_StartProcessConfig.ps1
  * Sample\_xProcessSet\_Stop.ps1 → xProcessSet\_StopProcessConfig.ps1
  * Sample\_xMsiPackage\_UninstallPackageFromHttps.ps1 → xMsiPackage\_UninstallPackageFromHttpsConfig.ps1
  * Sample\_xMsiPackage\_UninstallPackageFromFile.ps1 → xMsiPackage\_UninstallPackageFromFileConfig.ps1
  * Sample\_xMsiPackage\_InstallPackageFromFile → xMsiPackage\_InstallPackageConfig.ps1
  * Sample\_xGroup\_SetMembers.ps1 → xGroup\_SetMembersConfig.ps1
  * Sample\_xGroup\_RemoveMembers.ps1 → xGroup\_RemoveMembersConfig.ps1
  * Sample\_xGroupSet\_AddMembers.ps1 → xGroupSet\_AddMembersConfig.ps1
  * Sample\_xFileUpload.ps1 → xFileUpload\_UploadToSMBShareConfig.ps1
  * Sample\_xEnvironment\_CreateMultiplePathVariables.ps1 → xEnvironment\_AddMultiplePathsConfig.ps1
  * Sample\_xEnvironment\_RemovePathVariables.ps1 → xEnvironment\_RemoveMultiplePathsConfig.ps1
  * Sample\_xEnvironment\_CreateNonPathVariable.ps1 → xEnvironment\_CreateNonPathVariableConfig.ps1
  * Sample\_xEnvironment\_Remove.ps1 → xEnvironment\_RemoveVariableConfig.ps1
  * Sample\_xArchive\_ExpandArchiveChecksumAndForce.ps1 → xArchive\_ExpandArchiveChecksumAndForceConfig.ps1
  * Sample\_xArchive\_ExpandArchiveDefaultValidationAndForce.ps1 → xArchive\_ExpandArchiveDefaultValidationAndForceConfig.ps1
  * Sample\_xArchive\_ExpandArchiveNoValidation.ps1 → xArchive\_ExpandArchiveNoValidationConfig.ps1
  * Sample\_xArchive\_ExpandArchiveNoValidationCredential.ps1 → xArchive\_ExpandArchiveNoValidationCredentialConfig.ps1
  * Sample\_xArchive\_RemoveArchiveChecksum.ps1 → xArchive\_RemoveArchiveChecksumConfig.ps1
  * Sample\_xArchive\_RemoveArchiveNoValidation.ps1 → xArchive\_RemoveArchiveNoValidationConfig.ps1
  * Sample\_InstallExeCreds\_xPackage.ps1 → xPackage\_InstallExeUsingCredentialsConfig.ps1
  * Sample\_InstallExeCredsRegistry\_xPackage.ps1 → xPackage\_InstallExeUsingCredentialsAndRegistryConfig.ps1
  * Sample\_InstallMSI\_xPackage.ps1 → xPackage\_InstallMsiConfig.ps1
  * Sample\_InstallMSIProductId\_xPackage.ps1 → xPackage\_InstallMsiUsingProductIdConfig.ps1
* New examples
  * xUser\_RemoveUserConfig.ps1
  * xWindowsFeature\_AddFeatureUsingCredentialConfig.ps1
  * xWindowsFeature\_AddFeatureWithLogPathConfig.ps1
  * xWindowsFeature\_RemoveFeatureConfig.ps1
  * xService\_ChangeServiceStateConfig.ps1
  * xWindowsOptionalFeature\_DisableConfig.ps1
  * xPSEndpoint\_NewConfig.ps1
  * xPSEndpoint\_NewWithDefaultsConfig.ps1
  * xPSEndpoint\_RemoveConfig.ps1
  * xPSEndpoint\_NewCustomConfig.ps1
* Removed examples
  * Sample\_xPSSessionConfiguration.ps1 - This file was split up in several examples,
    those starting with 'xPSEndpoint*'.
  * Sample\_xMsiPackage\_InstallPackageFromHttp - This was added to the example
    xMsiPackage\_InstallPackageConfig.ps1 so the example sows either URI scheme.
  * Sample\_xEnvironment\_CreatePathVariable.ps1 - Same as the new example
    xEnvironment\_AddMultiplePaths.ps1

### 8.3.0.0

* Changes to xPSDesiredStateConfiguration
  * README.md: Fixed typo. [Steve Banik (@stevebanik-ndsc)](https://github.com/stevebanik-ndsc)
  * Adding a Branches section to the README.md with Codecov badges for both
    master and dev branch ([issue #416](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/416)).
* Changes to xWindowsProcess
  * Integration tests for this resource should no longer fail randomly. A timing
    issue made the tests fail in certain scenarios ([issue #420](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/420)).
* Changes to xDSCWebService
    * Added the option to use a certificate based on it's subject and template name instead of it's thumbprint. Resolves [issue #205](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/205).
    * xDSCWebService: Fixed an issue where Test-WebConfigModulesSetting would return $true when web.config contains a module and the desired state was for it to be absent. Resolves [issue #418](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/418).
* Updated the main DSCPullServerSetup readme to read easier, then updates the PowerShell comment based help for each function to follow normal help standards. [James Pogran (@jpogran)](https://github.com/jpogran)
* xRemoteFile: Remove progress bar for file download. This resolves issues [#165](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/165) and [#383](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/383) [Claudio Spizzi (@claudiospizzi)](https://github.com/claudiospizzi)

### 8.2.0.0

* xDSCWebService: Disable installing Microsoft.Powershell.Desiredstateconfiguration.Service.Resources.dll as a temporary workaround since the binary is missing on the latest Windows builds

### 8.1.0.0

* xDSCWebService: Enable SQL provider configuration

### 8.0.0.0

* xDSCWebService
    * BREAKING CHANGE: The Pull Server will now run in a 64 bit IIS process by default. Enable32BitAppOnWin64 needs to be set to TRUE for the Pull Server to run in a 32 bit process.

### 7.0.0.0

* xService
    * BREAKING CHANGE: The service will now return as compliant if the service is not installed and the StartupType is set to Disabled regardless of the value of the Ensure property.
* Fixed misnamed certificate thumbprint variable in example Sample_xDscWebServiceRegistrationWithSecurityBestPractices

### 6.4.0.0

* xGroup:
    * Added updates from PSDscResources:
        * Added support for domain based group members on Nano server

### 6.3.0.0

* xDSCWebService
    * Fixed an issue where all 64bit IIS application pools stop working after installing DSC Pull Server, because IISSelfSignedCertModule(32bit) module was registered without bitness32 precondition.

### 6.2.0.0

* xMsiPackage:
    * Created high quality MSI package manager resource
* xArchive:
    * Fixed a minor bug in the unit tests where sometimes the incorrect DateTime format was used.
* xWindowsFeatureSet:
    * Had the wrong parameter name in one test case.

### 6.1.0.0

* Moved DSC pull server setup tests to DSCPullServerSetup folder for new common tests
* xArchive:
    * Updated the resource to be a high quality resource
    * Transferred the existing "unit" tests to integration tests
    * Added unit and end-to-end tests
    * Updated documentation and examples
* xUser
    * Fixed error handling in xUser
* xRegistry
    * Fixed bug where an error was thrown when running Get-DscConfiguration if the registry key already existed
* Updated Test-IsNanoServer cmdlet to properly test for a Nano server rather than the core version of PowerShell

### 6.0.0.0

* xEnvironment
    * Updated resource to follow HQRM guidelines.
    * Added examples.
    * Added unit and end-to-end tests.
    * Significantly cleaned the resource.
    * Minor Breaking Change where the resource will now throw an error if no value is provided, Ensure is set to present, and the variable does not exist, whereas before it would create an empty registry key on the machine in this case (if this is the desired outcome then use the Registry resource).
    * Added a new Write property 'Target', which specifies whether the user wants to set the machine variable, the process variable, or both (previously it was setting both in most cases).
* xGroup:
    * Group members in the "NT Authority", "BuiltIn" and "NT Service" scopes should now be resolved without an error. If you were seeing the errors "Exception calling ".ctor" with "4" argument(s): "Server names cannot contain a space character."" or "Exception calling ".ctor" with "2" argument(s): "Server names cannot contain a space character."", this fix should resolve those errors. If you are still seeing one of the errors, there is probably another local scope we need to add. Please let us know.
    * The resource will no longer attempt to resolve group members if Members, MembersToInclude, and MembersToExclude are not specified.

### 5.2.0.0

* xWindowsProcess
    * Minor updates to integration tests because one of the tests was flaky.
* xRegistry:
    * Added support for forward slashes in registry key names. This resolves issue [#285](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/285).

### 5.1.0.0

* xWindowsFeature:
    * Added Catch to ignore RuntimeException when importing ServerManager module. This resolves issue [#69](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/69).
    * Updated unit tests.
* xPackage:
    * No longer checks for package installation when a reboot is required. This resolves issue [#52](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/52).
    * Ensures a space is added to MSI installation arguments. This resolves issue [#195](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/195).
    * Adds RunAsCredential parameter to permit installing packages with specific user account. This resolves issue [#221](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/221).
    * Fixes null verbose log output error. This resolves issue [#224](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/224).
* xDSCWebService
    * Fixed issue where resource would fail to read redirection.config file. This resolves issue [#191] (https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/191)
* xArchive
    * Fixed issue where resource would throw exception when file name contains brackets. This resolves issue [#255](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/255).
* xScript
    * Cleaned resource for high quality requirements
    * Added unit tests
    * Added integration tests
    * Updated documentation and example
* ResourceSetHelper:
    * Updated common functions for all 'Set' resources.
    * Added unit tests
* xGroupSet:
    * Updated resource to use new ResouceSetHelper functions and added integration tests.
* xGroup:
    * Cleaned module imports, fixed PSSA issues, and set ErrorActionPreference to stop.
* xService:
    * Cleaned resource functions to enable StrictMode.
    * Fixed bug in which Set-TargetResource would create a service when Ensure set to Absent and Path specified.
    * Added unit tests.
    * Added integration tests for BuiltInAccount and Credential.
* xServiceSet:
    * Updated resource to use new ResouceSetHelper functions and added integration tests.
    * Updated documentation and example
* xWindowsProcess
    * Cleaned resource as per high quality guidelines.
    * Added unit tests.
    * Added integration tests.
    * Updated documentation.
    * Updated examples.
    * Fixed bug in Get-TargetResource.
    * Added a 'Count' value to the hashtable returned by Get-TargetResource so that the user can see how many instances of the process are running.
    * Fixed bug in finding the path to the executable.
    * Changed name to be xWindowsProcess everywhere.
* xWindowsOptionalFeatureSet
    * Updated resource to use new ResouceSetHelper functions and added integration tests.
    * Updated documentation and examples
* xWindowsFeatureSet
    * Updated resource to use new ResouceSetHelper functions and added integration tests.
    * Updated documentation and examples
* xProcessSet
    * Updated resource to use new ResouceSetHelper functions and added integration tests.
    * Updated documentation and examples
* xRegistry
    * Updated resource to be high-quality
    * Fixed bug in which the user could not set a Binary registry value to 0
    * Added unit and integration tests
    * Added examples and updated documentation

### 5.0.0.0

* xWindowsFeature:
    * Cleaned up resource (PSSA issues, formatting, etc.)
    * Added/Updated Tests and Examples
    * BREAKING CHANGE: Removed the unused Source parameter
    * Updated to a high quality resource
* xDSCWebService:
    * Add DatabasePath property to specify a custom database path and enable multiple pull server instances on one server.
    * Rename UseUpToDateSecuritySettings property to UseSecurityBestPractices.
    * Add DisableSecurityBestPractices property to specify items that are excepted from following best practice security settings.
* xGroup:
    * Fixed PSSA issues
    * Formatting updated as per style guidelines
    * Missing comment-based help added for Get-/Set-/Test-TargetResource
    * Typos fixed in Unit test script
    * Unit test 'Get-TargetResource/Should return hashtable with correct values when group has no members' updated to handle the expected empty Members array correctly
    * Added a lot of unit tests
    * Cleaned resource
* xUser:
    * Fixed PSSA/Style violations
    * Added/Updated Tests and Examples
* Added xWindowsPackageCab
* xService:
    * Fixed PSSA/Style violations
    * Updated Tests
    * Added 'Ignore' state

### 4.0.0.0

* xDSCWebService:
    * Added setting of enhanced security
    * Cleaned up Examples
    * Cleaned up pull server verification test
* xProcess:
    * Fixed PSSA issues
    * Corrected most style guideline issues
* xPSSessionConfiguration:
    * Fixed PSSA and style issues
    * Renamed internal functions to follow verb-noun formats
    * Decorated all functions with comment-based help
* xRegistry:
    * Fixed PSSA and style issues
    * Renamed internal functions to follow verb-noun format
    * Decorated all functions with comment-based help
    * Merged with in-box Registry
    * Fixed registry key and value removal
    * Added unit tests
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
    * Added integration test for testing changes to additional service properties as well as changing service binary path.
    * Modified Set-TargetResource so that newly created service created with minimal properties and then all additional properties updated (simplification of code).
    * Added support for changing Service Description and DisplayName parameters.
    * Fixed bug when changing binary path of existing service.
* Removed test log output from repo.
* xWindowsOptionalFeature:
    * Cleaned up resource (PSSA issues, formatting, etc.)
    * Added example script
    * Added integration test
    * BREAKING CHANGE: Removed the unused Source parameter
    * Updated to a high quality resource
* Removed test log output from repo.
* Removed the prefix MSFT_ from all files and folders of the composite resources in this module
because they were unavailable to Get-DscResource and Import-DscResource.
    * xFileUpload
    * xGroupSet
    * xProcessSet
    * xServiceSet
    * xWindowsFeatureSet
    * xWindowsOptionalFeatureSet

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

### Sample1.ps3 installs a package that uses an .msi file

This configuration will install a .msi package and verify the package using the product ID and package name and requires credentials to read the share and install the package.

### Sample1.ps4 installs a package that uses an .exe file

This configuration will install a .exe package and verify the package using the product ID and package name and requires credentials to read the share and install the package. It also uses custom registry values to check for the package presence.

### Validate pullserver deployment

If Sample_xDscWebService.ps1 is used to setup a DSC pull and reporting endpoint, the service endpoint can be validated by performing Invoke-WebRequest -URI http://localhost:8080/PSDSCPullServer.svc/$metadata in PowerShell or http://localhost:8080/PSDSCPullServer.svc/ when using InternetExplorer.

[Pullserver Validation Pester Tests](DSCPullServerSetup/PullServerDeploymentVerificationTest)
