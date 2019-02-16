<#PSScriptInfo
.VERSION 1.0.1
.GUID 98e37dfd-cefb-4de6-8485-2ed8e5ca8959
.AUTHOR Microsoft Corporation
.COMPANYNAME Microsoft Corporation
.COPYRIGHT
.TAGS DSCConfiguration
.LICENSEURI https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/master/LICENSE
.PROJECTURI https://github.com/PowerShell/xPSDesiredStateConfiguration
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module @{ModuleName = 'xPSDesiredStateConfiguration';ModuleVersion = '8.2.0.0'}

<#
    .SYNOPSIS
        Configuration that installs an .exe using credentials, and uses another
        set of credentials to access the installer. Also uses custom registry
        data to discover the package.

    .DESCRIPTION
        Configuration that installs an .exe using credentials, and uses another
        set of credentials to access the installer. Also uses custom registry
        data to discover the package.

    .PARAMETER PackageName
        The name of the package to install.

    .PARAMETER Path
        The path to the executable to install.

    .PARAMETER Arguments
        The command line arguments passed on the installation command line.
        When installing MSI packages, the `/quiet` and `/norestart` arguments
        are automatically applied.

    .PARAMETER ProductId
        The product identification number of the package (usually a GUID).
        This parameter accepts an empty System.String.

    .PARAMETER InstalledCheckRegKey
        That path in the registry where the value should be created.

    .PARAMETER InstalledCheckRegValueName
        The name of the registry value to create.

    .PARAMETER InstalledCheckRegValueData
        The data that should be set to the registry value.

    .PARAMETER Credential
        The credential to access the executable in the parameter Path.

    .PARAMETER RunAsCredential
        The credentials used to install the package on the target node.

    .NOTES
        The reg key and value is created by xPackage.

    .EXAMPLE
        $configurationParameters = @{
            PackageName = 'Package Name'
            Path = '\\software\installer.exe'
            InstalledCheckRegKey = 'SOFTWARE\Microsoft\DevDiv\winexpress\Servicing\12.0\coremsi'
            InstalledCheckRegValueName = 'Install'
            InstalledCheckRegValueData = '1'
            CreateCheckRegValue = $true
            Credential = (Get-Credential)
            RunAsCredential = (Get-Credential)
            Arguments = '/q'
            ProductId = ''
        }
        xPackage_InstallExeUsingCredentialsAndRegistryConfig @configurationParameters

        Compiles a configuration that installs a package named 'Package Name'
        located in the path '\\software\installer.exe', using the arguments '/q',
        The executable is accessed using the credentials in parameter Credentials,
        and installed using the credential in RunAsCredential parameter.
        Also uses custom registry data to discover the package.
#>
Configuration xPackage_InstallExeUsingCredentialsAndRegistryConfig
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $PackageName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.String]
        $ProductId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $InstalledCheckRegKey,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $InstalledCheckRegValueName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $InstalledCheckRegValueData,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $RunAsCredential,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.String]
        $Arguments
    )

    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    Node localhost
    {
        xPackage 'InstallExe'
        {
            Ensure                     = 'Present'
            Name                       = $PackageName
            Path                       = $Path
            Arguments                  = $Arguments
            RunAsCredential            = $RunAsCredential
            Credential                 = $Credential
            ProductId                  = $ProductId
            CreateCheckRegValue        = $true
            InstalledCheckRegKey       = $InstalledCheckRegKey
            InstalledCheckRegValueName = $InstalledCheckRegValueName
            InstalledCheckRegValueData = $InstalledCheckRegValueData
        }
    }
}
