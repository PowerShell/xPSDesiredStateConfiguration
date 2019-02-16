<#PSScriptInfo
.VERSION 1.0.1
.GUID b89e163c-48d0-4038-aecd-8c759cfee61e
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
        set of credentials to access the installer.

    .DESCRIPTION
        Configuration that installs an .exe using credentials, and uses another
        set of credentials to access the installer.

    .PARAMETER PackageName
        The name of the package to install.

    .PARAMETER Path
        The path to the executable to install.

    .PARAMETER ProductId
        The product identification number of the package (usually a GUID).
        This parameter accepts an empty System.String.

    .PARAMETER Credential
        The credential to access the executable in the parameter Path.

    .PARAMETER RunAsCredential
        The credentials used to install the package on the target node.

    .EXAMPLE
        xPackage_InstallExeUsingCredentialsConfig -PackageName 'Package Name' -Path '\\software\installer.exe' -ProductId '' -Credential (Get-Credential) -RunAsCredential (Get-Credential)

        Compiles a configuration that installs a package named 'Package Name'
        located in the path '\\software\installer.exe' that is access using
        the credentials in parameter Credentials, and installed using the
        credential in RunAsCredential parameter.
#>
Configuration xPackage_InstallExeUsingCredentialsConfig
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
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ProductId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $RunAsCredential
    )


    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xPackage 'InstallExe'
        {
            Ensure          = 'Present'
            Name            = $PackageName
            Path            = $Path
            RunAsCredential = $RunAsCredential
            Credential      = $Credential
            ProductId       = $ProductId
        }
    }
}
