<#PSScriptInfo
.VERSION 1.0.1
.GUID 596fd9ca-7c00-4aa3-8efc-8e77c96942bf
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
        Configuration that installs an .msi that matches via the Name.

    .DESCRIPTION
        Configuration that installs an .msi that matches via the Name.

    .PARAMETER PackageName
        The name of the package to install.

    .PARAMETER Path
        The path to the executable to install.

    .EXAMPLE
        xPackage_InstallMsiConfig -PackageName 'Package Name' -Path '\\software\installer.msi'

        Compiles a configuration that installs a package named 'Package Name'
        located in the path '\\software\installer.msi'.
#>
Configuration xPackage_InstallMsiConfig
{
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $PackageName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path
    )

    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    Node localhost
    {
        xPackage 'InstallMsi'
        {
            Ensure    = 'Present'
            Name      = $PackageName
            Path      = $Path
            ProductId = ''
        }
    }
}
