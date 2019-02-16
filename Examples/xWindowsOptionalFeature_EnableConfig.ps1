<#PSScriptInfo
.VERSION 1.0.1
.GUID 6fca965e-e3a2-4108-8385-d14bf2c4f0dc
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
        Enables a Windows optional feature.

    .DESCRIPTION
        Enables the Windows optional feature with the specified name and outputs
        a log to the specified path.

    .PARAMETER Name
        The name of the Windows optional feature to enable.

    .PARAMETER LogPath
        The path to the file to log the enable operation to.

    .NOTES
        Can only be run on Windows client operating systems and Windows Server 2012
        or later.
        The DISM PowerShell module must be available on the target machine.

    .EXAMPLE
        xWindowsOptionalFeature_EnableConfig -Name 'TelnetClient' -LogPath 'c:\log\feature.log'

        Compiles a configuration that ensures that the Telnet Client optional
        feature is enabled, and logs the operation to 'C:\log\feature.log'.
#>
Configuration xWindowsOptionalFeature_EnableConfig
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $LogPath
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xWindowsOptionalFeature 'EnableOptionalFeature'
        {
            Name    = $Name
            Ensure  = 'Present'
            LogPath = $LogPath
        }
    }
}
