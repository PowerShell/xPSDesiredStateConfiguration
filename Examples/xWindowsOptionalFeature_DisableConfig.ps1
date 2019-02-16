<#PSScriptInfo
.VERSION 1.0.1
.GUID 4671e4f7-7ba5-4736-8a29-d439db3d9bb7
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
        Disables a Windows optional feature.

    .DESCRIPTION
        Disables the Windows optional feature with the specified name and outputs
        a log to the specified path. When the optional feature is disabled, the
        files associated with the feature will also be removed.

    .PARAMETER Name
        The name of the Windows optional feature to disable.

    .PARAMETER LogPath
        The path to the file to log the disable operation to.

    .NOTES
        Can only be run on Windows client operating systems and Windows Server 2012
        or later.
        The DISM PowerShell module must be available on the target machine.

    .EXAMPLE
        xWindowsOptionalFeature_DisableConfig -Name 'SMB1Protocol' -LogPath 'c:\log\feature.log'

        Compiles a configuration that ensures that the SMB1Protocol optional
        feature is disabled, and logs the operation to 'C:\log\feature.log'.
#>
Configuration xWindowsOptionalFeature_DisableConfig
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
        xWindowsOptionalFeature 'DisableOptionalFeature'
        {
            Name                 = $Name
            Ensure               = 'Absent'
            LogPath              = $LogPath
            RemoveFilesOnDisable = $true
        }
    }
}
