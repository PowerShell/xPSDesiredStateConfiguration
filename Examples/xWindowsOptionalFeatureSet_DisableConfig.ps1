<#PSScriptInfo
.VERSION 1.0.1
.GUID 0deebd0b-2e1a-4b4f-a5e7-d8264754fa51
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
        Disables one or more Windows optional features.

    .DESCRIPTION
        Disables one or more Windows optional features with the specified name
        and outputs a log to the specified path.When the optional feature is
        disabled, the files associated with the feature will also be removed.

    .PARAMETER Name
        The name of one or more Windows optional features to disable.

    .PARAMETER LogPath
        The path to the file to log the disable operation to.

    .NOTES
        Can only be run on Windows client operating systems and Windows Server 2012 or later.
        The DISM PowerShell module must be available on the target machine.

    .EXAMPLE
        xWindowsOptionalFeatureSet_DisableConfig -Name @('TelnetClient', 'LegacyComponents') -LogPath 'c:\log\feature.log'

        Compiles a configuration that disables the Windows optional features
        TelnetClient and LegacyComponents and removes all files associated with
        these features. Outputs a log of the operations to a file at the path
        'C:\LogPath\Log.txt'.

    .EXAMPLE
        Start-AzureRmAutomationDscCompilationJob -ResourceGroupName '<resource-group>' -AutomationAccountName '<automation-account>' -ConfigurationName 'xWindowsOptionalFeatureSet_DisableConfig' -Parameters @{ Name = @('TelnetClient', 'LegacyComponents'); LogPath = 'c:\log\feature.log' }

        Compiles a configuration in Azure Automation that that disables the
        Windows optional features TelnetClient and LegacyComponents and removes
        all files associated with these features. Outputs a log of the operations
        to a file at the path 'C:\LogPath\Log.txt'.

        Replace the <resource-group> and <automation-account> with correct values.
#>
Configuration xWindowsOptionalFeatureSet_DisableConfig
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String[]]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $LogPath
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xWindowsOptionalFeatureSet WindowsOptionalFeatureSet1
        {
            Name    = $Name
            Ensure  = 'Absent'
            LogPath = $LogPath
            RemoveFilesOnDisable = $true
        }
    }
}
