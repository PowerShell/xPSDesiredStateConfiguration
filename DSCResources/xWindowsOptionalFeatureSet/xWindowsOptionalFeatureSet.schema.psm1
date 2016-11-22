Set-StrictMode -Version 'latest'
$errorActionPreference = 'stop'

Import-Module -Name (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'ResourceSetHelper.psm1')

Configuration xWindowsOptionalFeatureSet
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure,

        [Boolean]
        $RemoveFilesOnDisable,

        [ValidateNotNullOrEmpty()]
        [String]
        $LogPath,

        [Boolean]
        $NoWindowsUpdateCheck,

        [ValidateSet('ErrorsOnly', 'ErrorsAndWarning', 'ErrorsAndWarningAndInformation')]
        [String]
        $LogLevel
    )

    $newResourceSetConfigurationParams = @{
        ResourceName = 'xWindowsOptionalFeature'
        ModuleName = 'xPSDesiredStateConfiguration'
        KeyParameterName = 'Name'
        Parameters = $PSBoundParameters
    }
    
    $configurationScriptBlock = New-ResourceSetConfigurationScriptBlock @newResourceSetConfigurationParams

    # This script block must be run directly in this configuration in order to resolve variables
    . $configurationScriptBlock
}
