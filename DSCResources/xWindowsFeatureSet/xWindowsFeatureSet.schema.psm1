Set-StrictMode -Version 'latest'
$errorActionPreference = 'stop'

Import-Module -Name (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'ResourceSetHelper.psm1')

Configuration xWindowsFeatureSet
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Name,

        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure,

        [ValidateNotNullOrEmpty()]
        [String]
        $Source,

        [Boolean]
        $IncludeAllSubFeature,

        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [ValidateNotNullOrEmpty()]
        [String]
        $LogPath
    )

    $newResourceSetConfigurationParams = @{
        ResourceName = 'xWindowsFeature'
        KeyParameterName = 'Name'
        CommonParameterNames = @( 'Ensure', 'Source', 'IncludeAllSubFeature', 'Credential', 'LogPath' )
        Parameters = $PSBoundParameters
    }
    
    $configurationScriptBlock = New-ResourceSetConfigurationScriptBlock @newResourceSetConfigurationParams

    # This script block must be run directly in this configuration in order to resolve variables
    . $configurationScriptBlock
}
