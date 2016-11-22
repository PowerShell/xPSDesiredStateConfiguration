Set-StrictMode -Version 'latest'
$errorActionPreference = 'stop'

Import-Module -Name (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'ResourceSetHelper.psm1')

Configuration xServiceSet
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Name,

        [ValidateSet('Automatic', 'Manual', 'Disabled')]
        [String]
        $StartupType,

        [ValidateSet('LocalSystem', 'LocalService', 'NetworkService')]
        [String]
        $BuiltInAccount,

        [ValidateSet('Running', 'Stopped')]
        [String]
        $State,

        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure,

        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    $newResourceSetConfigurationParams = @{
        ResourceName = 'xService'
        ModuleName = 'xPSDesiredStateConfiguration'
        KeyParameterName = 'Name'
        Parameters = $PSBoundParameters
    }
    
    $configurationScriptBlock = New-ResourceSetConfigurationScriptBlock @newResourceSetConfigurationParams

    # This script block must be run directly in this configuration in order to resolve variables
    . $configurationScriptBlock
}
