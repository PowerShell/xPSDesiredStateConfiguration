Set-StrictMode -Version 'latest'
$errorActionPreference = 'stop'

Import-Module -Name (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'ResourceSetHelper.psm1')

Configuration xProcessSet
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure,

        [String]
        $StandardOutputPath,

        [String]
        $StandardErrorPath,

        [String]
        $StandardInputPath,

        [String]
        $WorkingDirectory
    )
    
    $newResourceSetConfigurationParams = @{
        ResourceName = 'xWindowsProcess'
        KeyParameterName = 'Path'
        CommonParameterNames = @( 'Credential', 'Ensure', 'StandardOutputPath', 'StandardErrorPath', 'StandardInputPath', 'WorkingDirectory', 'Arguments' )
        Parameters = $PSBoundParameters
    }

    # Arguments is a key parameter in xProcess resource. Adding it as a common parameter with an empty value string
    $newResourceSetConfigurationParams['Parameters']['Arguments'] = ''
    
    $configurationScriptBlock = New-ResourceSetConfigurationScriptBlock @newResourceSetConfigurationParams

    # This script block must be run directly in this configuration in order to resolve variables
    . $configurationScriptBlock
}
