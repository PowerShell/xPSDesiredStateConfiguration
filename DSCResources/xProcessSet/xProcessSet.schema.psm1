Import-Module "$PSScriptRoot\..\ResourceSetHelper.psm1"

Configuration xProcessSet
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Path,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure,

        [System.String]
        $StandardOutputPath,

        [System.String]
        $StandardErrorPath,

        [System.String]
        $StandardInputPath,

        [System.String]
        $WorkingDirectory
    )

    $commonParameterNames = @("Credential", "Ensure", "StandardOutputPath", "StandardErrorPath", "StandardInputPath", "WorkingDirectory")
    $keyParameterName = "Path"
    $resourceName = "xWindowsProcess"

    # Build common parameters for all xWindowsProcess resource nodes
    [string] $commonParameters = New-ResourceCommonParameterString -KeyParameterName $keyParameterName -CommonParameterNames $commonParameterNames -Parameters $PSBoundParameters

    # Arguments is a key parameter in xWindowsProcess resource. Adding it as default parameter with an empty value string
    $defaultParameters = 'Arguments = ""'

    # Build WindowsProcess resource string
    [string] $resourceString = New-ResourceString -KeyParameterValues $PSBoundParameters[$keyParameterName] -KeyParameterName $keyParameterName -CommonParameters $commonParameters -ResourceName $resourceName -DefaultParameters $defaultParameters

    $configurationScript = [ScriptBlock]::Create($resourceString)
    . $configurationScript
}
