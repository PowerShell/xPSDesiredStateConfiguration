param
(
    [Parameter(Mandatory = $true)]
    [System.String]
    $ConfigurationName
)

Configuration $ConfigurationName
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [ValidateNotNull()]
        [System.String]
        $Value = [System.String]::Empty,

        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [System.Boolean]
        $Path = $false,

        [ValidateSet('Process', 'Machine')]
        [System.String[]]
        $Target = ('Process', 'Machine')
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    xEnvironment Environment1
    {
        Name = $Name
        Value = $Value
        Ensure = $Ensure
        Path = $Path
        Target = $Target
    }
}

