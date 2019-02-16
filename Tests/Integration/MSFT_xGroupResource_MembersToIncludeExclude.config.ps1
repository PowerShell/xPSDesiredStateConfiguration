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
        $GroupName,

        [ValidateSet('Present', 'Absent')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Ensure = 'Present',

        [System.String[]]
        $MembersToInclude = @(),

        [System.String[]]
        $MembersToExclude = @()
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    xGroup Group2
    {
        GroupName = $GroupName
        Ensure = $Ensure
        MembersToInclude = $MembersToInclude
        MembersToExclude = $MembersToExclude
    }
}
