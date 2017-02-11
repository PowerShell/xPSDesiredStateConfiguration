param
(
    [Parameter(Mandatory = $true)]
    [String]
    $ConfigurationName
)

Configuration $ConfigurationName
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Destination,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure = 'Present',

        [Parameter()]
        [Boolean]
        $Validate = $false,

        [Parameter()]
        [String]
        $Checksum = 'SHA-256',

        [Parameter()]
        [Boolean]
        $Force = $false
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xArchive Archive1
        {
            Path = $Path
            Destination = $Destination
            Ensure = $Ensure
            Validate = $Validate
            Checksum = $Checksum
            Force = $Force
        }
    }
}
