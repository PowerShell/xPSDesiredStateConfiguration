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
        [System.String[]]
        $Name,

        [ValidateSet('Present', 'Absent')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [ValidateSet('Running', 'Stopped', 'Ignore')]
        [System.String]
        $State = 'Running',

        [ValidateSet('Automatic', 'Manual', 'Disabled')]
        [System.String]
        $StartupType = 'Automatic'
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xServiceSet ServiceSet1
        {
            Name        = $Name
            Ensure      = $Ensure
            Credential  = $Credential
            State       = $State
            StartupType = $StartupType
        }
    }
}
