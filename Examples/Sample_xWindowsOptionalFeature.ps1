# Installs the Windows optional feature 'TelnetClient'

Configuration Sample_xWindowsOptionalFeature
{
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $LogPath
    )

    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    xWindowsOptionalFeature TelnetClient
    {
        Name = 'TelnetClient'
        Ensure = 'Present'
        LogPath = $LogPath
    }
}

Sample_xWindowsOptionalFeature
