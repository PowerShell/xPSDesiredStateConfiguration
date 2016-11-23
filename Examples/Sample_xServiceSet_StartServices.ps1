<#
    .SYNOPSIS
        Starts the services with the given names.

    .PARAMETER ServiceNames
        The names of the services to start.
#>
Configuration xServiceSetStartExample
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String[]]
        $ServiceNames
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    xServiceSet ServiceSet1
    {
        Name   = $ServiceNames
        Ensure = 'Present'
        State  = 'Running'
    }
}
