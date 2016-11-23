<#
    .SYNOPSIS
        Sets the services with the given names to start under the built-in account LocalService.

    .PARAMETER ServiceNames
        The names of the services to set.
#>
Configuration xServiceSetBuiltInAccountExample
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
        Name           = $ServiceNames
        Ensure         = 'Present'
        BuiltInAccount = 'LocalService'
        State          = 'Ignore'
    }
}
