<#
    .SYNOPSIS
        Stops the gpresult process.
#>
Configuration Sample_xWindowsProcess_EnsureAbsent
{
    param
    ()

    Import-DSCResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xWindowsProcess GPresult
        {
            Path = 'C:\Windows\System32\gpresult.exe'
            Arguments = '/h C:\gp2.htm'
            Ensure = 'Absent'
        }
    }
}
 
Sample_xProcess_EnsureAbsent

