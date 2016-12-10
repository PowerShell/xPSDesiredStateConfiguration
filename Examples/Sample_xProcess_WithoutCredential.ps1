<#
    .SYNOPSIS
        Starts the gpresult process which generates a log about the group policy.
#>
Configuration Sample_xProcess_WithoutCredential
{
    param
    ()

    Import-DSCResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xProcess GPresult
        {
            Path = 'C:\Windows\System32\gpresult.exe'
            Arguments = '/h C:\gp2.htm'
            Ensure = 'Present'
        }
    }
}

Sample_xProcess_WithoutCredential

