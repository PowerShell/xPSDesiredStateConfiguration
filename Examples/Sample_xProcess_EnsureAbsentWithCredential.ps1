<#
    .SYNOPSIS
        Stops the gpresult process running under the given credential

    .PARAMETER Credential
        Credential to stop the process
#>
Configuration Sample_xProcess_EnsureAbsentWithCredential
{
    [CmdletBinding()]
    param
    (
       [ValidateNotNullOrEmpty()]
       [System.Management.Automation.PSCredential]
       [System.Management.Automation.Credential()]
       $Credential = (Get-Credential)
    )
    Import-DSCResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xProcess GPresult
        {
            Path = 'C:\Windows\System32\gpresult.exe'
            Arguments = '/h C:\gp2.htm'
            Credential = $Credential
            Ensure = 'Absent'
        }
    }
}
            
<#           
    To use the sample(s) with credentials, see blog at:
    http://blogs.msdn.com/b/powershell/archive/2014/01/31/want-to-secure-credentials-in-windows-powershell-desired-state-configuration.aspx
#>


