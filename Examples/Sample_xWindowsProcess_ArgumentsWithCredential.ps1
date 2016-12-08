Configuration Sample_xWindowsProcess_ArgumentsWithCredential
{
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
        xWindowsProcess PowerShell
        {
            Path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
            Arguments = "-NoExit -File `"C:\testScript.ps1`""
            Credential = $Credential
            Ensure = 'Present'
        }
    }
}
            
# To use the sample(s) with credentials, see blog at http://blogs.msdn.com/b/powershell/archive/2014/01/31/want-to-secure-credentials-in-windows-powershell-desired-state-configuration.aspx
Sample_xWindowsProcess_ArgumentsWithCredential
