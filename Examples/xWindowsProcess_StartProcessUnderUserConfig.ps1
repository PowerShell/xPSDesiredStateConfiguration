<#PSScriptInfo
.VERSION 1.0.1
.GUID 1bea33c0-38a6-4332-82b9-e1a1d40b56dc
.AUTHOR Microsoft Corporation
.COMPANYNAME Microsoft Corporation
.COPYRIGHT
.TAGS DSCConfiguration
.LICENSEURI https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/master/LICENSE
.PROJECTURI https://github.com/PowerShell/xPSDesiredStateConfiguration
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module @{ModuleName = 'xPSDesiredStateConfiguration';ModuleVersion = '8.2.0.0'}

<#
    .SYNOPSIS
        Configuration that starts a process under the given credential.

    .DESCRIPTION
        Configuration that starts a process under the given credential, that is
        provided in the given file path with the specified arguments.

    .PARAMETER FilePath
        The path to the executable file to start.

    .PARAMETER Argument
        The arguments for the process to start. Defaults to no argument.

    .PARAMETER Credential
        Credential to start the process under.

    .NOTES
        To use the sample(s) with credentials, see blog at:
        http://blogs.msdn.com/b/powershell/archive/2014/01/31/want-to-secure-credentials-in-windows-powershell-desired-state-configuration.aspx

    .EXAMPLE
        xWindowsProcess_StartProcessUnderUserConfig -FilePath 'C:\WINDOWS\system32\PING.EXE' -Argument '-t localhost' -Credential (Get-Credential)

        Compiles a configuration that starts a 'ping' process under the given
        credential, that continuously ping localhost, and monitors that the
        process 'ping' is always started.
#>
Configuration xWindowsProcess_StartProcessUnderUserConfig
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $FilePath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Argument,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    Import-DSCResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xUser 'CreateUserAccount'
        {
            Ensure   = 'Present'
            UserName = Split-Path -Path $Credential.UserName -Leaf
            Password = $Credential
        }

        xWindowsProcess 'StartProcessUnderUser'
        {
            Path       = $FilePath
            Arguments  = $Argument
            Credential = $Credential
            Ensure     = 'Present'
        }
    }
}
