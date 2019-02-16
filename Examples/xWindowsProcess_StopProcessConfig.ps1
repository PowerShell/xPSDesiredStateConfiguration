<#PSScriptInfo
.VERSION 1.0.1
.GUID 6ee000de-f0c1-4aca-8423-33d35d3288e1
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
        Configuration that stops a process.

    .DESCRIPTION
        Configuration that stops the process that is provided in the given file
        path, where the argument matches, and if the process is running.

    .PARAMETER FilePath
        The path to the executable file to (process) to stop.

    .PARAMETER Argument
        The arguments for the process to stop. Defaults to no argument.

    .NOTES
        The FilePath could be set to just the process name only if the number of
        returned processed is less than or equal to 8. If more than 8 processes
        are returned, another filter is used to optimize performance, and that
        filter needs the full path to the executable file.

    .EXAMPLE
        xWindowsProcess_StopProcessConfig -FilePath 'C:\WINDOWS\system32\PING.EXE' -Argument '-t localhost'

        Compiles a configuration that stops a 'ping' process if the process exist.
#>
Configuration xWindowsProcess_StopProcessConfig
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
        $Argument
    )

    Import-DSCResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xWindowsProcess 'StopProcess'
        {
            Path      = $FilePath
            Arguments = $Argument
            Ensure    = 'Absent'
        }
    }
}
