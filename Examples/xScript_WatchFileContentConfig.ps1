<#PSScriptInfo
.VERSION 1.0.1
.GUID f9306ebe-8af5-4dee-baf3-f3fac17891db
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
        Configuration that make sure the file exist at the given file path with
        the specified content.

    .DESCRIPTION
        Configuration that creates a file at the given file path with the
        specified content, using the xScript resource.
        If the content of the file is changed, the configuration will update
        the file content to match the content in the configuration.

    .PARAMETER FilePath
        The path at which to create the file.

    .PARAMETER FileContent
        The content to set in the file.

    .EXAMPLE
        xScript_WatchFileContentConfig -FilePath 'C:\test.txt' -FileContent 'Just some sample text to write to the file'

        Compiles a configuration that make sure the is a file 'C:\test.txt' with
        the content 'Just some sample text to write to the file'.
#>
Configuration xScript_WatchFileContentConfig {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, HelpMessage='The path at which to create the file.')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $FilePath,

        [Parameter(Mandatory = $true, HelpMessage='The content to set in the file.')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $FileContent
    )

    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    Node localhost
    {
        xScript ScriptExample
        {
            SetScript  = {
                $streamWriter = New-Object -TypeName 'System.IO.StreamWriter' -ArgumentList @( $using:FilePath )
                $streamWriter.WriteLine($using:FileContent)
                $streamWriter.Close()
            }

            TestScript = {
                if (Test-Path -Path $using:FilePath)
                {
                    $fileContent = Get-Content -Path $using:filePath -Raw
                    return $fileContent -eq $using:FileContent
                }
                else
                {
                    return $false
                }
            }

            GetScript  = {
                $fileContent = $null

                if (Test-Path -Path $using:FilePath)
                {
                    $fileContent = Get-Content -Path $using:filePath -Raw
                }

                return @{
                    Result = $fileContent
                }
            }
        }
    }
}

