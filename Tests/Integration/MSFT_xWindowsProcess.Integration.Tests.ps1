[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
param ()

<#
    Please note that some of these tests depend on each other.
    They must be run in the order given - if one test fails, subsequent tests may
    also fail.
#>
$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

Import-Module -Name (Join-Path -Path (Split-Path $PSScriptRoot -Parent) `
                               -ChildPath 'CommonTestHelper.psm1') `
                               -Force

if (Test-SkipContinuousIntegrationTask -Type 'Integration')
{
    return
}

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DscResourceModuleName 'xPSDesiredStateConfiguration' `
    -DscResourceName 'MSFT_xWindowsProcess' `
    -TestType 'Integration'

<#
    .SYNOPSIS
        Starts the specified DSC Configuration and verifies that it executes
        without throwing.

    .PARAMETER ConfigFile
        Path to the DSC Config script.

    .PARAMETER ConfigurationName
        The Name of the DSC Configuration.

    .PARAMETER ConfigurationPath
        Path to the Compiled DSC Configuration.

    .PARAMETER DscParams
        Parameters to pass to Start-DscConfiguration.
#>
function Start-DscConfigurationAndVerify
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $ConfigFile,

        [System.String]
        $ConfigurationName,

        [System.String]
        $ConfigurationPath,

        [System.Collections.Hashtable]
        $DscParams
    )

    It 'Should compile without throwing' {
        {
            .$configFile -ConfigurationName $configurationName
            & $configurationName @dscParams
            Start-DscConfiguration -Path $configurationPath -ErrorAction 'Stop' -Wait -Force
        } | Should -Not -Throw
    }
}

<#
    .SYNOPSIS
        Performs common post Set-DscConfiguration tests.

    .PARAMETER Path
        Corresponds to the Path parameter of xWindowsProcess.

    .PARAMETER Arguments
        Corresponds to the Arguments parameter of xWindowsProcess.

    .PARAMETER Ensure
        Corresponds to the Ensure parameter of xWindowsProcess.

    .PARAMETER ProcessCount
        The expected count of running processes for the specified Process.
        Allows Null.
#>
function Start-GetDscConfigurationAndVerify
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $Path,

        [System.String]
        $Arguments,

        [System.String]
        $Ensure,

        [Nullable[System.Int32]]
        $ProcessCount
    )

    It 'Should call Get-DscConfiguration without throwing and get expected results' {
        { $script:currentConfig = Get-DscConfiguration -ErrorAction 'Stop' } | Should -Not -Throw

        $script:currentConfig.Path | Should -Be $Path
        $script:currentConfig.Arguments | Should -Be $Arguments
        $script:currentConfig.Ensure | Should -Be $Ensure
        $script:currentConfig.ProcessCount | Should -Be $ProcessCount
    }
}

<#
    .SYNOPSIS
        Starts the test process using DSC and verifies that it is started.

    .PARAMETER Path
        Corresponds to the Path parameter of xWindowsProcess.

    .PARAMETER Arguments
        Corresponds to the Arguments parameter of xWindowsProcess.

    .PARAMETER Ensure
        Corresponds to the Ensure parameter of xWindowsProcess.

    .PARAMETER ProcessCount
        The expected count of running processes for the specified Process.
        Allows Null.

    .PARAMETER ContextLabel
        The Context label to pass to Pester.

    .PARAMETER DscParams
        Parameters to pass to Start and Get-DscConfiguration.
#>
function Start-TestProcessUsingDscAndVerify
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $Path,

        [System.String]
        $Arguments,

        [System.String]
        $Ensure,

        [Nullable[System.Int32]]
        $ProcessCount,

        [System.String]
        $ContextLabel = 'Should start a new instance of the test process',

        [System.Collections.Hashtable]
        $DscParams
    )

    Context $ContextLabel {
        $configurationName = 'MSFT_xWindowsProcess_StartProcess'
        $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName
        $dscParams.OutputPath = $configurationPath
        $dscParams.Ensure = 'Present'

        Start-DscConfigurationAndVerify `
            -ConfigFile $configFile `
            -ConfigurationName $configurationName `
            -ConfigurationPath $configurationPath `
            -DscParams $dscParams

        Start-GetDscConfigurationAndVerify `
            -Path $Path `
            -Arguments $Arguments `
            -Ensure 'Present' `
            -ProcessCount 1
    }
}

<#
    .SYNOPSIS
        Stops the test process using DSC and verifies that it is stopped.

    .PARAMETER Path
        Corresponds to the Path parameter of xWindowsProcess.

    .PARAMETER Arguments
        Corresponds to the Arguments parameter of xWindowsProcess.

    .PARAMETER Ensure
        Corresponds to the Ensure parameter of xWindowsProcess.

    .PARAMETER ProcessCount
        The expected count of running processes for the specified Process.
        Allows Null.

    .PARAMETER ContextLabel
        The Context label to pass to Pester.

    .PARAMETER DscParams
        Parameters to pass to Start and Get-DscConfiguration.
#>
function Stop-TestProcessUsingDscAndVerify
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $Path,

        [System.String]
        $Arguments,

        [System.String]
        $Ensure,

        [Nullable[System.Int32]]
        $ProcessCount,

        [System.String]
        $ContextLabel = 'Should stop all instances of the test process',

        [System.Collections.Hashtable]
        $DscParams
    )

    Context $ContextLabel {
        $configurationName = 'MSFT_xWindowsProcess_StopAllProcesses'
        $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName
        $dscParams.OutputPath = $configurationPath
        $dscParams.Ensure = 'Absent'

        Start-DscConfigurationAndVerify `
            -ConfigFile $configFile `
            -ConfigurationName $configurationName `
            -ConfigurationPath $configurationPath `
            -DscParams $dscParams

        Start-GetDscConfigurationAndVerify `
            -Path $Path `
            -Arguments $Arguments `
            -Ensure 'Absent' `
            -ProcessCount $null
    }

    # Force a stop on any running test processes just in case they failed to stop via DSC
    Get-Process | Where-Object -FilterScript {$_.Path -like $Path} | `
        Stop-Process -Confirm:$false -Force
}

<#
    .SYNOPSIS
        Starts two instances of the test process, one using DSC, and one manually,
        and tests whether Get-DscConfiguration returns the right number of
        processes.

    .PARAMETER Path
        Corresponds to the Path parameter of xWindowsProcess.

    .PARAMETER Arguments
        Corresponds to the Arguments parameter of xWindowsProcess.

    .PARAMETER Ensure
        Corresponds to the Ensure parameter of xWindowsProcess.

    .PARAMETER ProcessCount
        The expected count of running processes for the specified Process.
        Allows Null.

    .PARAMETER ContextLabel
        The Context label to pass to Pester.

    .PARAMETER DscParams
        Parameters to pass to Start and Get-DscConfiguration.
#>
function Start-AdditionalTestProcessAndVerify
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $Path,

        [System.String]
        $Arguments,

        [System.String]
        $Ensure,

        [Nullable[System.Int32]]
        $ProcessCount,

        [System.String]
        $ContextLabel = 'Should return the correct amount of processes when more than 1 are running',

        [System.Collections.Hashtable]
        $DscParams
    )

    Context $ContextLabel {
        $configurationName = 'MSFT_xWindowsProcess_CheckForMultipleProcesses'
        $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName
        $dscParams.OutputPath = $configurationPath
        $dscParams.Ensure = 'Present'

        Start-DscConfigurationAndVerify `
            -ConfigFile $configFile `
            -ConfigurationName $configurationName `
            -ConfigurationPath $configurationPath `
            -DscParams $dscParams

        # Start another instance of the same process using the same credentials.
        $startProcessParams = @{
            FilePath = $Path
        }

        if (!([String]::IsNullOrEmpty($Arguments)))
        {
            $startProcessParams.ArgumentList = @("`"$Arguments`"")
        }

        if ($null -ne $Credential)
        {
            $startProcessParams.Add('Credential', $Credential)
        }

        Start-Process @startProcessParams

        # Run Get-DscConfiguration and verify that 2 processes are detected
        Start-GetDscConfigurationAndVerify `
            -Path $Path `
            -Arguments $Arguments `
            -Ensure 'Present' `
            -ProcessCount 2
    }
}

<#
    .SYNOPSIS
        Performs commmon sets of tests using
        Start, Get, Set, and Test - DscConfiguration.

    .PARAMETER Path
        Corresponds to the Path parameter of xWindowsProcess.

    .PARAMETER Arguments
        Corresponds to the Arguments parameter of xWindowsProcess.

    .PARAMETER ConfigFile
        Path to the DSC Configuration script.

    .PARAMETER Credential
        Corresponds to the Credential parameter of xWindowsProcess.
#>
function Invoke-CommonResourceTesting
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DescribeLabel,

        [System.String]
        $Path,

        [System.String]
        $Arguments,

        [System.String]
        $ConfigFile,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    Describe $DescribeLabel {
        $ConfigData = @{
            AllNodes = @(
                @{
                    NodeName = '*'
                    PSDscAllowPlainTextPassword = $true
                }
                @{
                    NodeName = 'localhost'
                }
            )
        }

        $dscParams = @{
            Path = $Path
            Arguments = $Arguments
            Ensure = 'Present'
            ErrorAction = 'Stop'
            OutputPath = ''
            ConfigurationData = $ConfigData
        }

        if ($null -ne $Credential)
        {
            $dscParams.Add('Credential', $Credential)
        }

        # Stop all test process instances and DSC configurations.
        Stop-TestProcessUsingDscAndVerify `
            -Path $Path `
            -Arguments $Arguments `
            -Ensure 'Absent' `
            -ProcessCount $null `
            -DscParams $dscParams

        # Start test process using DSC.
        Start-TestProcessUsingDscAndVerify `
            -Path $Path `
            -Arguments $Arguments `
            -Ensure 'Present' `
            -ProcessCount 1 `
            -DscParams $dscParams

        # Run same config again. Should not start a second new test Process instance when one is already running.
        Start-TestProcessUsingDscAndVerify `
            -Path $Path `
            -Arguments $Arguments `
            -Ensure 'Present' `
            -ProcessCount 1 `
            -ContextLabel 'Should detect when multiple process instances are running' `
            -DscParams $dscParams

        # Stop all test process instances and DSC configurations.
        Stop-TestProcessUsingDscAndVerify `
            -Path $Path `
            -Arguments $Arguments `
            -Ensure 'Absent' `
            -ProcessCount $null `
            -DscParams $dscParams

        # Start test process using DSC, then start a test process outside of DSC
        Start-AdditionalTestProcessAndVerify `
            -Path $Path `
            -Arguments $Arguments `
            -Ensure 'Absent' `
            -ProcessCount 2 `
            -DscParams $dscParams

        # Stop all test process instances and DSC configurations.
        Stop-TestProcessUsingDscAndVerify `
            -Path $Path `
            -Arguments $Arguments `
            -Ensure 'Absent' `
            -ProcessCount $null `
            -DscParams $dscParams
    }
}

try
{
    # Setup test process paths.
    $system32Path = Join-Path -Path $env:SystemRoot -ChildPath System32
    $notepadExePath = Join-Path -Path $system32Path -ChildPath notepad.exe -Resolve
    $powershellExePath = Join-Path -Path (Join-Path -Path (Join-Path -Path $system32Path -ChildPath WindowsPowerShell) -ChildPath v1.0) -ChildPath powershell.exe -Resolve
    $iexplorerExePath = Join-Path -Path (Join-Path -Path $env:ProgramFiles -ChildPath 'internet explorer') -ChildPath iexplore.exe -Resolve

    # Setup test combination variables
    $testPathAndArgsCombos = @(
        @{
            Description = 'Process Path Without Spaces, No Arguments'
            Path = $notepadExePath
            Arguments = ''
        }

        @{
            Description = 'Process Path With Spaces, No Arguments'
            Path = $iexplorerExePath
            Arguments = ''
        }

        @{
            Description = 'Process Path Without Spaces, Arguments Without Spaces'
            Path = $powershellExePath
            Arguments = "30|Start-Sleep"
        }

        @{
            Description = 'Process Path With Spaces, Arguments Without Spaces'
            Path = $iexplorerExePath
            Arguments = 'https://github.com/PowerShell/xPSDesiredStateConfiguration'
        }

        @{
            Description = 'Process Path Without Spaces, Arguments With Spaces'
            Path = $powershellExePath
            Arguments = "Start-Sleep -Seconds 30"
        }

        @{
            Description = 'Process Path With Spaces, Arguments With Spaces'
            Path = $iexplorerExePath
            Arguments = "https://github.com/PowerShell/xPSDesiredStateConfiguration with spaces"
        }
    )

    $credentialCombos = @(
        @{
            Description = 'No Credentials'
            Credential = $null
            ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath 'MSFT_xWindowsProcess.config.ps1'
        }

        @{
            Description = 'With Credentials'
            Credential = Get-TestAdministratorAccountCredential
            ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath 'MSFT_xWindowsProcessWithCredential.config.ps1'
        }
    )

    # Perform tests on each variable combination
    foreach ($pathAndArgsCombo in $testPathAndArgsCombos)
    {
        foreach ($credentialCombo in $credentialCombos)
        {
            $params = @{
                Path = $pathAndArgsCombo.Path
                Arguments = $pathAndArgsCombo.Arguments
                Credential = $credentialCombo.Credential
                ConfigFile = $credentialCombo.ConfigFile
            }

            $params.Add('DescribeLabel', "$($pathAndArgsCombo.Description), $($credentialCombo.Description)")
            $params.Remove('FolderDescription')
            $params.Remove('CredentialDescription')

            Invoke-CommonResourceTesting @params
        }
    }
}
finally
{
    Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
}
