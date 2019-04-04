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

    .PARAMETER CreateLog
        Specifies whether a log file should have been created.
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
        $ProcessCount,

        [System.Boolean]
        $CreateLog
    )

    It 'Should call Get-DscConfiguration without throwing and get expected results' {
        { $script:currentConfig = Get-DscConfiguration -ErrorAction 'Stop' } | Should -Not -Throw

        $script:currentConfig.Path | Should -Be $Path
        $script:currentConfig.Arguments | Should -Be $Arguments
        $script:currentConfig.Ensure | Should -Be $Ensure
        $script:currentConfig.ProcessCount | Should -Be $ProcessCount
    }

    if ($CreateLog)
    {
        Test-LogFilePresent -Arguments $Arguments
    }
    else
    {
        Test-LogFileNotPresent -Arguments $Arguments
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

    .PARAMETER LogPresent
        Specifies whether a log file should already be present at Function entry.

    .PARAMETER CreateLog
        Specifies whether a log file should have been created.
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

        [System.Boolean]
        $LogPresent,

        [System.Boolean]
        $CreateLog,

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

        if (!$LogPresent)
        {
            Test-LogFileNotPresent -Arguments $Arguments
        }

        Start-DscConfigurationAndVerify -ConfigFile $configFile -ConfigurationName $configurationName -ConfigurationPath $configurationPath -DscParams $dscParams

        Start-GetDscConfigurationAndVerify -Path $Path -Arguments $Arguments -Ensure 'Present' -ProcessCount 1 -CreateLog $true
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

    .PARAMETER CreateLog
        Specifies whether a log file should have been created.
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

        [System.Boolean]
        $CreateLog,

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

        if (Test-PathSafe -Path $Arguments)
        {
            Remove-Item -Path $Arguments
        }

        Start-DscConfigurationAndVerify -ConfigFile $configFile -ConfigurationName $configurationName -ConfigurationPath $configurationPath -DscParams $dscParams

        Start-GetDscConfigurationAndVerify -Path $Path -Arguments $Arguments -Ensure 'Absent' -ProcessCount $null -CreateLog $false
    }

    Get-Process -Name WindowsProcessTestProcess -ErrorAction SilentlyContinue | Stop-Process -Confirm:$false -Force
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

    .PARAMETER LogPresent
        Specifies whether a log file should already be present at Function entry.

    .PARAMETER CreateLog
        Specifies whether a log file should have been created.
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

        [System.Boolean]
        $LogPresent,

        [System.Boolean]
        $CreateLog,

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

        Test-LogFileNotPresent -Arguments $Arguments

        Start-DscConfigurationAndVerify -ConfigFile $configFile -ConfigurationName $configurationName -ConfigurationPath $configurationPath -DscParams $dscParams

        # Start another instance of the same process using the same credentials.
        $startProcessParams = @{
            FilePath = $Path
        }

        if (!([String]::IsNullOrEmpty($Arguments)))
        {
            $startProcessParams.ArgumentList = @("`"$Arguments`"")
        }
        else
        {
            $startProcessParams.ArgumentList = "''"
        }

        if ($null -ne $Credential)
        {
            $startProcessParams.Add('Credential', $Credential)
        }

        Start-Process @startProcessParams

        # Run Get-DscConfiguration and verify that 2 processes are detected
        Start-GetDscConfigurationAndVerify -Path $Path -Arguments $Arguments -Ensure 'Present' -ProcessCount 2 -CreateLog $true
    }
}

<#
    .SYNOPSIS
        Safely tests whether or not a file Path exist. Returns True if the
        Path exists, or if it is null or empty.

    .PARAMETER Path
        The file Path to safely test for.
#>
function Test-PathSafe
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $Path
    )

    $pathSafe = $false

    if(!([String]::IsNullOrEmpty($Path)))
    {
        try
        {
            $pathSafe = Test-Path -Path $Path
        }
        catch
        {
            Write-Warning -Message 'Test-PathSafe: Caught exception trying to process Path'
        }
    }

    return $pathSafe
}

<#
    .SYNOPSIS
        Tests whether the DSC resource handled the Arguments parameter properly.
        Tests pass if Arguments is null or empty, or if the Path specified in
        Arguments exists.

    .PARAMETER Arguments
        Corresponds to the Arguments parameter of xWindowsProcess.
#>
function Test-LogFilePresent
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $Arguments
    )

    It 'Should create a logfile when Arguments is used' {
        $pathResult = ([String]::IsNullOrEmpty($Arguments)) -or (Test-PathSafe -Path $Arguments)
        $pathResult | Should -Be $true
    }
}

<#
    .SYNOPSIS
        Tests whether the DSC resource handled the Arguments parameter properly.
        Tests pass if Arguments if the Path specified in Arguments do not exist.

    .PARAMETER Arguments
        Corresponds to the Arguments parameter of xWindowsProcess.
#>
function Test-LogFileNotPresent
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $Arguments
    )

    It 'Should not have a logfile present' {
        $pathResult = Test-PathSafe -Path $Arguments
        $pathResult | Should -Be $false
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

        if ($null -ne $Credential -and !([String]::IsNullOrEmpty($Arguments)))
        {
            # Make sure test admin account has permissions on log folder
            Add-PathPermission `
                -Path (Split-Path -Path $Arguments) `
                -IdentityReference $Credential.UserName
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
        Stop-TestProcessUsingDscAndVerify -Path $Path -Arguments $Arguments -Ensure 'Absent' -ProcessCount $null -CreateLog $false -DscParams $dscParams

        # Start test process using DSC.
        Start-TestProcessUsingDscAndVerify -Path $Path -Arguments $Arguments -Ensure 'Present' -ProcessCount 1 -CreateLog $true -DscParams $dscParams

        # Run same config again. Should not start a second new testProcess instance when one is already running.
        Start-TestProcessUsingDscAndVerify -Path $Path -Arguments $Arguments -Ensure 'Present' -ProcessCount 1 -LogPresent $true -CreateLog $false -ContextLabel 'Should detect when multiple process instances are running' -DscParams $dscParams

        # Stop all test process instances and DSC configurations.
        Stop-TestProcessUsingDscAndVerify -Path $Path -Arguments $Arguments -Ensure 'Absent' -ProcessCount $null -CreateLog $false -DscParams $dscParams

        # Start test process using DSC, then start a test process outside of DSC
        Start-AdditionalTestProcessAndVerify -Path $Path -Arguments $Arguments -Ensure 'Absent' -ProcessCount 2 -CreateLog $true -DscParams $dscParams

        # Stop all test process instances and DSC configurations.
        Stop-TestProcessUsingDscAndVerify -Path $Path -Arguments $Arguments -Ensure 'Absent' -ProcessCount $null -CreateLog $false -DscParams $dscParams
    }
}

try
{
    # Setup test folders and files
    $originalTestProcessFolderPath = Split-Path $PSScriptRoot -Parent
    $originalTestProcessPath = Join-Path -Path $originalTestProcessFolderPath -ChildPath 'WindowsProcessTestProcess.exe'

    $folderNoSpaces = Join-Path -Path $env:SystemDrive -ChildPath 'TestNoSpaces'
    $folderWithSpaces = Join-Path -Path $env:SystemDrive -ChildPath 'Test With Spaces'

    $testProcessNoSpaces = Join-Path -Path $folderNoSpaces -ChildPath 'WindowsProcessTestProcess.exe'
    $testLogNoSpaces = Join-Path -Path $folderNoSpaces -ChildPath 'processTestLog.txt'

    $testProcessWithSpaces = Join-Path -Path $folderWithSpaces -ChildPath 'WindowsProcessTestProcess.exe'
    $testLogWithSpaces = Join-Path -Path $folderWithSpaces -ChildPath 'processTestLog.txt'

    if (!(Test-Path -Path $folderNoSpaces))
    {
        mkdir -Path $folderNoSpaces -ErrorAction Stop
    }

    if (!(Test-Path -Path $folderWithSpaces))
    {
        mkdir -Path $folderWithSpaces -ErrorAction Stop
    }

    if (!(Test-Path -Path $testProcessNoSpaces))
    {
        Copy-Item -Path $originalTestProcessPath -Destination $folderNoSpaces -ErrorAction Stop
    }

    if (!(Test-Path -Path $testProcessWithSpaces))
    {
        Copy-Item -Path $originalTestProcessPath -Destination $folderWithSpaces -ErrorAction Stop
    }

    # Setup test combination variables
    $testFolderCombos = @(
        @{
            Description = 'Process Path Without Spaces, No Log'
            Path = $testProcessNoSpaces
            Arguments = ''
        }

        @{
            Description = 'Process Path Without Spaces, Log Path Without Spaces'
            Path = $testProcessNoSpaces
            Arguments = $testLogNoSpaces
        }

        @{
            Description = 'Process Path With Spaces, Log Path Without Spaces'
            Path = $testProcessWithSpaces
            Arguments = $testLogNoSpaces
        }

        @{
            Description = 'Process Path Without Spaces, Log Path With Spaces'
            Path = $testProcessNoSpaces
            Arguments = $testLogWithSpaces
        }

        @{
            Description = 'Process Path With Spaces, Log Path With Spaces'
            Path = $testProcessWithSpaces
            Arguments = $testLogWithSpaces
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
    foreach ($folderCombo in $testFolderCombos)
    {
        foreach ($credentialCombo in $credentialCombos)
        {
            $params = @{
                Path = $folderCombo.Path
                Arguments = $folderCombo.Arguments
                Credential = $credentialCombo.Credential
                ConfigFile = $credentialCombo.ConfigFile
            }

            $params.Add('DescribeLabel', "$($folderCombo.Description), $($credentialCombo.Description)")
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
