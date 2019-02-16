$script:dscModuleName = 'xPSDesiredStateConfiguration'
$script:dscResourceFriendlyName = 'xDSCWebService'
$script:dcsResourceName = "MSFT_$($script:dscResourceFriendlyName)"

#region HEADER
# Integration Test Template Version: 1.3.1
[System.String] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath 'DscResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:dscModuleName `
    -DSCResourceName $script:dcsResourceName `
    -TestType Integration

Import-Module -Name (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'CommonTestHelper.psm1')

if (Test-SkipContinuousIntegrationTask -Type 'Integration')
{
    return
}

<#
    .SYNOPSIS
        Performs common DSC integration tests including compiling, setting,
        testing, and getting a configuration.

    .PARAMETER ConfigurationName
        The name of the configuration being executed.
#>
function Invoke-CommonResourceTesting
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ConfigurationName
    )

    It 'Should compile and apply the MOF without throwing' {
        {
            $configurationParameters = @{
                OutputPath           = $TestDrive
                ConfigurationData    = $ConfigurationData
            }

            & $configurationName @configurationParameters

            $startDscConfigurationParameters = @{
                Path         = $TestDrive
                ComputerName = 'localhost'
                Wait         = $true
                Verbose      = $true
                Force        = $true
                ErrorAction  = 'Stop'
            }

            Start-DscConfiguration @startDscConfigurationParameters
        } | Should -Not -Throw
    }

    It 'Should be able to call Get-DscConfiguration without throwing' {
        {
            $script:currentConfiguration = Get-DscConfiguration -Verbose -ErrorAction Stop
        } | Should -Not -Throw
    }

    It 'Should return $true when Test-DscConfiguration is run' {
        Test-DscConfiguration -Verbose | Should -Be $true
    }
}

<#
    .SYNOPSIS
        Performs common tests to ensure that the DSC pull server was properly
        installed.
#>
function Test-DSCPullServerIsPresent
{
    [CmdletBinding()]
    param
    (
    )

    It 'Should create a web.config file at the web site root' {
        Test-Path -Path (Join-Path -Path $ConfigurationData.AllNodes.PhysicalPath -ChildPath 'web.config') | Should -Be $true
    }

    It 'Should create a firewall rule for the chosen port' {
        (Get-NetFirewallRule | Where-Object -FilterScript {
            $_.DisplayName -eq 'DSCPullServer_IIS_Port'
        } | Measure-Object).Count | Should -Be 1
    }
}
#endregion

# Using try/finally to always cleanup.
try
{
    # Make sure the DSC-Service and Web-Server Windows features are installed
    if (!(Install-WindowsFeatureAndVerify -Name 'DSC-Service') -or
        !(Install-WindowsFeatureAndVerify -Name 'Web-Server'))
    {
        Write-Verbose -Message 'Skipping xDSCWebService Integration tests due to missing Windows Features.' -Verbose
        return
    }

    # Make sure the w3svc is running before proceeding with tests
    Start-Service -Name w3svc -ErrorAction Stop

    #region Integration Tests
    $configurationFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:dcsResourceName).config.ps1"
    . $configurationFile

    Describe "$($script:dcsResourceName)_Integration" {
        $ensureAbsentConfigurationName = 'MSFT_xDSCWebService_PullTestRemoval_Config'

        $ensurePresentConfigurationNames = @(
            'MSFT_xDSCWebService_PullTestWithSecurityBestPractices_Config',
            'MSFT_xDSCWebService_PullTestWithoutSecurityBestPractices_Config'
        )

        foreach ($configurationName in $ensurePresentConfigurationNames)
        {
            Context ('When using configuration {0}' -f $configurationName) {
                BeforeAll {
                    Invoke-CommonResourceTesting -ConfigurationName $ensureAbsentConfigurationName
                }

                AfterAll {
                    Invoke-CommonResourceTesting -ConfigurationName $ensureAbsentConfigurationName
                }

                Invoke-CommonResourceTesting -ConfigurationName $configurationName

                Test-DSCPullServerIsPresent
            }
        }
    }
    #endregion

}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}
