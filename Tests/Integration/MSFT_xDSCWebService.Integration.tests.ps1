$script:dscModuleName = 'xPSDesiredStateConfiguration'
$script:dscResourceFriendlyName = 'xDSCWebService'
$script:dcsResourceName = "MSFT_$($script:dscResourceFriendlyName)"

#region HEADER
# Integration Test Template Version: 1.3.1
[String] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
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

[System.String] $tempFolderName = 'xDSCWebServiceTests_' + (Get-Date).ToString("yyyyMMdd_HHmmss")

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

    It 'Should create a web site to host the DSC Pull Server' {
        (Get-ChildItem -Path IIS:\sites | Where-Object -Property Name -Match "^$($ConfigurationData.AllNodes.EndpointName)").Count | Should -Be 1
    }

    It 'Should create a web.config file at the web site root' {
        Test-Path -Path (Join-Path -Path $ConfigurationData.AllNodes.PhysicalPath -ChildPath 'web.config') | Should -Be $true
    }

    It 'Should create a firewall rule for the chosen port' {
        (Get-NetFirewallRule | Where-Object -FilterScript {$_.DisplayName -eq 'DSCPullServer_IIS_Port'} | Measure-Object).Count | Should -Be 1
    }
}
#endregion

# Make sure the DSC-Service and Web-Server features are installed
if (!(Install-WindowsFeatureAndVerify -Name 'DSC-Service') -or 
    !(Install-WindowsFeatureAndVerify -Name 'Web-Server'))
{
    Write-Verbose -Message 'Skipping xDSCWebService Integration tests.' -Verbose
    return
}

# Make sure the w3svc is running before proceeding with tests
if ((Get-Service -Name w3svc).Status -ne 'Running')
{
    Start-Service -Name w3svc -ErrorAction Stop
}

# Using try/finally to always cleanup.
try
{
    #region Integration Tests
    $configurationFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:dcsResourceName).config.ps1"
    . $configurationFile

    # Backup the existing web configuration before making any changes
    Backup-WebConfiguration -Name $tempFolderName

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

    # Roll back our IIS changes
    Restore-WebConfiguration -Name $tempFolderName
    Remove-WebConfigurationBackup -Name $tempFolderName

    # Remove any temp files
    Get-ChildItem -Path $ENV:TEMP -Filter $tempFolderName | Remove-Item -Recurse -Force

    # Remove firewall port created by module
    Get-NetFirewallRule | Where-Object -FilterScript {$_.DisplayName -eq 'DSCPullServer_IIS_Port'}  | Remove-NetFirewallRule
}
