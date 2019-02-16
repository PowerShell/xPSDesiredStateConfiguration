Import-Module -Name (Join-Path -Path (Split-Path $PSScriptRoot -Parent) `
                               -ChildPath 'CommonTestHelper.psm1')

$script:DSCModuleName      = 'xPSDesiredStateConfiguration' # Example xNetworking
$script:DSCResourceName    = 'MSFT_xRemoteFile' # Example MSFT_xFirewall

if (Test-SkipContinuousIntegrationTask -Type 'Integration')
{
    return
}

#region HEADER
# Integration Test Template Version: 1.1.0
[System.String] $moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))
if ( (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:DSCModuleName `
    -DSCResourceName $script:DSCResourceName `
    -TestType Integration
#endregion

# Using try/finally to always cleanup even if something awful happens.
try
{
    #region Integration Tests
    $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:DSCResourceName).config.ps1"
    . $ConfigFile

    # Make sure the file to download doesn't exist
    Remove-Item -Path $TestDestinationPath -Force -ErrorAction SilentlyContinue

    Describe "$($script:DSCResourceName)_Integration" {
        #region DEFAULT TESTS
        It 'Should compile without throwing' {
            {
                Invoke-Expression -Command "$($script:DSCResourceName)_Config -OutputPath `$TestDrive"
                Start-DscConfiguration -Path $TestDrive `
                    -ComputerName localhost -Wait -Verbose -Force
            } | Should not throw
        }

        It 'should be able to call Get-DscConfiguration without throwing' {
            { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not throw
        }
        #endregion

        It 'Should have set the resource and all the parameters should match' {
            $Result = Get-DscConfiguration
            $Result.Ensure          | Should Be 'Present'
            $Result.Uri             | Should Be $TestURI
            $Result.DestinationPath | Should Be $TestDestinationPath
        }
        It 'The Downloaded content should match the source content' {
            $DownloadedContent = Get-Content -Path $TestDestinationPath -Raw
            $ExistingContent = Get-Content -Path $TestConfigPath -Raw
            $DownloadedContent | Should Be $ExistingContent
        }
    }
    #endregion

}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion

    # Clean up
    Remove-Item -Path $TestDestinationPath -Force -ErrorAction SilentlyContinue
}
