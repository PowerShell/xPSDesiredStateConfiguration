Set-StrictMode -Version 'latest'
$errorActionPreference = 'stop'

Import-Module -Name (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'CommonTestHelper.psm1')

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DscResourceModuleName 'xPSDesiredStateConfiguration' `
    -DscResourceName 'xWindowsFeatureSet' `
    -TestType 'Integration'

Describe "xWindowsFeatureSet Integration Tests" {
    It "Prepare to install a set of Windows features with their sub features" {
        $configurationName = "PrepareInstallWithSubFeatures"
        $configurationPath = Join-Path -Path (Get-Location) -ChildPath $configurationName
        $logPath = Join-Path -Path (Get-Location) -ChildPath "TestLogs"
        $featureNames = @("Test1", "SubTest3")

        try
        {
            Configuration $configurationName
            {
                Import-DscResource -ModuleName xPSDesiredStateConfiguration

                xWindowsFeatureSet xWindowsFeatureSet1
                {
                    Name = $featureNames
                    Ensure = "Present"
                    IncludeAllSubFeature = $true
                    LogPath = $logPath
                }
            }

            # Ensure that the configuration compiles correctly
            { & $configurationName -OutputPath $configurationPath } | Should Not Throw

            # This call will not actually work since we are not on a server and these are not real features
            { Start-DscConfiguration -Path $configurationPath -ErrorAction SilentlyContinue } | Should Not Throw
        }
        finally
        {
            if (Test-Path -Path $logPath)
            {
                Remove-Item -Path $logPath -Recurse -Force
            }

            if (Test-Path -Path $configurationPath)
            {
                Remove-Item -Path $configurationPath -Recurse -Force
            }
        }
    }
}
