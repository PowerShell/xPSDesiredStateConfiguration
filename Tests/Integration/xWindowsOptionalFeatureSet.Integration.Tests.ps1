Set-StrictMode -Version 'latest'
$errorActionPreference = 'stop'

Import-Module -Name (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'CommonTestHelper.psm1')

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DscResourceModuleName 'xPSDesiredStateConfiguration' `
    -DscResourceName 'xWindowsOptionalFeatureSet' `
    -TestType 'Integration'

try
{
    Describe "xWindowsOptionalFeatureSet Integration Tests" {
        It "Should install two valid Windows optional features" {
            $configurationName = "InstallOptionalFeature"
            $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName
            $logPath = Join-Path -Path $TestDrive -ChildPath 'InstallOptionalFeature.log'

            $validFeatureName1 = 'MicrosoftWindowsPowerShellV2'
            $validFeatureName2 = 'Internet-Explorer-Optional-amd64'

            $originalFeature1 = Dism\Get-WindowsOptionalFeature -Online -FeatureName $validFeatureName1
            $originalFeature2 = Dism\Get-WindowsOptionalFeature -Online -FeatureName $validFeatureName2

            try
            {
                Configuration $configurationName
                {
                    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

                    xWindowsOptionalFeatureSet xWindowsOptionalFeatureSet1
                    {
                        Name = @($validFeatureName1, $validFeatureName2)
                        Ensure = 'Present'
                        LogPath = $logPath
                        NoWindowsUpdateCheck = $true
                    }
                }

                { & $configurationName -OutputPath $configurationPath } | Should Not Throw

                { Start-DscConfiguration -Path $configurationPath -Wait -Force -Verbose } | Should Not Throw

                $windowsOptionalFeature1 = Dism\Get-WindowsOptionalFeature -Online -FeatureName $validFeatureName1

                $windowsOptionalFeature1 | Should Not Be $null
                $windowsOptionalFeature1.State -eq 'Enabled' -or $windowsOptionalFeature1.State -eq 'EnablePending' | Should Be $true

                $windowsOptionalFeature2 = Dism\Get-WindowsOptionalFeature -Online -FeatureName $validFeatureName2

                $windowsOptionalFeature2 | Should Not Be $null
                $windowsOptionalFeature2.State -eq 'Enabled' -or $windowsOptionalFeature2.State -eq 'EnablePending' | Should Be $true
            }
            finally
            {
                if ($originalFeature1.State -eq 'Disabled' -or $originalFeature1.State -eq 'DisablePending')
                {
                    Dism\Disable-WindowsOptionalFeature -Online -FeatureName $validFeatureName1 -NoRestart
                }

                if ($originalFeature2.State -eq 'Disabled' -or $originalFeature2.State -eq 'DisablePending')
                {
                    Dism\Disable-WindowsOptionalFeature -Online -FeatureName $validFeatureName2 -NoRestart
                }

                if (Test-Path -Path $logPath) {
                    Remove-Item -Path $logPath -Recurse -Force
                }

                if (Test-Path -Path $configurationPath)
                {
                    Remove-Item -Path $configurationPath -Recurse -Force
                }
            }
        }

        It "Should not install an incorrect Windows optional feature" {
            $configurationName = "InstallIncorrectWindowsFeature"
            $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName
            $logPath = Join-Path -Path $TestDrive -ChildPath 'InstallIncorrectWindowsFeature.log'

            try
            {
                Configuration $configurationName
                {
                    Import-DscResource -ModuleName xPSDesiredStateConfiguration

                    xWindowsOptionalFeatureSet feature1
                    {
                        Name = @("NonExistentWindowsOptionalFeature")
                        Ensure = "Present"
                        LogPath = $logPath
                    }
                }

                { & $configurationName -OutputPath $configurationPath } | Should Not Throw

                # This should not work. LCM is expected to print errors, but the call to this function itself should not throw errors.
                { Start-DscConfiguration -Path $configurationPath -Wait -Force -ErrorAction SilentlyContinue } | Should Not Throw

                Test-Path -Path $logPath | Should Be $true
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
}
finally
{
    Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
}
