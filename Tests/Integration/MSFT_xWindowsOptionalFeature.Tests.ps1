$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName 'xPSDesiredStateConfiguration' `
    -DSCResourceName 'MSFT_xWindowsOptionalFeature' `
    -TestType Integration

Describe "xWindowsOptionalFeature Integration Tests" {
    It "Install a valid Windows optional feature" {
        $configurationName = "InstallOptionalFeature"
        $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName
        $logPath = Join-Path -Path $TestDrive -ChildPath 'InstallOptionalFeature.log'

        $validFeatureName = 'TelnetClient'

        $originalFeature = Dism\Get-WindowsOptionalFeature -Online -FeatureName $validFeatureName

        try
        {
            Configuration $configurationName
            {
                Import-DscResource -ModuleName xPSDesiredStateConfiguration

                xWindowsOptionalFeature WindowsOptionalFeature
                {
                    Name = $validFeatureName
                    Ensure = "Present"
                    LogPath = $logPath
                    NoWindowsUpdateCheck = $true
                }
            }

            { & $configurationName -OutputPath $configurationPath } | Should Not Throw

            { Start-DscConfiguration -Path $configurationPath -Wait -Force -Verbose } |
                Should Not Throw

            $windowsOptionalFeature =
                Dism\Get-WindowsOptionalFeature -Online -FeatureName $validFeatureName

            $windowsOptionalFeature | Should Not Be $null
            $windowsOptionalFeature.State -in 'Enabled','EnablePending' | Should Be $true
        }
        finally
        {
            if ($originalFeature.State -in 'Disabled','DisablePending')
            {
                Dism\Disable-WindowsOptionalFeature -Online -FeatureName $validFeatureName -NoRestart
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

    It "Install an incorrect Windows optional feature" {
        $configurationName = "InstallIncorrectWindowsFeature"
        $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName
        $logPath = Join-Path -Path $TestDrive -ChildPath 'InstallIncorrectWindowsFeature.log'

        try
        {
            Configuration $configurationName
            {
                Import-DscResource -ModuleName xPSDesiredStateConfiguration

                xWindowsOptionalFeatureSet feature
                {
                    Name = @("NonExistentWindowsOptionalFeature")
                    Ensure = "Present"
                    LogPath = $logPath
                }
            }

            { & $configurationName -OutputPath $configurationPath } | Should Not Throw

            # This should not work. LCM is expected to print errors,
            # but the call to this function itself should not throw errors.
            {
                $startParams = @{
                    Path = $configurationPath
                    Wait = $true
                    Force = $true
                    ErrorAction = 'SilentlyContinue'
                }
                Start-DscConfiguration @startParams
            } | Should Not Throw

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
