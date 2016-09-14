Import-Module -Name "$PSScriptRoot\..\CommonTestHelper.psm1"

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DscResourceModuleName 'xPSDesiredStateConfiguration' `
    -DscResourceName 'MSFT_xWindowsOptionalFeature' `
    -TestType 'Integration'

Describe 'xWindowsOptionalFeature Integration Tests' {
    BeforeAll {
        $script:enabledStates = @( 'Enabled', 'EnablePending' )
        $script:disabledStates = @( 'Disabled', 'DisablePending' )
    }
    
    It 'Should enable a valid Windows optional feature' {
        $configurationName = 'EnableOptionalFeature'
        $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName

        $logPath = Join-Path -Path $TestDrive -ChildPath 'EnableOptionalFeature.log'

        $validFeatureName = 'TelnetClient'

        $originalFeature = Dism\Get-WindowsOptionalFeature -FeatureName $validFeatureName -Online

        try
        {
            if ($originalFeature.State -in $script:enabledStates)
            {
                Dism\Disable-WindowsOptionalFeature -FeatureName $validFeatureName -Online -NoRestart
            }
        
            Configuration $configurationName
            {
                Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

                xWindowsOptionalFeature WindowsOptionalFeature1
                {
                    Name = $validFeatureName
                    Ensure = 'Present'
                    LogPath = $logPath
                    NoWindowsUpdateCheck = $true
                }
            }

            { & $configurationName -OutputPath $configurationPath } | Should Not Throw

            { Start-DscConfiguration -Path $configurationPath -Wait -Force } | Should Not Throw

            $windowsOptionalFeature = Dism\Get-WindowsOptionalFeature -FeatureName $validFeatureName -Online

            $windowsOptionalFeature | Should Not Be $null
            $windowsOptionalFeature.State -in $script:enabledStates| Should Be $true
        }
        finally
        {
            if ($originalFeature.State -in $script:disabledStates)
            {
                Dism\Disable-WindowsOptionalFeature -FeatureName $validFeatureName -Online -NoRestart
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

    It 'Should disable a valid Windows optional feature' {
        $configurationName = 'DisableOptionalFeature'
        $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName

        $logPath = Join-Path -Path $TestDrive -ChildPath 'DisableOptionalFeature.log'

        $validFeatureName = 'TelnetClient'

        $originalFeature = Dism\Get-WindowsOptionalFeature -FeatureName $validFeatureName -Online

        try
        {
            if ($originalFeature.State -in $script:disabledStates)
            {
                Dism\Enable-WindowsOptionalFeature -FeatureName $validFeatureName -Online -NoRestart
            }

            Configuration $configurationName
            {
                Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

                xWindowsOptionalFeature WindowsOptionalFeature1
                {
                    Name = $validFeatureName
                    Ensure = 'Absent'
                    LogPath = $logPath
                    NoWindowsUpdateCheck = $true
                }
            }

            { & $configurationName -OutputPath $configurationPath } | Should Not Throw

            { Start-DscConfiguration -Path $configurationPath -Wait -Force } | Should Not Throw

            $windowsOptionalFeature = Dism\Get-WindowsOptionalFeature -FeatureName $validFeatureName -Online 

            $windowsOptionalFeature | Should Not Be $null
            $windowsOptionalFeature.State -in $script:disabledStates | Should Be $true
        }
        finally
        {
            if ($originalFeature.State -in $script:disabledStates)
            {
                Dism\Disable-WindowsOptionalFeature -FeatureName $validFeatureName -Online -NoRestart
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

    It 'Should not enable an incorrect Windows optional feature' {
        $configurationName = 'EnableIncorrectWindowsFeature'
        $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName

        $logPath = Join-Path -Path $TestDrive -ChildPath 'EnableIncorrectWindowsFeature.log'

        $invalidFeatureName = 'NonExistentWindowsOptionalFeature'

        Dism\Get-WindowsOptionalFeature -FeatureName $invalidFeatureName -Online | Should Be $null

        try
        {
            Configuration $configurationName
            {
                Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

                xWindowsOptionalFeature WindowsOptionalFeature1
                {
                    Name = $invalidFeatureName
                    Ensure = 'Present'
                    LogPath = $logPath
                }
            }

            { & $configurationName -OutputPath $configurationPath } | Should Not Throw

            { Start-DscConfiguration -Path $configurationPath -ErrorAction 'Stop' -Wait -Force } |
                Should Throw "Feature name $invalidFeatureName is unknown."

            Test-Path -Path $logPath | Should Be $true

            Dism\Get-WindowsOptionalFeature -FeatureName $invalidFeatureName -Online | Should Be $null
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
