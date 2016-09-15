Import-Module -Name "$PSScriptRoot\..\CommonTestHelper.psm1"

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DscResourceModuleName 'xPSDesiredStateConfiguration' `
    -DscResourceName 'MSFT_xUserResource' `
    -TestType 'Integration'

try {

    $configFile = Join-Path -Path $PSScriptRoot -ChildPath 'MSFT_xUserResource.config.ps1'

    Describe 'xUserResource Integration Tests' {
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
    
        Context 'Should create a new user' {
            $configurationName = 'MSFT_xUser_NewUser'
            $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName

            $logPath = Join-Path -Path $TestDrive -ChildPath 'NewUser.log'
            
            $testUserName = 'TestUserName12345'
            $testUserPassword = 'StrongOne7.'
            $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
            $testCredential = New-Object PSCredential ($testUserName, $secureTestPassword)

            try
            {
        
                It 'Should compile without throwing' {
                    

                    {
                        . $configFile
                        & $configurationName -UserName $testUserName -Password $testCredential -OutputPath $configurationPath -ConfigurationData $ConfigData -ErrorAction Stop
                        Start-DscConfiguration -Path $configurationPath -Wait -Force
                    } | Should Not Throw

                    #{  } | Should Not Throw
                    
                    #{
                    #   Invoke-Expression -Command '$configurationName -OutputPath `$script:testEnvironment.WorkingFolder'
                    #    Start-DscConfiguration -Path $script:testEnvironment.WorkingFolder -ComputerName localhost -Wait -Verbose -Force
                    #} | Should Not Throw
                }

                It 'Should be able to call Get-DscConfiguration without throwing' {
                    #{ Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not Throw
                }

                        #{ & $configurationName -OutputPath $configurationPath } | Should Not Throw

                        #{ Start-DscConfiguration -Path $configurationPath -Wait -Force } | Should Not Throw

            }
            finally
            {
                if (Test-Path -Path $logPath) {
                    Remove-Item -Path $logPath -Recurse -Force
                }

                if (Test-Path -Path $configurationPath)
                {
                    Remove-Item -Path $configurationPath -Recurse -Force
                }
            }
        }
        <#
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
        #>
    }
}
finally
{
    Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
}


