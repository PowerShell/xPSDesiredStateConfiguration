Set-StrictMode -Version 'Latest'

Import-Module -Name (Join-Path -Path (Split-Path $PSScriptRoot -Parent) `
                               -ChildPath 'CommonTestHelper.psm1') `
                               -Force

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DscResourceModuleName 'xPSDesiredStateConfiguration' `
    -DscResourceName 'MSFT_xProcessResource' `
    -TestType 'Integration'

try
{
    Describe 'xProcessResource Integration Tests' {
        $testProcessPath = Join-Path -Path (Split-Path $PSScriptRoot -Parent) `
                                     -ChildPath 'ProcessResourceTestProcess.exe'
        $logFilePath = Join-Path -Path (Split-Path $PSScriptRoot -Parent) `
                                 -ChildPath 'processTestLog.txt'

        $configFile = Join-Path -Path $PSScriptRoot `
                                -ChildPath 'MSFT_xProcessResource.config.ps1'

        Context 'Should stop any current instances of the testProcess running' {
            $configurationName = 'MSFT_xProcess_Setup'
            $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName

            It 'Should compile without throwing' {
                {
                    if (Test-Path -Path $logFilePath)
                    {
                        Remove-Item -Path $logFilePath
                    }

                    .$configFile -ConfigurationName $configurationName
                    & $configurationName -Path $testProcessPath `
                                         -Arguments $logFilePath `
                                         -Ensure 'Absent' `
                                         -ErrorAction 'Stop' `
                                         -OutputPath $configurationPath
                    Start-DscConfiguration -Path $configurationPath -ErrorAction 'Stop' -Wait -Force
                } | Should Not Throw
            }
            
            It 'Should be able to call Get-DscConfiguration without throwing' {
                    { Get-DscConfiguration -Verbose -ErrorAction 'Stop' } | Should Not Throw
            }

            It 'Should return the correct configuration' {
                    $currentConfig = Get-DscConfiguration -Verbose -ErrorAction 'Stop'
                    $currentConfig.Path | Should Be $testProcessPath
                    $currentConfig.Arguments | Should Be $logFilePath
                    $currentConfig.Ensure | Should Be 'Absent'
            }

            It 'Should not create a logfile' {
                $pathResult = Test-Path $logFilePath
                $pathResult | Should Be $false
            }
        }

        Context 'Should start a new testProcess instance as running' {
            $configurationName = 'MSFT_xProcess_StartProcess'
            $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName

            It 'Should compile without throwing' {
                {
                    if (Test-Path -Path $logFilePath)
                    {
                        Remove-Item -Path $logFilePath
                    }

                    .$configFile -ConfigurationName $configurationName
                    & $configurationName -Path $testProcessPath `
                                         -Arguments $logFilePath `
                                         -Ensure 'Present' `
                                         -ErrorAction 'Stop' `
                                         -OutputPath $configurationPath
                    Start-DscConfiguration -Path $configurationPath -ErrorAction 'Stop' -Wait -Force
                } | Should Not Throw
            }
       
            It 'Should be able to call Get-DscConfiguration without throwing' {
                    { Get-DscConfiguration -Verbose -ErrorAction 'Stop' } | Should Not Throw
            }

            It 'Should return the correct configuration' {
                    $currentConfig = Get-DscConfiguration -Verbose -ErrorAction 'Stop'
                    $currentConfig.Path | Should Be $testProcessPath
                    $currentConfig.Arguments | Should Be $logFilePath
                    $currentConfig.Ensure | Should Be 'Present'
                    $currentConfig.ProcessCount | Should Be 1
            }

            It 'Should create a logfile' {
                $pathResult = Test-Path $logFilePath
                $pathResult | Should Be $true
            }
        }

        Context 'Should not start a second new testProcess instance when one is already running' {
            $configurationName = 'MSFT_xProcess_StartSecondProcess'
            $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName

            It 'Should compile without throwing' {
                {
                    if (Test-Path -Path $logFilePath)
                    {
                        Remove-Item -Path $logFilePath
                    }

                    .$configFile -ConfigurationName $configurationName
                    & $configurationName -Path $testProcessPath `
                                         -Arguments $logFilePath `
                                         -Ensure 'Present' `
                                         -ErrorAction 'Stop' `
                                         -OutputPath $configurationPath
                    Start-DscConfiguration -Path $configurationPath -ErrorAction 'Stop' -Wait -Force
                } | Should Not Throw
            }
       
            It 'Should be able to call Get-DscConfiguration without throwing' {
                    { Get-DscConfiguration -Verbose -ErrorAction 'Stop' } | Should Not Throw
            }

            It 'Should return the correct configuration' {
                    $currentConfig = Get-DscConfiguration -Verbose -ErrorAction 'Stop'
                    $currentConfig.Path | Should Be $testProcessPath
                    $currentConfig.Arguments | Should Be $logFilePath
                    $currentConfig.Ensure | Should Be 'Present'
                    $currentConfig.ProcessCount | Should Be 1
            }

            It 'Should not create a logfile' {
                $pathResult = Test-Path $logFilePath
                $pathResult | Should Be $false
            }
        }

        Context 'Should stop the testProcess instance from running' {
            $configurationName = 'MSFT_xProcess_StopProcesses'
            $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName

            It 'Should compile without throwing' {
                {
                    if (Test-Path -Path $logFilePath)
                    {
                        Remove-Item -Path $logFilePath
                    }

                    .$configFile -ConfigurationName $configurationName
                    & $configurationName -Path $testProcessPath `
                                         -Arguments $logFilePath `
                                         -Ensure 'Absent' `
                                         -ErrorAction 'Stop' `
                                         -OutputPath $configurationPath
                    Start-DscConfiguration -Path $configurationPath -ErrorAction 'Stop' -Wait -Force
                } | Should Not Throw
            }
       
            It 'Should be able to call Get-DscConfiguration without throwing' {
                    { Get-DscConfiguration -Verbose -ErrorAction 'Stop' } | Should Not Throw
            }

            It 'Should return the correct configuration' {
                    $currentConfig = Get-DscConfiguration -Verbose -ErrorAction 'Stop'
                    $currentConfig.Path | Should Be $testProcessPath
                    $currentConfig.Arguments | Should Be $logFilePath
                    $currentConfig.Ensure | Should Be 'Absent'
            }

            It 'Should not create a logfile' {
                $pathResult = Test-Path $logFilePath
                $pathResult | Should Be $false
            }
        }

        Context 'Should return correct amount of processes running when more than 1 are running' {
            $configurationName = 'MSFT_xProcess_StartMultipleProcesses'
            $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName

            It 'Should compile without throwing' {
                {
                    if (Test-Path -Path $logFilePath)
                    {
                        Remove-Item -Path $logFilePath
                    }

                    .$configFile -ConfigurationName $configurationName
                    & $configurationName -Path $testProcessPath `
                                         -Arguments $logFilePath `
                                         -Ensure 'Present' `
                                         -ErrorAction 'Stop' `
                                         -OutputPath $configurationPath
                    Start-DscConfiguration -Path $configurationPath -ErrorAction 'Stop' -Wait -Force
                } | Should Not Throw
            }

            It 'Should start another process running' {
                Start-Process -FilePath $testProcessPath -ArgumentList @($logFilePath)
            }
       
            It 'Should be able to call Get-DscConfiguration without throwing' {
                    { Get-DscConfiguration -Verbose -ErrorAction 'Stop' } | Should Not Throw
            }

            It 'Should return the correct configuration' {
                    $currentConfig = Get-DscConfiguration -Verbose -ErrorAction 'Stop'
                    $currentConfig.Path | Should Be $testProcessPath
                    $currentConfig.Arguments | Should Be $logFilePath
                    $currentConfig.Ensure | Should Be 'Present'
                    $currentConfig.ProcessCount | Should Be 2
            }

            It 'Should create a logfile' {
                $pathResult = Test-Path $logFilePath
                $pathResult | Should Be $true
            }
        
        
        }

        Context 'Should stop all of the testProcess instances from running' {
            $configurationName = 'MSFT_xProcess_StopAllProcesses'
            $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName

            It 'Should compile without throwing' {
                {
                    if (Test-Path -Path $logFilePath)
                    {
                        Remove-Item -Path $logFilePath
                    }

                    .$configFile -ConfigurationName $configurationName
                    & $configurationName -Path $testProcessPath `
                                         -Arguments $logFilePath `
                                         -Ensure 'Absent' `
                                         -ErrorAction 'Stop' `
                                         -OutputPath $configurationPath
                    Start-DscConfiguration -Path $configurationPath -ErrorAction 'Stop' -Wait -Force
                } | Should Not Throw
            }
       
            It 'Should be able to call Get-DscConfiguration without throwing' {
                    { Get-DscConfiguration -Verbose -ErrorAction 'Stop' } | Should Not Throw
            }

            It 'Should return the correct configuration' {
                    $currentConfig = Get-DscConfiguration -Verbose -ErrorAction 'Stop'
                    $currentConfig.Path | Should Be $testProcessPath
                    $currentConfig.Arguments | Should Be $logFilePath
                    $currentConfig.Ensure | Should Be 'Absent'
            }

            It 'Should not create a logfile' {
                $pathResult = Test-Path $logFilePath
                $pathResult | Should Be $false
            }
        }
    }

}
finally
{
    Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
}
