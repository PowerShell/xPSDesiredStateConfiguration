$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

# Import CommonTestHelper for Enter-DscResourceTestEnvironment, Exit-DscResourceTestEnvironment
$script:testsFolderFilePath = Split-Path $PSScriptRoot -Parent
$script:commonTestHelperFilePath = Join-Path -Path $testsFolderFilePath -ChildPath 'CommonTestHelper.psm1'
Import-Module -Name $commonTestHelperFilePath

if (Test-SkipContinuousIntegrationTask -Type 'Integration')
{
    return
}

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DscResourceModuleName 'xPSDesiredStateConfiguration' `
    -DscResourceName 'xProcessSet' `
    -TestType 'Integration'

try
{
    Describe 'xProcessSet Integration Tests' {
        BeforeAll {
            $script:configurationFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'xProcessSet.config.ps1'

            # Setup test process paths.
            $script:notepadExePath = Join-Path -Path (Join-Path -Path $env:SystemRoot -ChildPath System32) -ChildPath notepad.exe -Resolve
            $script:iexplorerExePath = Join-Path -Path (Join-Path -Path $env:ProgramFiles -ChildPath 'internet explorer') -ChildPath iexplore.exe -Resolve

            $script:processPaths = @( $script:notepadExePath, $script:iexplorerExePath)
        }

        AfterAll {
            foreach ($processPath in $script:processPaths)
            {
                Get-Process | Where-Object -FilterScript {$_.Path -like $processPath} | `
                    Stop-Process -Confirm:$false -Force
            }
        }

        Context 'Start two processes' {
            $configurationName = 'StartProcessSet'

            $processSetParameters = @{
                ProcessPaths = $script:processPaths
                Ensure = 'Present'
            }

            foreach ($processPath in $processSetParameters.ProcessPaths)
            {
                $processName = [System.IO.Path]::GetFileNameWithoutExtension($processPath)
                $process = Get-Process -Name $processName -ErrorAction 'SilentlyContinue'

                if ($null -ne $process)
                {
                    $null = Stop-Process -Name $processName -ErrorAction 'SilentlyContinue' -Force

                    # May need to wait a moment for the correct state to populate
                    $millisecondsElapsed = 0
                    $startTime = Get-Date
                    while ($null -eq $process -and $millisecondsElapsed -lt 3000)
                    {
                        $process = Get-Process -Name $processName -ErrorAction 'SilentlyContinue'
                        $millisecondsElapsed = ((Get-Date) - $startTime).TotalMilliseconds
                    }
                }

                It "Should not have started process $processName before configuration" {
                    $process | Should -Be $null
                }
            }

            It 'Should compile and run configuration' {
                {
                    . $script:configurationFilePath -ConfigurationName $configurationName
                    & $configurationName -OutputPath $TestDrive @processSetParameters
                    Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
                } | Should -Not -Throw
            }

            foreach ($processPath in $processSetParameters.ProcessPaths)
            {
                $processName = [System.IO.Path]::GetFileNameWithoutExtension($processPath)
                $process = Get-Process -Name $processName -ErrorAction 'SilentlyContinue'

                It "Should have started process $processName after configuration" {
                    $process | Should -Not -Be $null
                }
            }
        }

        Context 'Stop two processes' {
            $configurationName = 'StopProcessSet'

            $processSetParameters = @{
                ProcessPaths = $script:processPaths
                Ensure = 'Absent'
            }

            foreach ($processPath in $processSetParameters.ProcessPaths)
            {
                $processName = [System.IO.Path]::GetFileNameWithoutExtension($processPath)
                $process = Get-Process -Name $processName -ErrorAction 'SilentlyContinue'

                if ($null -eq $process)
                {
                    $null = Start-Process -FilePath $processPath -ErrorAction 'SilentlyContinue'

                    # May need to wait a moment for the correct state to populate
                    $millisecondsElapsed = 0
                    $startTime = Get-Date
                    while ($null -eq $process -and $millisecondsElapsed -lt 3000)
                    {
                        $process = Get-Process -Name $processName -ErrorAction 'SilentlyContinue'
                        $millisecondsElapsed = ((Get-Date) - $startTime).TotalMilliseconds
                    }
                }

                It "Should have started process $processName before configuration" {
                    $process | Should -Not -Be $null
                }
            }

            It 'Should compile and run configuration' {
                {
                    . $script:configurationFilePath -ConfigurationName $configurationName
                    & $configurationName -OutputPath $TestDrive @processSetParameters
                    Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
                } | Should -Not -Throw
            }

            foreach ($processPath in $processSetParameters.ProcessPaths)
            {
                $processName = [System.IO.Path]::GetFileNameWithoutExtension($processPath)
                $process = Get-Process -Name $processName -ErrorAction 'SilentlyContinue'

                It "Should have stopped process $processName after configuration" {
                    $process | Should -Be $null
                }
            }
        }
    }
}
finally
{
    Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
}
