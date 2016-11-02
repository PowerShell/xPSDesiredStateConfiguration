Set-StrictMode -Version 'latest'
$errorActionPreference = 'stop'

Import-Module -Name (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'CommonTestHelper.psm1')

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DscResourceModuleName 'xPSDesiredStateConfiguration' `
    -DscResourceName 'xProcessSet' `
    -TestType 'Integration'

Describe "xProcessSet Integration Tests" {
    BeforeAll {
        Import-Module "$PSScriptRoot\..\Unit\MSFT_xProcessResource.TestHelper.psm1" -Force

        $script:cmdProcess1ShortName = 'ProcessTest1'
        $script:cmdProcess1FullName = 'ProcessTest1.exe'
        $script:cmdProcess1FullPath = "$env:WinDir\system32\ProcessTest1.exe"
        Copy-Item "$env:WinDir\system32\cmd.exe" $script:cmdProcess1FullPath -Force -ErrorAction SilentlyContinue

        $script:cmdProcess2ShortName = 'ProcessTest2'
        $script:cmdProcess2FullName = 'ProcessTest2.exe'
        $script:cmdProcess2FullPath = "$env:WinDir\system32\ProcessTest2.exe"
        Copy-Item "$env:WinDir\system32\cmd.exe" $script:cmdProcess2FullPath -Force -ErrorAction SilentlyContinue
    }

    AfterEach {
        Stop-ProcessByName -ProcessName $script:cmdProcess1ShortName
        Stop-ProcessByName -ProcessName $script:cmdProcess2ShortName
    }

    AfterAll {
        Remove-Item $script:cmdProcess1FullPath -ErrorAction SilentlyContinue
        Remove-Item $script:cmdProcess2FullPath -ErrorAction SilentlyContinue
    }

    It "Ensure a set of processes is present" {
        $configurationName = "EnsureProcessIsPresent"
        $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName
        $errorPath = Join-Path -Path $TestDrive -ChildPath "StdErrorPath.txt"
        $outputPath = Join-Path -Path $TestDrive -ChildPath "StdOutputPath.txt"

        try
        {
            Configuration $configurationName
            {
                Import-DscResource -ModuleName xPSDesiredStateConfiguration

                xProcessSet xProcessSet1
                {
                    Path = @($script:cmdProcess1FullPath, $script:cmdProcess2FullPath)
                    Ensure = "Present"
                    StandardErrorPath = $errorPath
                    StandardOutputPath = $outputPath
                }
            }

            & $configurationName -OutputPath $configurationPath

            Start-DscConfiguration -Path $configurationPath -Wait -Force -Verbose

            $process1 = Get-Process $script:cmdProcess1ShortName
            $process1 | Should Not Be $null

            $process2 = Get-Process $script:cmdProcess2ShortName
            $process2 | Should Not Be $null
        }
        finally
        {
            if (Test-Path -Path $configurationPath)
            {
                Remove-Item -Path $configurationPath -Recurse -Force
            }
        }
    }

    It "Ensure a set of processes is absent" {
        $configurationName = "EnsureProcessIsAbsent"
        $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName

        try
        {
            Configuration $configurationName
            {
                Import-DscResource -ModuleName xPSDesiredStateConfiguration

                xProcessSet xProcessSet1
                {
                    Path = @($script:cmdProcess1FullPath, $script:cmdProcess2FullPath)
                    Ensure = "Absent"
                }
            }

            & $configurationName -OutputPath $configurationPath

            Start-DscConfiguration -Path $configurationPath -Wait -Force -Verbose

            $process1 = Get-Process $script:cmdProcess1ShortName -ErrorAction SilentlyContinue
            $process1 | Should Be $null

            $process2 = Get-Process $script:cmdProcess2ShortName -ErrorAction SilentlyContinue
            $process2 | Should Be $null

        }
        finally
        {
            if (Test-Path -path $configurationPath)
            {
                Remove-Item -Path $configurationPath -Recurse -Force
            }
        }
    }
}
