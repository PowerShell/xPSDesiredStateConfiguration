Set-StrictMode -Version 'latest'
$errorActionPreference = 'stop'

Import-Module -Name (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'CommonTestHelper.psm1')

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DscResourceModuleName 'xPSDesiredStateConfiguration' `
    -DscResourceName 'xServiceSet' `
    -TestType 'Integration'

Describe "xServiceSet Integration Tests" {
    BeforeAll {
        Import-Module "$PSScriptRoot\..\MSFT_xServiceResource.TestHelper.psm1"

        $script:testServiceName = "DscTestService"
        $script:testServiceCodePath = "$PSScriptRoot\..\DscTestService.cs"
        $script:testServiceDisplayName = "DSC test service display name"
        $script:testServiceDescription = "This is DSC test service used for testing ServiceSet composite resource"
        $script:testServiceDependsOn = "winrm"
        $script:testServiceExecutablePath = Join-Path -Path (Get-Location) -ChildPath "DscTestService.exe"

        Stop-Service $script:testServiceName -ErrorAction SilentlyContinue

        New-TestService `
            -ServiceName $script:testServiceName `
            -ServiceCodePath $script:testServiceCodePath `
            -ServiceDisplayName $script:testServiceDisplayName `
            -ServiceDescription $script:testServiceDescription `
            -ServiceDependsOn $script:testServiceDependsOn `
            -ServiceExecutablePath $script:testServiceExecutablePath
    }

    AfterAll {
        Remove-TestService -ServiceName $script:testServiceName -ServiceExecutablePath $script:testServiceExecutablePath
    }

    BeforeEach {
        $configurationName = 'SetUpService'
        $configurationPath = Join-Path -Path (Get-Location) -ChildPath $configurationName

        try
        {
            Configuration $configurationName {
                Import-DscResource -ModuleName xPSDesiredStateConfiguration

                xService xService1
                {
                    Name = $script:testServiceName
                    DisplayName = $script:testServiceDisplayName
                    Description = $script:testServiceDescription
                    Path = $script:testServiceExecutablePath
                    Dependencies = $script:testServiceDependsOn
                    BuiltInAccount = 'LocalSystem'
                    State = 'Stopped'
                    StartupType = 'Manual'
                }
            }

            & $configurationName -OutputPath $configurationPath

            Start-DscConfiguration -Path $configurationPath -Wait -Force -Verbose
        }
        finally
        {
            if (Test-Path -path $configurationPath)
            {
                Remove-Item -Path $configurationPath -Recurse -Force
            }
        }
    }

    AfterEach {
        $configurationName = 'CleanUpService'
        $configurationPath = Join-Path -Path (Get-Location) -ChildPath $configurationName

        try
        {
            Configuration $configurationName {
                Import-DscResource -ModuleName xPSDesiredStateConfiguration

                xService Service1
                {
                    Name = $script:testServiceName
                    Ensure = 'Absent'
                }
            }

            & $configurationName -OutputPath $configurationPath

            Start-DscConfiguration -Path $configurationPath -Wait -Force -Verbose
        }
        finally
        {
            if (Test-Path -path $configurationPath)
            {
                Remove-Item -Path $configurationPath -Recurse -Force
            }
        }
    }

    It "Changes the properties a set of services" {
        $configurationName = "ChangeServiceProperties"
        $configurationPath = Join-Path -Path (Get-Location) -ChildPath $configurationName

        try
        {
            Configuration $configurationName
            {
                Import-DscResource -ModuleName xPSDesiredStateConfiguration

                xServiceSet ServiceSet1
                {
                    Name = @($script:testServiceName)
                    Ensure = "Present"
                    State = "Running"
                    StartupType = "Automatic"
                }
            }

            & $configurationName -OutputPath $configurationPath

            Start-DscConfiguration -Path $configurationPath -Wait -Force -Verbose

            $testService = (Get-CimInstance -Class win32_service | Where-Object {$_.Name -eq $script:testServiceName})
            $testService | Should Not Be $null
            $testService.State | Should Be "Running"
            $testService.StartMode | Should Be "Auto"
        }
        finally
        {
            if (Test-Path -path $configurationPath)
            {
                Remove-Item -Path $configurationPath -Recurse -Force
            }
        }
    }

    It "Uses a set of services that depends on a file" -Skip {
        $configurationName = "UsingDependsOn"
        $configurationPath = Join-Path -Path (Get-Location) -ChildPath $configurationName
        $testDirectory = Join-Path -Path (Get-Location) -ChildPath "TestDirectory"

        try
        {
            Configuration $configurationName
            {
                #Import-DscResource -ModuleName PSDesiredStateConfiguration
                Import-DscResource -ModuleName xPSDesiredStateConfiguration

                File TestDirectory
                {
                    DestinationPath = $testDirectory
                    Type = "Directory"
                    Ensure = "Present"
                }

                xServiceSet ServiceSet1
                {
                    Name = @($script:testServiceName)
                    Ensure = "Present"
                    State = "Stopped"
                    StartupType = "Manual"
                    BuiltInAccount = "LocalSystem"
                    DependsOn = "[File]TestDirectory"
                }
            }

            & $configurationName -OutputPath $configurationPath

            Start-DscConfiguration -Path $configurationPath -Wait -Force -Verbose

            $testService = (Get-WmiObject -Class win32_service | Where-Object {$_.Name -eq $script:testServiceName})
            $testService | Should Not Be $null
            $testService.State | Should Be "Stopped"
            $testService.StartMode | Should Be "Manual"
            $testService.StartName | Should Be "LocalSystem"
        }
        finally
        {
            if (Test-Path -Path $testDirectory)
            {
                Remove-Item -Path @($testDirectory) -Recurse -Force
            }

            if (Test-Path -Path $configurationPath)
            {
                Remove-Item -Path @($configurationPath) -Recurse -Force
            }
        }
    }
}
