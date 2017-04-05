<#
    Please note that some of these tests depend on each other.
    They must be run in the order given - if one test fails, subsequent tests may
    also fail.
#>

$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

Describe 'xMsiPackage End to End Tests' {
    BeforeAll {
        # Import CommonTestHelper
        $testsFolderFilePath = Split-Path $PSScriptRoot -Parent
        $commonTestHelperFilePath = Join-Path -Path $testsFolderFilePath -ChildPath 'CommonTestHelper.psm1'
        Import-Module -Name $commonTestHelperFilePath

        $script:testEnvironment = Enter-DscResourceTestEnvironment `
            -DscResourceModuleName 'xPSDesiredStateConfiguration' `
            -DscResourceName 'MSFT_xMsiPackage' `
            -TestType 'Integration'

        # Import xMsiPackage resource module for Test-TargetResource
        $moduleRootFilePath = Split-Path -Path $testsFolderFilePath -Parent
        $dscResourcesFolderFilePath = Join-Path -Path $moduleRootFilePath -ChildPath 'DscResources'
        $msiPackageResourceFolderFilePath = Join-Path -Path $dscResourcesFolderFilePath -ChildPath 'MSFT_xMsiPackage'
        $msiPackageResourceModuleFilePath = Join-Path -Path $msiPackageResourceFolderFilePath -ChildPath 'MSFT_xMsiPackage.psm1'
        Import-Module -Name $msiPackageResourceModuleFilePath -Force

        # Import the xPackage test helper
        $packageTestHelperFilePath = Join-Path -Path $testsFolderFilePath -ChildPath 'MSFT_xPackageResource.TestHelper.psm1'
        Import-Module -Name $packageTestHelperFilePath -Force

        # Set up the paths to the test configurations
        $script:configurationFilePathNoOptionalParameters = Join-Path -Path $PSScriptRoot -ChildPath 'MSFT_xMsiPackage_NoOptionalParameters'
        $script:configurationFilePathLogPath = Join-Path -Path $PSScriptRoot -ChildPath 'MSFT_xMsiPackage_LogPath'

        $script:testDirectoryPath = Join-Path -Path $PSScriptRoot -ChildPath 'MSFT_xPackageResourceTests'
        $script:logFile = Join-Path -Path $PSScriptRoot -ChildPath 'PackageTestLogFile.txt'

        if (Test-Path -Path $script:testDirectoryPath)
        {
            $null = Remove-Item -Path $script:testDirectoryPath -Recurse -Force
        }

        $null = New-Item -Path $script:testDirectoryPath -ItemType 'Directory'

        $script:msiName = 'DSCSetupProject.msi'
        $script:msiLocation = Join-Path -Path $script:testDirectoryPath -ChildPath $script:msiName

        $script:packageId = '{deadbeef-80c6-41e6-a1b9-8bdb8a05027f}'

        $null = New-TestMsi -DestinationPath $script:msiLocation

        # Clear the log file
        'Beginning integration tests' > $script:logFile
    }

    AfterAll {
        if (Test-Path -Path $script:testDirectoryPath)
        {
            $null = Remove-Item -Path $script:testDirectoryPath -Recurse -Force
        }

        # Remove the test MSI if it is still installed
        if (Test-PackageInstalledById -ProductId $script:packageId)
        {
            $null = Start-Process -FilePath 'msiexec.exe' -ArgumentList @("/x$script:packageId", '/passive') -Wait
            $null = Start-Sleep -Seconds 1
        }

        if (Test-PackageInstalledById -ProductId $script:packageId)
        {
            Throw 'Test output will not be valid - package could not be removed.'
        }

        Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
    }

    Context 'Remove package that is already Absent' {
        $configurationName = 'RemoveAbsentMsiPackage'

        $msiPackageParameters = @{
            ProductId = $script:packageId
            Path = $script:msiLocation
            Ensure = 'Absent'
        }

        It 'Should return True from Test-TargetResource with the same parameters before configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
        }

        It 'Should compile and run configuration' {
            { 
                . $script:configurationFilePathNoOptionalParameters -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @msiPackageParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Should return True from Test-TargetResource with the same parameters after configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
        }
    }

    Context 'Install package that is not installed yet' {
        $configurationName = 'InstallMsiPackage'

        $msiPackageParameters = @{
            ProductId = $script:packageId
            Path = $script:msiLocation
            Ensure = 'Present'
        }

        It 'Should return False from Test-TargetResource with the same parameters before configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $false
        }

        It 'Should compile and run configuration' {
            { 
                . $script:configurationFilePathNoOptionalParameters -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @msiPackageParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Should return True from Test-TargetResource with the same parameters after configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
        }
    }

    Context 'Install package that is already installed' {
        $configurationName = 'InstallExistingMsiPackage'

        $msiPackageParameters = @{
            ProductId = $script:packageId
            Path = $script:msiLocation
            Ensure = 'Present'
        }

        It 'Should return True from Test-TargetResource with the same parameters before configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
        }

        It 'Should compile and run configuration' {
            { 
                . $script:configurationFilePathNoOptionalParameters -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @msiPackageParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Should return True from Test-TargetResource with the same parameters after configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
        }
    }

    Context 'Uninstall package that is installed' {
        $configurationName = 'UninstallExistingMsiPackage'

        $msiPackageParameters = @{
            ProductId = $script:packageId
            Path = $script:msiLocation
            Ensure = 'Absent'
        }

        It 'Should return False from Test-TargetResource with the same parameters before configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $false
        }

        It 'Should compile and run configuration' {
            { 
                . $script:configurationFilePathNoOptionalParameters -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @msiPackageParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Should return True from Test-TargetResource with the same parameters after configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
        }
    }

    Context 'Install package that is installed and write to specified log file' {
        $configurationName = 'InstallWithLogFile'

        $logPath = Join-Path -Path $script:testDirectoryPath -ChildPath 'TestMsiLog.txt'

        if (Test-Path -Path $logPath)
        {
            Remove-Item -Path $logPath -Force
        }

        $msiPackageParameters = @{
            ProductId = $script:packageId
            Path = $script:msiLocation
            Ensure = 'Present'
            LogPath = $logPath
        }

        try
        {
            It 'Should return False from Test-TargetResource with the same parameters before configuration' {
                MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $false
            }

            It 'Should compile and run configuration' {
                { 
                    . $script:configurationFilePathLogPath -ConfigurationName $configurationName
                    & $configurationName -OutputPath $TestDrive @msiPackageParameters
                    Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
                } | Should Not Throw
            }

            It 'Should return True from Test-TargetResource with the same parameters after configuration' {
                MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
            }

            It 'Should have created the log file' {
                Test-Path -Path $logPath | Should Be $true
            }
        }
        finally
        {
            if (Test-Path -Path $logPath)
            {
                Remove-Item -Path $logPath -Force
            }
        }
    }

    Context 'Uninstall package from HTTP Url' {
        $configurationName = 'UninstallExistingMsiPackageFromHttp'

        $baseUrl = 'http://localhost:1242/'
        $msiUrl = "$baseUrl" + 'package.msi'

        $fileServerStarted = $null
        $job = $null

        $msiPackageParameters = @{
            ProductId = $script:packageId
            Path = $msiUrl
            Ensure = 'Absent'
        }

        try
        {
            $serverResult = Start-Server -FilePath $script:msiLocation -LogPath $script:logFile -Https $false
            $fileServerStarted = $serverResult.FileServerStarted
            $job = $serverResult.Job              

            $fileServerStarted.WaitOne(30000)

            It 'Should compile and run configuration' {
                { 
                    . $script:configurationFilePathNoOptionalParameters -ConfigurationName $configurationName
                    & $configurationName -OutputPath $TestDrive @msiPackageParameters
                    Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
                } | Should Not Throw
            }
        }
        finally
        {
            <#
                This must be called after Start-Server to ensure the listening port is closed,
                otherwise subsequent tests may fail until the machine is rebooted.
            #>
            Stop-Server -FileServerStarted $fileServerStarted -Job $job
        }

        It 'Should return True from Test-TargetResource with the same parameters after configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
        }
    }

    Context 'Install Msi package from HTTP Url' {
        $configurationName = 'InstallMsiPackageFromHttp'

        $baseUrl = 'http://localhost:1242/'
        $msiUrl = "$baseUrl" + 'package.msi'

        $fileServerStarted = $null
        $job = $null

        $msiPackageParameters = @{
            ProductId = $script:packageId
            Path = $msiUrl
            Ensure = 'Present'
        }

        It 'Should return False from Test-TargetResource with the same parameters before configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $false
        }
        
        try
        {
            $serverResult = Start-Server -FilePath $script:msiLocation -LogPath $script:logFile -Https $false
            $fileServerStarted = $serverResult.FileServerStarted
            $job = $serverResult.Job

            $fileServerStarted.WaitOne(30000)

            It 'Should compile and run configuration' {
                { 
                    . $script:configurationFilePathNoOptionalParameters -ConfigurationName $configurationName
                    & $configurationName -OutputPath $TestDrive @msiPackageParameters
                    Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
                } | Should Not Throw
            }
        }
        finally
        {
            <#
                This must be called after Start-Server to ensure the listening port is closed,
                otherwise subsequent tests may fail until the machine is rebooted.
            #>
            Stop-Server -FileServerStarted $fileServerStarted -Job $job
        }

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
        }
    }

    Context 'Uninstall Msi package from HTTP Url' {
        $configurationName = 'UninstallMsiPackageFromHttp'

        $baseUrl = 'http://localhost:1242/'
        $msiUrl = "$baseUrl" + 'package.msi'

        $fileServerStarted = $null
        $job = $null

        $msiPackageParameters = @{
            ProductId = $script:packageId
            Path = $msiUrl
            Ensure = 'Absent'
        }

        It 'Should return False from Test-TargetResource with the same parameters before configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $false
        }

        try
        {
            $serverResult = Start-Server -FilePath $script:msiLocation -LogPath $script:logFile -Https $false
            $fileServerStarted = $serverResult.FileServerStarted
            $job = $serverResult.Job

            $fileServerStarted.WaitOne(30000)

            It 'Should compile and run configuration' {
                { 
                    . $script:configurationFilePathNoOptionalParameters -ConfigurationName $configurationName
                    & $configurationName -OutputPath $TestDrive @msiPackageParameters
                    Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
                } | Should Not Throw
            }
        }
        finally
        {
            <#
                This must be called after Start-Server to ensure the listening port is closed,
                otherwise subsequent tests may fail until the machine is rebooted.
            #>
            Stop-Server -FileServerStarted $fileServerStarted -Job $job
        }

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
        }
    }

    Context 'Install Msi package from HTTPS Url' {
        $configurationName = 'InstallMsiPackageFromHttpS'

        $baseUrl = 'https://localhost:1243/'
        $msiUrl = "$baseUrl" + 'package.msi'

        $fileServerStarted = $null
        $job = $null

        $msiPackageParameters = @{
            ProductId = $script:packageId
            Path = $msiUrl
            Ensure = 'Present'
        }

        It 'Should return False from Test-TargetResource with the same parameters before configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $false
        }
        
        try
        {
            $serverResult = Start-Server -FilePath $script:msiLocation -LogPath $script:logFile -Https $true
            $fileServerStarted = $serverResult.FileServerStarted
            $job = $serverResult.Job

            $fileServerStarted.WaitOne(30000)

            It 'Should compile and run configuration' {
                { 
                    . $script:configurationFilePathNoOptionalParameters -ConfigurationName $configurationName
                    & $configurationName -OutputPath $TestDrive @msiPackageParameters
                    Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
                } | Should Not Throw
            }
        }
        finally
        {
            <#
                This must be called after Start-Server to ensure the listening port is closed,
                otherwise subsequent tests may fail until the machine is rebooted.
            #>
            Stop-Server -FileServerStarted $fileServerStarted -Job $job
        }

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
        }
    }
    
    Context 'Uninstall Msi package from HTTPS Url' {
        $configurationName = 'UninstallMsiPackageFromHttps'

        $baseUrl = 'https://localhost:1243/'
        $msiUrl = "$baseUrl" + 'package.msi'

        $fileServerStarted = $null
        $job = $null

        $msiPackageParameters = @{
            ProductId = $script:packageId
            Path = $msiUrl
            Ensure = 'Absent'
        }

        It 'Should return False from Test-TargetResource with the same parameters before configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $false
        }

        try
        {
            $serverResult = Start-Server -FilePath $script:msiLocation -LogPath $script:logFile -Https $true
            $fileServerStarted = $serverResult.FileServerStarted
            $job = $serverResult.Job

            $fileServerStarted.WaitOne(30000)

            It 'Should compile and run configuration' {
                { 
                    . $script:configurationFilePathNoOptionalParameters -ConfigurationName $configurationName
                    & $configurationName -OutputPath $TestDrive @msiPackageParameters
                    Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
                } | Should Not Throw
            }
        }
        finally
        {
            <#
                This must be called after Start-Server to ensure the listening port is closed,
                otherwise subsequent tests may fail until the machine is rebooted.
            #>
            Stop-Server -FileServerStarted $fileServerStarted -Job $job
        }

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
        }
    }
}
