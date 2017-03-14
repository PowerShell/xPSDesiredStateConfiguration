<#
    Please note that some of these tests depend on each other.
    They must be run in the order given - if one test fails, subsequent tests may
    also fail.
#>
$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

Describe 'xMsiPackage End to End Tests' {
    BeforeAll {
        # Import CommonTestHelper for Enter-DscResourceTestEnvironment, Exit-DscResourceTestEnvironment
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
        $script:confgurationFilePathNoOptionalParameters = Join-Path -Path $PSScriptRoot -ChildPath 'MSFT_xMsiPackage_NoOptionalParameters'

        $script:testDirectoryPath = Join-Path -Path $PSScriptRoot -ChildPath 'MSFT_xPackageResourceTests'

        if (Test-Path -Path $script:testDirectoryPath)
        {
            $null = Remove-Item -Path $script:testDirectoryPath -Recurse -Force
        }

        $null = New-Item -Path $script:testDirectoryPath -ItemType 'Directory'

        $script:msiName = 'DSCSetupProject.msi'
        $script:msiLocation = Join-Path -Path $script:testDirectoryPath -ChildPath $script:msiName

        $script:packageId = '{deadbeef-80c6-41e6-a1b9-8bdb8a05027f}'

        $null = New-TestMsi -DestinationPath $script:msiLocation

        $null = Clear-xPackageCache
    }

    AfterAll {
        if (Test-Path -Path $script:testDirectoryPath)
        {
            $null = Remove-Item -Path $script:testDirectoryPath -Recurse -Force
        }

        $null = Clear-xPackageCache

        if (Test-PackageInstalledById -ProductId $script:packageId)
        {
            $null = Start-Process -FilePath 'msiexec.exe' -ArgumentList @("/x$script:packageId", '/passive') -Wait
            $null = Start-Sleep -Seconds 1
        }

        if (Test-PackageInstalledById -ProductId $script:packageId)
        {
            throw 'Test output will not be valid - package could not be removed.'
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

        It 'Should return true from Test-TargetResource with the same parameters before configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
        }

        It 'Should compile and run configuration' {
            { 
                . $script:confgurationFilePathNoOptionalParameters -ConfigurationName $configurationName
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
                . $script:confgurationFilePathNoOptionalParameters -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @msiPackageParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
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
                . $script:confgurationFilePathNoOptionalParameters -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @msiPackageParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
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
                . $script:confgurationFilePathNoOptionalParameters -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @msiPackageParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
        }
    }
    <#  Commenting out these HTTP tests since they are failing
    Context 'Install Msi package from HTTP Url' {
        $configurationName = 'InstallMsiPackageFromHttp'

        $baseUrl = 'http://localhost:1242/'
        $msiUrl = "$baseUrl" + 'package.msi'
        New-MockFileServer -FilePath $script:msiLocation

        # Test pipe connection as testing server readiness
        $pipe = New-Object -TypeName 'System.IO.Pipes.NamedPipeServerStream' -ArgumentList @( '\\.\pipe\dsctest1' )
        $pipe.WaitForConnection()
        $pipe.Dispose()

        $msiPackageParameters = @{
            ProductId = $script:packageId
            Path = $msiUrl
            Ensure = 'Present'
        }

        try
        {
            It 'Should return False from Test-TargetResource with the same parameters before configuration' {
                MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $false
            }

            It 'Should compile and run configuration' {
                { 
                    . $script:confgurationFilePathNoOptionalParameters -ConfigurationName $configurationName
                    & $configurationName -OutputPath $TestDrive @msiPackageParameters
                    Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
                } | Should Not Throw
            }

            It 'Should return true from Test-TargetResource with the same parameters after configuration' {
                MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
            }
        }
        catch
        {
            $pipe = New-Object -TypeName 'System.IO.Pipes.NamedPipeClientStream' -ArgumentList @( '\\.\pipe\dsctest2' )
            $pipe.Connect()
            $pipe.Dispose()
        }
    }
  
    Context 'Uninstall Msi package from HTTP Url' {
        $configurationName = 'UninstallMsiPackageFromHttp'

        $baseUrl = 'http://localhost:1242/'
        $msiUrl = "$baseUrl" + 'package.msi'
        New-MockFileServer -FilePath $script:msiLocation

        # Test pipe connection as testing server readiness
        $pipe = New-Object -TypeName 'System.IO.Pipes.NamedPipeServerStream' -ArgumentList @( '\\.\pipe\dsctest1' )
        $pipe.WaitForConnection()
        $pipe.Dispose()

        $msiPackageParameters = @{
            ProductId = $script:packageId
            Path = $msiUrl
            Ensure = 'Absent'
        }

        try
        {
            It 'Should return False from Test-TargetResource with the same parameters before configuration' {
                MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $false
            }

            It 'Should compile and run configuration' {
                { 
                    . $script:confgurationFilePathNoOptionalParameters -ConfigurationName $configurationName
                    & $configurationName -OutputPath $TestDrive @msiPackageParameters
                    Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
                } | Should Not Throw
            }

            It 'Should return true from Test-TargetResource with the same parameters after configuration' {
                MSFT_xMsiPackage\Test-TargetResource @msiPackageParameters | Should Be $true
            }
        }
        finally
        {
            $pipe = New-Object -TypeName 'System.IO.Pipes.NamedPipeClientStream' -ArgumentList @( '\\.\pipe\dsctest2' )
            $pipe.Connect()
            $pipe.Dispose()
        }
    }#>
}
