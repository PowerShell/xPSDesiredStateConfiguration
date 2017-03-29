$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

$script:testsFolderFilePath = Split-Path $PSScriptRoot -Parent
$script:commonTestHelperFilePath = Join-Path -Path $script:testsFolderFilePath -ChildPath 'CommonTestHelper.psm1'
Import-Module -Name $script:commonTestHelperFilePath -force

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DscResourceModuleName 'xPSDesiredStateConfiguration' `
    -DscResourceName 'MSFT_xMsiPackage' `
    -TestType 'Unit'

try
{
    InModuleScope 'MSFT_xMsiPackage' {
        Describe 'MSFT_xMsiPackage integration Tests' {
            BeforeAll {
                $testsFolderFilePath = Split-Path $PSScriptRoot -Parent
                $packageTestHelperFilePath = Join-Path -Path $testsFolderFilePath -ChildPath 'MSFT_xPackageResource.TestHelper.psm1'
                $commonTestHelperFilePath = Join-Path -Path $testsFolderFilePath -ChildPath 'CommonTestHelper.psm1'

                Import-Module -Name $packageTestHelperFilePath -Force
                # The common test helper file needs to be imported twice because of the InModuleScope
                Import-Module -Name $commonTestHelperFilePath

                $script:skipHttpsTest = $false
                $script:testDirectoryPath = Join-Path -Path $PSScriptRoot -ChildPath 'MSFT_xPackageResourceTests'
                $script:logFile = 'C:\server.txt'

                if (Test-Path -Path $script:testDirectoryPath)
                {
                    $null = Remove-Item -Path $script:testDirectoryPath -Recurse -Force
                }

                $null = New-Item -Path $script:testDirectoryPath -ItemType 'Directory'

                $script:msiName = 'DSCSetupProject.msi'
                $script:msiLocation = Join-Path -Path $script:testDirectoryPath -ChildPath $script:msiName
                $script:msiArguments = '/NoReboot'

                $script:packageId = '{deadbeef-80c6-41e6-a1b9-8bdb8a05027f}'

                $null = New-TestMsi -DestinationPath $script:msiLocation

                $null = Clear-PackageCache
            }

            BeforeEach {
                $null = Clear-PackageCache

                if (Test-PackageInstalledById -ProductId $script:packageId)
                {
                    $null = Start-Process -FilePath 'msiexec.exe' -ArgumentList @("/x$script:packageId", '/passive') -Wait
                    $null = Start-Sleep -Seconds 1
                }

                if (Test-PackageInstalledById -ProductId $script:packageId)
                {
                    Throw 'Package could not be removed.'
                }
            }

            AfterAll {
                if (Test-Path -Path $script:testDirectoryPath)
                {
                    $null = Remove-Item -Path $script:testDirectoryPath -Recurse -Force
                }

                $null = Clear-PackageCache

                if (Test-PackageInstalledById -ProductId $script:packageId)
                {
                    $null = Start-Process -FilePath 'msiexec.exe' -ArgumentList @("/x$script:packageId", '/passive') -Wait
                    $null = Start-Sleep -Seconds 1
                }

                if (Test-PackageInstalledById -ProductId $script:packageId)
                {
                    throw 'Test output will not be valid - package could not be removed.'
                }
            }

            Context 'Get-TargetResource' {
                It 'Should return only basic properties for absent package' {
                    $packageParameters = @{
                        Path = $script:msiLocation
                        ProductId = $script:packageId
                    }

                    $getTargetResourceResult = Get-TargetResource @packageParameters
                    $getTargetResourceResultProperties = @( 'Ensure', 'ProductId' )

                    Test-GetTargetResourceResult -GetTargetResourceResult $getTargetResourceResult -GetTargetResourceResultProperties $getTargetResourceResultProperties
                }

                It 'Should return full package properties for present package without registry check parameters specified' {
                    $packageParameters = @{
                        Path = $script:msiLocation
                        ProductId = $script:packageId
                    }

                    Set-TargetResource -Ensure 'Present' @packageParameters
                    Clear-PackageCache

                    $getTargetResourceResult = Get-TargetResource @packageParameters
                    $getTargetResourceResultProperties = @( 'Ensure', 'Name', 'InstallSource', 'InstalledOn', 'ProductId', 'Size', 'Version', 'PackageDescription', 'Publisher' )

                    Test-GetTargetResourceResult -GetTargetResourceResult $getTargetResourceResult -GetTargetResourceResultProperties $getTargetResourceResultProperties
                }
            }

            Context 'Test-TargetResource' {
                It 'Should return correct value when package is absent' {
                    $testTargetResourceResult = Test-TargetResource `
                        -Ensure 'Present' `
                        -Path $script:msiLocation `
                        -ProductId $script:packageId

                    $testTargetResourceResult | Should Be $false

                    $testTargetResourceResult = Test-TargetResource `
                        -Ensure 'Absent' `
                        -Path $script:msiLocation `
                        -ProductId $script:packageId

                    $testTargetResourceResult | Should Be $true
                }

                It 'Should return correct value when package is present' {
                    Set-TargetResource -Ensure 'Present' -Path $script:msiLocation -ProductId $script:packageId

                    Clear-PackageCache

                    Test-PackageInstalledById -ProductId $script:packageId | Should Be $true

                    $testTargetResourceResult = Test-TargetResource `
                            -Ensure 'Present' `
                            -Path $script:msiLocation `
                            -ProductId $script:packageId `

                    $testTargetResourceResult | Should Be $true

                    $testTargetResourceResult = Test-TargetResource `
                        -Ensure 'Absent' `
                        -Path $script:msiLocation `
                        -ProductId $script:packageId `

                    $testTargetResourceResult | Should Be $false
                }
            }

            Context 'Set-TargetResource' {
                It 'Should correctly install and remove a .msi package' {
                    Set-TargetResource -Ensure 'Present' -Path $script:msiLocation -ProductId $script:packageId

                    Test-PackageInstalledById -ProductId $script:packageId | Should Be $true

                    $getTargetResourceResult = Get-TargetResource -Path $script:msiLocation -ProductId $script:packageId

                    $getTargetResourceResult.Version | Should Be '1.2.3.4'
                    $getTargetResourceResult.InstalledOn | Should Be ('{0:d}' -f [DateTime]::Now.Date)
                    $getTargetResourceResult.ProductId | Should Be $script:packageId

                    # Can't figure out how to set this within the MSI.
                    # $getTargetResourceResult.PackageDescription | Should Be 'A package for unit testing'

                    [Math]::Round($getTargetResourceResult.Size, 2) | Should Be 0.03

                    Set-TargetResource -Ensure 'Absent' -Path $script:msiLocation -ProductId $script:packageId

                    Test-PackageInstalledById -ProductId $script:packageId | Should Be $false
                }

                It 'Should throw with incorrect product id' {
                    $wrongPackageId = '{deadbeef-80c6-41e6-a1b9-8bdb8a050272}'

                    { Set-TargetResource -Ensure 'Present' -Path $script:msiLocation -ProductId $wrongPackageId } | Should Throw
                }

                It 'Should correctly install and remove a package from a HTTP URL' {
                    $baseUrl = 'http://localhost:1242/'
                    $msiUrl = "$baseUrl" + 'package.msi'

                    $fileServerStarted = $null

                    try
                    {
                        $fileServerStarted = New-Object System.Threading.EventWaitHandle ($false, [System.Threading.EventResetMode]::ManualReset,
                                    'HttpIntegrationTest.FileServerStarted')
                        $fileServerStarted.Reset()

                        'Http tests:' > $script:logFile

                        $job = Start-Server -FilePath $script:msiLocation -LogPath $script:logFile -Https $false              

                        $fileServerStarted.WaitOne(30000)

                        { Set-TargetResource -Ensure 'Present' -Path $baseUrl -ProductId $script:packageId } | Should Throw

                        Set-TargetResource -Ensure 'Present' -Path $msiUrl -ProductId $script:packageId
                        Test-PackageInstalledById -ProductId $script:packageId | Should Be $true

                        Set-TargetResource -Ensure 'Absent' -Path $msiUrl -ProductId $script:packageId
                        Test-PackageInstalledById -ProductId $script:packageId | Should Be $false
                    }
                    finally
                    {
                        if ($fileServerStarted)
                        {
                            $fileServerStarted.Dispose()
                        }

                        Stop-Job -Job $job
                        Remove-Job -Job $job
                    }
                }

                It 'Should correctly install and remove a package from a HTTPS URL' -Skip:$script:skipHttpsTest {

                    $baseUrl = 'https://localhost:1243/'
                    $msiUrl = "$baseUrl" + 'package.msi'

                    $fileServerStarted = $null

                    try
                    {
                        $fileServerStarted = New-Object System.Threading.EventWaitHandle ($false, [System.Threading.EventResetMode]::ManualReset,
                                    'HttpIntegrationTest.FileServerStarted')
                        $fileServerStarted.Reset()

                        'Https tests:' >> $script:logFile

                        $job = Start-Server -FilePath $script:msiLocation -LogPath $script:logFile -Https $true              

                        $fileServerStarted.WaitOne(30000)

                        { Set-TargetResource -Ensure 'Present' -Path $baseUrl -ProductId $script:packageId } | Should Throw

                        Set-TargetResource -Ensure 'Present' -Path $msiUrl -ProductId $script:packageId
                        Test-PackageInstalledById -ProductId $script:packageId | Should Be $true

                        Set-TargetResource -Ensure 'Absent' -Path $msiUrl -ProductId $script:packageId
                        Test-PackageInstalledById -ProductId $script:packageId | Should Be $false
                    }
                    finally
                    {
                        if ($fileServerStarted)
                        {
                            $fileServerStarted.Dispose()
                        }

                        Stop-Job -Job $job
                        Remove-Job -Job $job
                    }
                }

                It 'Should write to the specified log path' {
                    $logPath = Join-Path -Path $script:testDirectoryPath -ChildPath 'TestMsiLog.txt'

                    if (Test-Path -Path $logPath)
                    {
                        Remove-Item -Path $logPath -Force
                    }

                    Set-TargetResource -Ensure 'Present' -Path $script:msiLocation -LogPath $logPath -ProductId $script:packageId

                    Test-Path -Path $logPath | Should Be $true
                    Get-Content -Path $logPath | Should Not Be $null
                }

                It 'Should add space after .MSI installation arguments (#195)' {
                    Mock Invoke-Process -ParameterFilter { $Process.StartInfo.Arguments.EndsWith($script:msiArguments) } { return @{ ExitCode = 0 } }
                    Mock Test-TargetResource { return $false }
                    Mock Get-ProductEntry { return $script:packageId }

                    $packageParameters = @{
                        Path = $script:msiLocation
                        ProductId = $script:packageId
                        Arguments = $script:msiArguments
                    }

                    Set-TargetResource -Ensure 'Present' @packageParameters

                    Assert-MockCalled Invoke-Process -ParameterFilter { $Process.StartInfo.Arguments.EndsWith(" $script:msiArguments") } -Scope It
                }

                It 'Should not check for product installation when rebooted is required (#52)' {
                    Mock Invoke-Process { return [PSCustomObject] @{ ExitCode = 3010 } }
                    Mock Test-TargetResource { return $false }
                    Mock Get-ProductEntry { }

                    $packageParameters = @{
                        Path = $script:msiLocation
                        ProductId = $script:packageId
                    }

                    { Set-TargetResource -Ensure 'Present' @packageParameters } | Should Not Throw
                }

                It 'Should install package using user credentials when specified' {
                    Mock Invoke-PInvoke { }
                    Mock Test-TargetResource { return $false }
                    Mock Get-ProductEntry { return $script:packageId }

                    $packageCredential = [System.Management.Automation.PSCredential]::Empty
                    $packageParameters = @{
                        Path = $script:msiLocation
                        ProductId = $script:packageId
                        RunAsCredential = $packageCredential
                    }

                    Set-TargetResource -Ensure 'Present' @packageParameters

                    Assert-MockCalled Invoke-PInvoke -ParameterFilter { $RunAsCredential -eq $packageCredential} -Scope It
                }
            }

            Context 'Get-MsiTool' {
                It 'Should add MSI tools in the Microsoft.Windows.DesiredStateConfiguration.xPackageResource namespace' {
                    $addTypeResult = @{ Namespace = 'Mock not called' }
                    Mock -CommandName 'Add-Type' -MockWith { $addTypeResult['Namespace'] = $Namespace }

                    $msiTool = Get-MsiTool

                    if (([System.Management.Automation.PSTypeName]'Microsoft.Windows.DesiredStateConfiguration.xPackageResource.MsiTools').Type)
                    {
                        Assert-MockCalled -CommandName 'Add-Type' -Times 0

                        $msiTool | Should Be ([System.Management.Automation.PSTypeName]'Microsoft.Windows.DesiredStateConfiguration.xPackageResource.MsiTools').Type
                    }
                    else
                    {
                        Assert-MockCalled -CommandName 'Add-Type' -Times 1

                        $addTypeResult['Namespace'] | Should Be 'Microsoft.Windows.DesiredStateConfiguration.xPackageResource'
                        $msiTool | Should Be $null
                    }
                }
            }
        }
    }
}
finally
{
    Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
}
