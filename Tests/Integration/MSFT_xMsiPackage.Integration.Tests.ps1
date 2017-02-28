$script:testsFolderFilePath = Split-Path $PSScriptRoot -Parent
$script:packageTestHelperFilePath = Join-Path -Path $script:testsFolderFilePath -ChildPath 'MSFT_xPackageResource.TestHelper.psm1'
$script:commonTestHelperFilePath = Join-Path -Path $script:testsFolderFilePath -ChildPath 'CommonTestHelper.psm1'
Import-Module -Name $script:packageTestHelperFilePath
Import-Module -Name $script:commonTestHelperFilePath

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DscResourceModuleName 'xPSDesiredStateConfiguration' `
    -DscResourceName 'MSFT_xMsiPackage' `
    -TestType 'Unit'

try
{
    InModuleScope 'MSFT_xMsiPackage' {
        Describe 'MSFT_xMsiPackage integration Tests' {
            BeforeAll {

                $script:skipHttpsTest = $true

                $script:testDirectoryPath = Join-Path -Path $PSScriptRoot -ChildPath 'MSFT_xPackageResourceTests'

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

                $script:testExecutablePath = Join-Path -Path $script:testDirectoryPath -ChildPath 'TestExecutable.exe'

                $null = New-TestExecutable -DestinationPath $script:testExecutablePath

                $null = Clear-xPackageCache
            }

            BeforeEach {
                $null = Clear-xPackageCache

                if (Test-PackageInstalledById -ProductId $script:packageId)
                {
                    $null = Start-Process -FilePath 'msiexec.exe' -ArgumentList @("/x$script:packageId", '/passive') -Wait
                    $null = Start-Sleep -Seconds 1
                }

                if (Test-PackageInstalledById -ProductId $script:packageId)
                {
                    throw 'Package could not be removed.'
                }
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
                    Clear-xPackageCache

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

                    Clear-xPackageCache

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
                    New-MockFileServer -FilePath $script:msiLocation

                    # Test pipe connection as testing server readiness
                    $pipe = New-Object -TypeName 'System.IO.Pipes.NamedPipeServerStream' -ArgumentList @( '\\.\pipe\dsctest1' )
                    $pipe.WaitForConnection()
                    $pipe.Dispose()

                    { Set-TargetResource -Ensure 'Present' -Path $baseUrl -ProductId $script:packageId } | Should Throw

                    Set-TargetResource -Ensure 'Present' -Path $msiUrl -ProductId $script:packageId
                    Test-PackageInstalledById -ProductId $script:packageId | Should Be $true

                    Set-TargetResource -Ensure 'Absent' -Path $msiUrl -ProductId $script:packageId
                    Test-PackageInstalledById -ProductId $script:packageId | Should Be $false

                    $pipe = New-Object -TypeName 'System.IO.Pipes.NamedPipeClientStream' -ArgumentList @( '\\.\pipe\dsctest2' )
                    $pipe.Connect()
                    $pipe.Dispose()
                }

                It 'Should correctly install and remove a package from a HTTPS URL' -Skip:$script:skipHttpsTest {
                    $baseUrl = 'https://localhost:1243/'
                    $msiUrl = "$baseUrl" + 'package.msi'
                    New-MockFileServer -FilePath $script:msiLocation -Https

                    # Test pipe connection as testing server reasdiness
                    $pipe = New-Object -TypeName 'System.IO.Pipes.NamedPipeServerStream' -ArgumentList @( '\\.\pipe\dsctest1' )
                    $pipe.WaitForConnection()
                    $pipe.Dispose()

                    { Set-TargetResource -Ensure 'Present' -Path $baseUrl -ProductId $script:packageId } | Should Throw

                    Set-TargetResource -Ensure 'Present' -Path $msiUrl -ProductId $script:packageId
                    Test-PackageInstalledById -ProductId $script:packageId | Should Be $true

                    Set-TargetResource -Ensure 'Absent' -Path $msiUrl -ProductId $script:packageId
                    Test-PackageInstalledById -ProductId $script:packageId | Should Be $false

                    $pipe = New-Object -TypeName 'System.IO.Pipes.NamedPipeClientStream' -ArgumentList @( '\\.\pipe\dsctest2' )
                    $pipe.Connect()
                    $pipe.Dispose()
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
                    #Mock Get-ProductEntry { return $script:packageId }

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
                    #Mock Get-ProductEntry { }

                    $packageParameters = @{
                        Path = $script:msiLocation
                        ProductId = $script:packageId
                    }

                    { Set-TargetResource -Ensure 'Present' @packageParameters } | Should Not Throw
                }

                It 'Should install package using user credentials when specified' {
                    Mock Invoke-PInvoke { }
                    Mock Test-TargetResource { return $false }

                    $packageCredential = [System.Management.Automation.PSCredential]::Empty
                    $packageParameters = @{
                        Path = $script:msiLocation
                        ProductId = $script:packageId
                        RunAsCredential = $packageCredential
                    }

                    Set-TargetResource -Ensure 'Present' @packageParameters

                    Assert-MockCalled Invoke-PInvoke -ParameterFilter { $Credential -eq $packageCredential} -Scope It
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
