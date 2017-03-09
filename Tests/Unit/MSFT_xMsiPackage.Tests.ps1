$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

Describe 'xMsiPackage Unit Tests' {
    BeforeAll {
        # Import CommonTestHelper for Enter-DscResourceTestEnvironment, Exit-DscResourceTestEnvironment
        $script:testsFolderFilePath = Split-Path $PSScriptRoot -Parent
        $script:commonTestHelperFilePath = Join-Path -Path $testsFolderFilePath -ChildPath 'CommonTestHelper.psm1'
        Import-Module -Name $commonTestHelperFilePath

        $script:testEnvironment = Enter-DscResourceTestEnvironment `
            -DscResourceModuleName 'xPSDesiredStateConfiguration' `
            -DscResourceName 'MSFT_xMsiPackage' `
            -TestType 'Unit'
    }

    AfterAll {
        Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
    }

    InModuleScope 'MSFT_xMsiPackage' {

        $testUsername = 'TestUsername'
        $testPassword = 'TestPassword'
        $secureTestPassword = ConvertTo-SecureString -String $testPassword -AsPlainText -Force

        $script:testCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @( $testUsername, $secureTestPassword )
        $script:testProductId = '{deadbeef-80c6-41e6-a1b9-8bdb8a05027f}'
        $script:testIdentifyingNumber = '{DEADBEEF-80C6-41E6-A1B9-8BDB8A05027F}'
        $script:testPath = 'TestPath'

        Describe 'Get-TargetResource' {

            function Get-TestName {
                [OutputType([String])]
                [CmdletBinding()]
                param
                (
                    [Parameter(Mandatory = $true)]
                    [String]
                    $Title,

                    [Boolean]
                    $IsCalled = $true
                )

                if ($IsCalled)
                {
                    return 'Should ' + $Title
                }
                else
                {
                    return 'Should not ' + $Title
                }
            }

            function Invoke-GetTargetResourceTest {
                [CmdletBinding()]
                param
                (
                    [Parameter(Mandatory = $true)]
                    [Hashtable]
                    $GetTargetResourceParameters,

                    [Parameter(Mandatory = $true)]
                    [Hashtable]
                    $MocksCalled
                )

                It 'Should not throw' {
                    { $null = Get-TargetResource @GetTargetResourceParameters } | Should Not Throw
                }

                $testName = Get-TestName -Title 'convert product ID to identifying number' -IsCalled $MocksCalled.ConvertProductIdToIdentifyingNumber
                It $MocksCalled[0] {
                    Assert-MockCalled -CommandName 'Convert-ProductIdToIdentifyingNumber' -Exactly $MocksCalled.ConvertProductIdToIdentifyingNumber -Scope 'Context'
                }

                It 'Should retrieve the product entry' {
                    Assert-MockCalled -CommandName 'Get-ProductEntry' -Exactly 1 -Scope 'Context'
                }

                $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters

                It 'Should return a Hashtable' {
                    $getTargetResourceResult -is [Hashtable] | Should Be $true
                }

                It 'Should return a Hashtable with 2 properties' {
                    $getTargetResourceResult.Keys.Count | Should Be 2
                }

                It 'Should return a Hashtable with the Ensure property as Absent' {
                    $getTargetResourceResult.Ensure | Should Be 'Absent'
                }

                It 'Should return a Hashtable with the ProductId property as the returned identifying number' {
                    $getTargetResourceResult.ProductId | Should Be $script:testIdentifyingNumber
                }
            }

            Mock -CommandName 'Convert-ProductIdToIdentifyingNumber' -MockWith { return $script:testIdentifyingNumber }
            Mock -CommandName 'Get-ProductEntry' -MockWith { return $null }

            Context 'MSI package does not exist' {
                $getTargetResourceParameters = @{
                    ProductId = $script:testProductId
                    Path = $script:testPath
                }

                Invoke-GetTargetResourceTest -GetTargetResourceParameters $getTargetResourceParameters -MocksCalled @{ConvertProductIdToIdentifyingNumber = 1}

                It 'Should not throw' {
                    { $null = Get-TargetResource @getTargetResourceParameters } | Should Not Throw
                }

                It 'Should convert product ID to identifying number' {
                    Assert-MockCalled -CommandName 'Convert-ProductIdToIdentifyingNumber' -Exactly 1 -Scope 'Context'
                }

                It 'Should retrieve the product entry' {
                    Assert-MockCalled -CommandName 'Get-ProductEntry' -Exactly 1 -Scope 'Context'
                }

                $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters

                It 'Should return a Hashtable' {
                    $getTargetResourceResult -is [Hashtable] | Should Be $true
                }

                It 'Should return a Hashtable with 2 properties' {
                    $getTargetResourceResult.Keys.Count | Should Be 2
                }

                It 'Should return a Hashtable with the Ensure property as Absent' {
                    $getTargetResourceResult.Ensure | Should Be 'Absent'
                }

                It 'Should return a Hashtable with the ProductId property as the returned identifying number' {
                    $getTargetResourceResult.ProductId | Should Be $script:testIdentifyingNumber
                }
            }
        }
            
        Describe 'Set-TargetResource' {
            
            Context 'set tests' {
                $setTargetResourceParameters = @{
                    ProductId = 'TestProductId'
                    Path = 'TestPath'
                    Ensure = 'Present'
                    Arguments = 'TestArguments'
                    Credential = $script:testCredential
                    LogPath = 'TestLogPath'
                    FileHash = 'TestFileHash'
                    HashAlgorithm = 'Sha256'
                    SignerSubject = 'TestSignerSubject'
                    SignerThumbprint = 'TestSignerThumbprint'
                    ServerCertificateValidationCallback = 'TestValidationCallback'
                    RunAsCredential = $script:testCredential
                }
            }
        }

        Describe 'Test-TargetResource' {
            Mock -CommandName 'Convert-ProductIdToIdentifyingNumber' -MockWith { return $script:testIdentifyingNumber }
            Mock -CommandName 'Get-ProductEntry' -MockWith { return $null }

            Context 'test tests' {
                $testTargetResourceParameters = @{
                    ProductId = $script:testProductId
                    Path = $script:testPath
                    Ensure = 'Present'
                }

                It 'Should not throw' {
                    { $null = Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                }

                It 'Should return false' {
                    Test-TargetResource @testTargetResourceParameters | Should Be $false
                }
            }
        }
    }
}
