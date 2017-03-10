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

        # This registry key is used ONLY for its type (Microsoft.Win32.RegistryKey). It is not actually accessed in any way during these tests.
        $script:mockProductEntry = [Microsoft.Win32.Registry]::CurrentConfig

        $script:mockProductEntryInfo = @{
            Name = 'TestDisplayName'
            InstallSource = 'TestInstallSource'
            InstalledOn = 'TestInstalledOnDate'
            Size = 1024
            Version = '1.2.3.4'
            PackageDescription = 'Test Description'
            Publisher = 'Test Publisher'
            Ensure = 'Present'
        }

        $script:functionAssertTitles = @{
            'Convert-ProductIdToIdentifyingNumber' = 'convert product ID to identifying number.'
            'Get-ProductEntry' = 'retrieve product entry.'
            'Get-ProductEntryInfo' = 'retrieve product entry info.'
        }

        function Get-TestName
        {
            [OutputType([String])]
            [CmdletBinding()]
            param
            (
                [Parameter(Mandatory = $true)]
                [String]
                $Command,

                [Boolean]
                $IsCalled = $true
            )

            if ($IsCalled)
            {
                return 'Should ' + $script:functionAssertTitles.$Command
            }
            else
            {
                return 'Should not ' + $script:functionAssertTitles.$Command
            }
        }

        Describe 'Get-TargetResource' {
            function Invoke-GetTargetResourceTest {
                [CmdletBinding()]
                param
                (
                    [Parameter(Mandatory = $true)]
                    [Hashtable]
                    $GetTargetResourceParameters,

                    [Parameter(Mandatory = $true)]
                    [Hashtable]
                    $MocksCalled,

                    [Parameter(Mandatory = $true)]
                    [Hashtable]
                    $ExpectedReturnValue
                )

                It 'Should not throw' {
                    { $null = Get-TargetResource @GetTargetResourceParameters } | Should Not Throw
                }

                foreach ($key in $MocksCalled.Keys)
                {
                    $testName = Get-TestName -Command $key -IsCalled $MocksCalled.$key

                    It $testName {
                        Assert-MockCalled -CommandName $key -Exactly $MocksCalled.$key -Scope 'Context'
                    }
                }

                $getTargetResourceResult = Get-TargetResource @GetTargetResourceParameters

                It 'Should return a Hashtable' {
                    $getTargetResourceResult -is [Hashtable] | Should Be $true
                }

                It "Should return a Hashtable with $($ExpectedReturnValue.Keys.Count) properties" {
                    $getTargetResourceResult.Keys.Count | Should Be $ExpectedReturnValue.Keys.Count
                }

                foreach ($key in $ExpectedReturnValue.Keys)
                {
                    It "Should return a Hashtable with the $key property as $($ExpectedReturnValue.$key)" {
                       $getTargetResourceResult.$key | Should Be $ExpectedReturnValue.$key
                    }
                }
            }

            $mocksCalled = @{
                'Convert-ProductIdToIdentifyingNumber' = 1
                'Get-ProductEntry' = 1
                'Get-ProductEntryInfo' = 0
            }

            Mock -CommandName 'Convert-ProductIdToIdentifyingNumber' -MockWith { return $script:testIdentifyingNumber }
            Mock -CommandName 'Get-ProductEntry' -MockWith { return $null }
            Mock -CommandName 'Get-ProductEntryInfo' -MockWith { return $script:mockProductEntryInfo }

            Context 'MSI package does not exist' {
                $getTargetResourceParameters = @{
                    ProductId = $script:testProductId
                    Path = $script:testPath
                }

                $expectedReturnValue = @{
                    Ensure = 'Absent'
                    ProductId = $script:testIdentifyingNumber
                }

                Invoke-GetTargetResourceTest -GetTargetResourceParameters $getTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ExpectedReturnValue $expectedReturnValue
            }

            Mock -CommandName 'Get-ProductEntry' -MockWith { return $script:mockProductEntry }

            Context 'MSI package does exist' {
                $getTargetResourceParameters = @{
                    ProductId = $script:testProductId
                    Path = $script:testPath
                }

                $expectedReturnValue = $script:mockProductEntryInfo
                $mocksCalled['Get-ProductEntryInfo'] = 1

                Invoke-GetTargetResourceTest -GetTargetResourceParameters $getTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ExpectedReturnValue $expectedReturnValue
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
