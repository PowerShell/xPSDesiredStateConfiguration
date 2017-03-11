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
        $script:testWrongProductId = 'wrongId'
        $script:testPath = Join-Path -Path Test-Drive -ChildPath 'test.msi'
        $script:destinationPath = Join-Path -Path $script:packageCacheLocation -ChildPath 'C:\'
        $script:testUriNonUnc = [Uri] $script:testPath
        $script:testUriHttp = [Uri] 'http://testPath'
        $script:testUriHttps = [Uri] 'https://testPath'
        $script:testUriFile = [Uri] 'file://testPath'

        $script:testFileOutStream = New-MockObject -Type 'System.IO.FileStream'
        $script:mockPSDrive = @{
            Root = 'mockRoot'
        }
        $script:mockProcess = @{
            ExitCode = 0
        }

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
            'Convert-ProductIdToIdentifyingNumber' = 'convert product ID to identifying number'
            'Get-ProductEntry' = 'retrieve product entry'
            'Get-ProductEntryInfo' = 'retrieve product entry info'
            'Test-TargetResource' = 'check to see if the resource is already in the desired state'
            'Assert-PathExtensionValid' = 'assert that the specified path extension is valid'
            'Convert-PathToUri' = 'convert the path to a URI'
            'Test-Path' = 'test that the path exists....'
            'Remove-Item' = 'remove .....'
            'New-Item' = 'create a new.....'
            'New-PSDrive' = 'create a new PS Drive'
            'New-Object' = 'create a new.....'
            'Assert-FileValid' = 'assert that the file is valid'
            'Get-MsiProductCode' = 'retrieve the MSI product code'
            'Invoke-PInvoke' = 'attempt to... what does this do?'
            'Invoke-Process' = 'attempt to ......not quite sure?'
            'Invoke-CimMethod' = 'attempt to invoke a cim method'
            'Close-Stream' = 'close the stream'
            'Copy-WebResponseToFileStream' = 'copy the web response to the file stream'
            'Get-ItemProperty' = 'retrieve the item property'
        }

        $script:errorMessageTitles = @{ ###Problem here since messeges passed in ususally contain a variable - could pass these in separately?


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
            <#
                .SYNOPSIS
                    Performs generic tests for Get-TargetResource, including checking that the
                    function does not throw, checking that all mocks are called the expected
                    number of times, and checking that the correct result is returned. If the function
                    is expected to throw, then this function should not be used.

                .PARAMETER GetTargetResourceParameters

                .PARAMETER MocksCalled

                .PARAMETER ExpectedReturnValue
            #>
            function Invoke-GetTargetResourceTest {
                [CmdletBinding()]
                param
                (
                    [Parameter(Mandatory = $true)]
                    [Hashtable]
                    $GetTargetResourceParameters,

                    [Parameter(Mandatory = $true)]
                    [Hashtable[]]
                    $MocksCalled,

                    [Parameter(Mandatory = $true)]
                    [Hashtable]
                    $ExpectedReturnValue
                )

                It 'Should not throw' {
                    { $null = Get-TargetResource @GetTargetResourceParameters } | Should Not Throw
                }

                foreach ($mock in $MocksCalled)
                {
                    $testName = Get-TestName -Command $mock.Command -IsCalled $mock.Times

                    It $testName {
                        Assert-MockCalled -CommandName $mock.Command -Exactly $mock.Times -Scope 'Context'
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

            Mock -CommandName 'Convert-ProductIdToIdentifyingNumber' -MockWith { return $script:testIdentifyingNumber }
            Mock -CommandName 'Get-ProductEntry' -MockWith { return $null }
            Mock -CommandName 'Get-ProductEntryInfo' -MockWith { return $script:mockProductEntryInfo }

            Context 'MSI package does not exist' {
                $getTargetResourceParameters = @{
                    ProductId = $script:testProductId
                    Path = $script:testPath
                }

                $mocksCalled = @(
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                    @{ Command = 'Get-ProductEntryInfo'; Times = 0 }
                )

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

                $mocksCalled = @(
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                    @{ Command = 'Get-ProductEntryInfo'; Times = 1 }
                )

                $expectedReturnValue = $script:mockProductEntryInfo

                Invoke-GetTargetResourceTest -GetTargetResourceParameters $getTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ExpectedReturnValue $expectedReturnValue
            }
        }
            
        Describe 'Set-TargetResource' {
            <#
                .SYNOPSIS
                    Performs generic tests for Set-TargetResource, including checking that the
                    function does not throw and checking that all mocks are called the expected
                    number of times. If the function is expected to throw, then this function
                    should not be used.

                .PARAMETER SetTargetResourceParameters

                .PARAMETER MocksCalled

                .PARAMETER ShouldThrow

                .PARAMETER ErrorMessage
            #>
            function Invoke-SetTargetResourceTest {
                [CmdletBinding()]
                param
                (
                    [Parameter(Mandatory = $true)]
                    [Hashtable]
                    $SetTargetResourceParameters,

                    [Parameter(Mandatory = $true)]
                    [Hashtable[]]
                    $MocksCalled,

                    [Boolean]
                    $ShouldThrow = $false,

                    [String]
                    $ErrorMessage = ''
                )

                if ($ShouldThrow)
                {
                    It "Should throw error: $ErrorMessage" {
                        { $null = Set-TargetResource @SetTargetResourceParameters } | Should Throw $ErrorMessage
                    }
                }
                else
                {
                    It 'Should not throw' {
                        { $null = Set-TargetResource @SetTargetResourceParameters } | Should Not Throw
                    }
                }

                foreach ($mock in $MocksCalled)
                {
                    $testName = Get-TestName -Command $mock.Command -IsCalled $mock.Times

                    It $testName {
                        Assert-MockCalled -CommandName $mock.Command -Exactly $mock.Times -Scope 'Context'
                    }
                }
            }

            $setTargetResourceParameters = @{
                ProductId = 'TestProductId'
                Path = $script:testPath
                Ensure = 'Present'
                Arguments = 'TestArguments'
                LogPath = 'TestLogPath'
                FileHash = 'TestFileHash'
                HashAlgorithm = 'Sha256'
                SignerSubject = 'TestSignerSubject'
                SignerThumbprint = 'TestSignerThumbprint'
                ServerCertificateValidationCallback = 'TestValidationCallback'
                RunAsCredential = $script:testCredential
            }
            
            Mock -CommandName 'Test-TargetResource' -MockWith { return $true }
            Mock -CommandName 'Assert-PathExtensionValid' -MockWith {}
            Mock -CommandName 'Convert-PathToUri' -MockWith { return $script:testUriFile }
            Mock -CommandName 'Convert-ProductIdToIdentifyingNumber' -MockWith { return $script:testIdentifyingNumber }
            Mock -CommandName 'Get-ProductEntry' -MockWith { return $null }
            Mock -CommandName 'Test-Path' -MockWith { return $true }
            Mock -CommandName 'Remove-Item' -MockWith { Throw }
            Mock -CommandName 'New-Item' -MockWith {}
            Mock -CommandName 'New-PSDrive' -MockWith { return $script:mockPSDrive }
            Mock -CommandName 'New-Object' -MockWith { Throw } -ParameterFilter { $TypeName -eq 'System.IO.FileStream' }
            Mock -CommandName 'Close-Stream' -MockWith {}
            Mock -CommandName 'Copy-WebResponseToFileStream' -MockWith {}
            Mock -CommandName 'Assert-FileValid' -MockWith {}
            Mock -CommandName 'Get-MsiProductCode' -MockWith { return $script:testWrongProductId }
            Mock -CommandName 'Invoke-PInvoke' -MockWith { Throw }
            Mock -CommandName 'Invoke-Process' -MockWith { Throw }
            Mock -CommandName 'Invoke-CimMethod' -MockWith {}
            Mock -CommandName 'Get-ItemProperty' -MockWith { return $null }
            Mock -CommandName 'Remove-PSDrive' -MockWith {}
            
            Context 'Resource is in desired state already' {

                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 0 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled  
            }

            Mock -CommandName 'Test-TargetResource' -MockWith { return $false }

            Context 'Error opening Log' {

                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 1 }
                    @{ Command = 'Remove-Item'; Times = 1 }
                    @{ Command = 'New-Item'; Times = 0 }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.CouldNotOpenLog -f $setTargetResourceParameters.LogPath)
            }

            Mock -CommandName 'Remove-Item' -MockWith {}

            Context 'Uri scheme is File and specified ProductId does not match actual product code' {

                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 2 }
                    @{ Command = 'Remove-Item'; Times = 1 }
                    @{ Command = 'New-Item'; Times = 1 }
                    @{ Command = 'New-PSDrive'; Times = 1 }
                    @{ Command = 'Copy-WebResponseToFileStream'; Times = 0 }
                    @{ Command = 'Assert-FileValid'; Times = 1 }
                    @{ Command = 'Get-MsiProductCode'; Times = 1 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.InvalidId -f $script:testIdentifyingNumber, $script:testWrongProductId)
            }

            Mock -CommandName 'Convert-PathToUri' -MockWith { return $script:testUriHttp }

            Context 'Uri scheme is http and error occurred while attempting to open destination file' {

                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 2 }
                    @{ Command = 'Remove-Item'; Times = 1 }
                    @{ Command = 'New-Item'; Times = 1 }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.CouldNotOpenDestFile -f $script:destinationPath)
            }

            Mock -CommandName 'Convert-PathToUri' -MockWith { return $script:testUriHttps }
            Mock -CommandName 'New-Object' -MockWith { return $script:testFileOutStream } -ParameterFilter { $TypeName -eq 'System.IO.FileStream' }
            Mock -CommandName 'Test-Path' -MockWith { return $false } -ParameterFilter { $Path -eq $script:destinationPath}

            Context 'Uri scheme is https and specified Path does not exist' {

                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 0 }
                    @{ Command = 'Test-Path'; Times = 3 }
                    @{ Command = 'Remove-Item'; Times = 1 }
                    @{ Command = 'New-Item'; Times = 1 }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'New-Object'; Times = 1 }
                    @{ Command = 'Copy-WebResponseToFileStream'; Times = 1 }
                    @{ Command = 'Close-Stream'; Times = 1 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.PathDoesNotExist -f $script:destinationPath)
            }

            Mock -CommandName 'Convert-PathToUri' -MockWith { return $script:testUriNonUnc }
            Mock -CommandName 'Get-MsiProductCode' -MockWith { return $script:testIdentifyingNumber }

            Context 'Uri scheme is not file, http, or https and RunAsCredential is specified and starting the process fails' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 0 }
                    @{ Command = 'Test-Path'; Times = 2 }
                    @{ Command = 'Remove-Item'; Times = 1 }
                    @{ Command = 'New-Item'; Times = 1 }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'Copy-WebResponseToFileStream'; Times = 0 }
                    @{ Command = 'Assert-FileValid'; Times = 1 }
                    @{ Command = 'Get-MsiProductCode'; Times = 1 }
                    @{ Command = 'Invoke-PInvoke'; Times = 1 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.CouldNotStartProcess -f $setTargetResourceParameters.Path)
            }

            Context 'Uri scheme is not file, http, or https and RunAsCredential is specified and starting the process fails' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 0 }
                    @{ Command = 'Test-Path'; Times = 2 }
                    @{ Command = 'Remove-Item'; Times = 1 }
                    @{ Command = 'New-Item'; Times = 1 }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'Copy-WebResponseToFileStream'; Times = 0 }
                    @{ Command = 'Assert-FileValid'; Times = 1 }
                    @{ Command = 'Get-MsiProductCode'; Times = 1 }
                    @{ Command = 'Invoke-PInvoke'; Times = 1 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.CouldNotStartProcess -f $setTargetResourceParameters.Path)
            }

            $setTargetResourceParameters.Remove('RunAsCredential')

            Context 'Uri scheme is not file, http, or https and RunAsCredential is not specified and starting the process fails' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 0 }
                    @{ Command = 'Test-Path'; Times = 2 }
                    @{ Command = 'Remove-Item'; Times = 1 }
                    @{ Command = 'New-Item'; Times = 1 }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'Copy-WebResponseToFileStream'; Times = 0 }
                    @{ Command = 'Assert-FileValid'; Times = 1 }
                    @{ Command = 'Get-MsiProductCode'; Times = 1 }
                    @{ Command = 'Invoke-Process'; Times = 1 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.CouldNotStartProcess -f $setTargetResourceParameters.Path)
            }

            Mock -CommandName 'Invoke-Process' -MockWith { return $script:mockProcess }

            Context 'Uri scheme is not file, http, or https and RunAsCredential is not specified and starting the process succeeds but there is a post validation error' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 2 }
                    @{ Command = 'Remove-Item'; Times = 1 }
                    @{ Command = 'New-Item'; Times = 1 }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'Copy-WebResponseToFileStream'; Times = 0 }
                    @{ Command = 'Assert-FileValid'; Times = 1 }
                    @{ Command = 'Get-MsiProductCode'; Times = 1 }
                    @{ Command = 'Invoke-Process'; Times = 1 }
                    @{ Command = 'Invoke-CimMethod'; Times = 1 }
                    @{ Command = 'Get-ItemProperty'; Times = 1 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.PostValidationError -f $setTargetResourceParameters.Path)
            }

            Mock -CommandName 'Convert-PathToUri' -MockWith { return $script:testUriHttp }
            Mock -CommandName 'Test-Path' -MockWith { return $true } -ParameterFilter { $Path -eq $script:destinationPath}

            Context 'Uri scheme is http, RunAsCredential is not specified and starting the process succeeds but there is a post validation error' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 3 }
                    @{ Command = 'Remove-Item'; Times = 2 }
                    @{ Command = 'New-Item'; Times = 1 }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'Copy-WebResponseToFileStream'; Times = 1 }
                    @{ Command = 'Assert-FileValid'; Times = 1 }
                    @{ Command = 'Get-MsiProductCode'; Times = 1 }
                    @{ Command = 'Invoke-Process'; Times = 1 }
                    @{ Command = 'Invoke-CimMethod'; Times = 1 }
                    @{ Command = 'Get-ItemProperty'; Times = 1 }
                    @{ Command = 'Close-Stream'; Times = 1 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.PostValidationError -f $setTargetResourceParameters.Path)
            }

            Mock -CommandName 'Convert-PathToUri' -MockWith { return $script:testUriNonUnc }
            Mock -CommandName 'Get-ProductEntry' -MockWith { return $script:mockProductEntry }

            Context 'Uri scheme is not file, http, or https and RunAsCredential is not specified and installation succeeds' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 2 }
                    @{ Command = 'Remove-Item'; Times = 1 }
                    @{ Command = 'New-Item'; Times = 1 }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'Copy-WebResponseToFileStream'; Times = 0 }
                    @{ Command = 'Assert-FileValid'; Times = 1 }
                    @{ Command = 'Get-MsiProductCode'; Times = 1 }
                    @{ Command = 'Invoke-Process'; Times = 1 }
                    @{ Command = 'Invoke-CimMethod'; Times = 1 }
                    @{ Command = 'Get-ItemProperty'; Times = 1 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $false `
            }

            $setTargetResourceParameters.Ensure = 'Absent'

            Context 'Uri scheme is not file, http, or https and RunAsCredential is not specified and uninstallation succeeds' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 1 }
                    @{ Command = 'Remove-Item'; Times = 1 }
                    @{ Command = 'New-Item'; Times = 1 }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'Copy-WebResponseToFileStream'; Times = 0 }
                    @{ Command = 'Assert-FileValid'; Times = 0 }
                    @{ Command = 'Get-MsiProductCode'; Times = 0 }
                    @{ Command = 'Invoke-Process'; Times = 1 }
                    @{ Command = 'Invoke-CimMethod'; Times = 1 }
                    @{ Command = 'Get-ItemProperty'; Times = 1 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $false `
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
