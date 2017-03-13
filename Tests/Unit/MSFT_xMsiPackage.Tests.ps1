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

        data testStrings
        {
            ConvertFrom-StringData -StringData @'
Convert-ProductIdToIdentifyingNumber = convert the product ID to the identifying number
Get-ProductEntry = retrieve the product entry
Get-ProductEntryInfo = retrieve the product entry info
Test-TargetResource = check to see if the resource is already in the desired state
Assert-PathExtensionValid = assert that the specified path extension is valid
Convert-PathToUri = convert the path to a URI
Test-Path = test that the path at '{0}' exists
Remove-Item = remove '{0}'
New-Item = create a new {0}
New-PSDrive = create a new PS Drive
New-Object = create a new object of type {0}
Assert-FileValid = assert that the file is valid
Get-MsiProductCode = retrieve the MSI product code
Invoke-PInvoke = attempt to install/uninstall the MSI package with PInvoke
Invoke-Process = attempt to install/uninstall the MSI package under the process
Invoke-CimMethod = attempt to invoke a cim method to check if reboot is required
Close-Stream = close the stream
Copy-WebResponseToFileStream = copy the web response to the file stream
Get-ItemProperty = retrieve the registry data
'@
        }

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

        # Used to create the names of the tests that check to ensure the correct error is thrown.
        $script:errorMessageTitles = @{
            CouldNotOpenLog = 'not being able to open the log path'
            InvalidId = 'the specified product ID not matching the actual product ID'
            CouldNotOpenDestFile = 'not being able to open the destination file to write to'
            PathDoesNotExist = 'not being able to find the path'
            CouldNotStartProcess = 'not being able to start the process'
            PostValidationError = 'not being able to find the package after installation'
        }

        <#
            .SYNOPSIS
                Retrieves the name of the test for asserting that the given function is called.
        
            .PARAMETER IsCalled
                Indicates whether the function should be called or not.
        
            .PARAMETER Custom
                An optional string to include in the test name to make the name more descriptive.
        #>
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
                $IsCalled = $true,

                [String]
                $Custom = ''
            )

            $testName = ''

            if (-not [String]::IsNullOrEmpty($Custom))
            {
                $testName = ($testStrings.$Command -f $Custom)
            }
            else
            {
                $testName = $testStrings.$Command
            }

            if ($IsCalled)
            {
                return 'Should ' + $testName
            }
            else
            {
                return 'Should not ' + $testName
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
                    The parameters that should be passed to Get-TargetResource for this test.

                .PARAMETER MocksCalled
                    An array of the mocked commands that should be called for this test.
                    Each item in the array is a hashtable that contains the name of the command
                    being mocked and the number of times it is called (can be 0).

                .PARAMETER ExpectedReturnValue
                    The expected hashtable that Get-TargetResource should return for this test.
            #>
            function Invoke-GetTargetResourceTest
            {
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
                    number of times.

                .PARAMETER SetTargetResourceParameters
                    The parameters that should be passed to Set-TargetResource for this test.

                .PARAMETER MocksCalled
                    An array of the mocked commands that should be called for this test.
                    Each item in the array is a hashtable that contains the name of the command
                    being mocked, the number of times it is called (can be 0) and, optionally,
                    an extra custom string to make the test name more descriptive.

                .PARAMETER ShouldThrow
                    Indicates whether the function should throw or not. If this is set to True
                    then ErrorMessage and ErrorTestName should also be passed.

                .PARAMETER ErrorMessage
                    The error message that should be thrown if the function is supposed to throw.

                .PARAMETER ErrorTestName
                    The string that should be used to create the name of the test that checks for
                    the correct error being thrown.
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
                    $ErrorMessage = '',

                    [String]
                    $ErrorTestName = ''
                )

                if ($ShouldThrow)
                {
                    It "Should throw an error for $ErrorTestName" {
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

                    if ($mock.Keys -contains 'Custom')
                    {
                        $testName = Get-TestName -Command $mock.Command -IsCalled $mock.Times -Custom $mock.Custom
                    }

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
                    @{ Command = 'Test-Path'; Times = 1; Custom = 'Path' }
                    @{ Command = 'Remove-Item'; Times = 1; Custom = $setTargetResourceParameters.LogPath }
                    @{ Command = 'New-Item'; Times = 0; Custom = $setTargetResourceParameters.LogPath }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.CouldNotOpenLog -f $setTargetResourceParameters.LogPath) `
                                             -ErrorTestName $script:errorMessageTitles.CouldNotOpenLog
            }

            Mock -CommandName 'Remove-Item' -MockWith {}

            Context 'Uri scheme is File and specified ProductId does not match actual product code' {

                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 2; Custom = 'Path' }
                    @{ Command = 'Remove-Item'; Times = 1; Custom = $setTargetResourceParameters.LogPath }
                    @{ Command = 'New-Item'; Times = 1; Custom = $setTargetResourceParameters.LogPath }
                    @{ Command = 'New-PSDrive'; Times = 1 }
                    @{ Command = 'Copy-WebResponseToFileStream'; Times = 0 }
                    @{ Command = 'Assert-FileValid'; Times = 1 }
                    @{ Command = 'Get-MsiProductCode'; Times = 1 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.InvalidId -f $script:testIdentifyingNumber, $script:testWrongProductId) `
                                             -ErrorTestName $script:errorMessageTitles.InvalidId
            }

            Mock -CommandName 'Convert-PathToUri' -MockWith { return $script:testUriHttp }

            Context 'Uri scheme is http and error occurred while attempting to open destination file' {

                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 2; Custom = 'Path' }
                    @{ Command = 'Remove-Item'; Times = 1; Custom = $setTargetResourceParameters.LogPath }
                    @{ Command = 'New-Item'; Times = 1; Custom = $setTargetResourceParameters.LogPath }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.CouldNotOpenDestFile -f $script:destinationPath) `
                                             -ErrorTestName $script:errorMessageTitles.CouldNotOpenDestFile
            }

            Mock -CommandName 'Convert-PathToUri' -MockWith { return $script:testUriHttps }
            Mock -CommandName 'New-Object' -MockWith { return $script:testFileOutStream } -ParameterFilter { $TypeName -eq 'System.IO.FileStream' }
            Mock -CommandName 'Test-Path' -MockWith { return $false } -ParameterFilter { $Path -eq $script:destinationPath }
            $setTargetResourceParameters.Remove('LogPath')

            Context 'Uri scheme is https and specified Path does not exist' {

                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 0 }
                    @{ Command = 'Test-Path'; Times = 2; Custom = 'Path' }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'New-Object'; Times = 1; Custom = 'System.IO.FileStream' }
                    @{ Command = 'Copy-WebResponseToFileStream'; Times = 1 }
                    @{ Command = 'Close-Stream'; Times = 1 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.PathDoesNotExist -f $script:destinationPath) `
                                             -ErrorTestName $script:errorMessageTitles.PathDoesNotExist
            }

            Mock -CommandName 'Convert-PathToUri' -MockWith { return $script:testUriNonUnc }
            Mock -CommandName 'Get-MsiProductCode' -MockWith { return $script:testIdentifyingNumber }

            Context 'Uri scheme is not file, http, or https, RunAsCredential is specified and starting the process fails' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 0 }
                    @{ Command = 'Test-Path'; Times = 1; Custom = 'Path' }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'Copy-WebResponseToFileStream'; Times = 0 }
                    @{ Command = 'Assert-FileValid'; Times = 1 }
                    @{ Command = 'Get-MsiProductCode'; Times = 1 }
                    @{ Command = 'Invoke-PInvoke'; Times = 1 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.CouldNotStartProcess -f $setTargetResourceParameters.Path) `
                                             -ErrorTestName $script:errorMessageTitles.CouldNotStartProcess
            }

            $setTargetResourceParameters.Remove('RunAsCredential')

            Context 'Uri scheme is not file, http, or https, RunAsCredential is not specified and starting the process fails' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 0 }
                    @{ Command = 'Test-Path'; Times = 1; Custom = 'Path' }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'Copy-WebResponseToFileStream'; Times = 0 }
                    @{ Command = 'Assert-FileValid'; Times = 1 }
                    @{ Command = 'Get-MsiProductCode'; Times = 1 }
                    @{ Command = 'Invoke-Process'; Times = 1 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.CouldNotStartProcess -f $setTargetResourceParameters.Path) `
                                             -ErrorTestName $script:errorMessageTitles.CouldNotStartProcess
            }

            Mock -CommandName 'Invoke-Process' -MockWith { return $script:mockProcess }

            Context 'Uri scheme is not file, http, or https, RunAsCredential is not specified and starting the process succeeds but there is a post validation error' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 1; Custom = 'Path' }
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
                                             -ErrorMessage ($script:localizedData.PostValidationError -f $setTargetResourceParameters.Path) `
                                             -ErrorTestName $script:errorMessageTitles.PostValidationError
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
                    @{ Command = 'Test-Path'; Times = 2; Custom = 'Path' }
                    @{ Command = 'Remove-Item'; Times = 1; Custom = $destinationPath }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'New-Object'; Times = 1; Custom = 'System.IO.FileStream' }
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
                                             -ErrorMessage ($script:localizedData.PostValidationError -f $setTargetResourceParameters.Path) `
                                             -ErrorTestName $script:errorMessageTitles.PostValidationError
            }

            Mock -CommandName 'Convert-PathToUri' -MockWith { return $script:testUriNonUnc }
            Mock -CommandName 'Get-ProductEntry' -MockWith { return $script:mockProductEntry }

            Context 'Uri scheme is not file, http, or https, RunAsCredential is not specified and installation succeeds' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 1; Custom = 'Path' }
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

            Context 'Uri scheme is not file, http, or https, RunAsCredential is not specified and uninstallation succeeds' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 0; Custom = 'Path' }
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
            <#
                .SYNOPSIS
                    Performs generic tests for Test-TargetResource, including checking that the
                    function does not throw, checking that all mocks are called the expected
                    number of times, and checking that the correct result is returned. If the function
                    is expected to throw, then this function should not be used.

                .PARAMETER TestTargetResourceParameters
                    The parameters that should be passed to Test-TargetResource for this test.

                .PARAMETER MocksCalled
                    An array of the mocked commands that should be called for this test.
                    Each item in the array is a hashtable that contains the name of the command
                    being mocked and the number of times it is called (can be 0).

                .PARAMETER ExpectedReturnValue
                    The expected boolean value that should be returned
            #>
            function Invoke-TestTargetResourceTest
            {
                [CmdletBinding()]
                param
                (
                    [Parameter(Mandatory = $true)]
                    [Hashtable]
                    $TestTargetResourceParameters,

                    [Parameter(Mandatory = $true)]
                    [Hashtable[]]
                    $MocksCalled,

                    [Parameter(Mandatory = $true)]
                    [Boolean]
                    $ExpectedReturnValue
                )

                It 'Should not throw' {
                    { $null = Test-TargetResource @TestTargetResourceParameters } | Should Not Throw
                }

                foreach ($mock in $MocksCalled)
                {
                    $testName = Get-TestName -Command $mock.Command -IsCalled $mock.Times

                    It $testName {
                        Assert-MockCalled -CommandName $mock.Command -Exactly $mock.Times -Scope 'Context'
                    }
                }

                $testTargetResourceResult = Test-TargetResource @TestTargetResourceParameters

                It "Should return $ExpectedReturnValue" {
                    $testTargetResourceResult | Should Be $ExpectedReturnValue
                }
            }

            Mock -CommandName 'Convert-ProductIdToIdentifyingNumber' -MockWith { return $script:testIdentifyingNumber }
            Mock -CommandName 'Get-ProductEntry' -MockWith { return $script:mockProductEntry }

            Context 'Specified package is present and should be' {
                $testTargetResourceParameters = @{
                    ProductId = $script:testProductId
                    Path = $script:testPath
                    Ensure = 'Present'
                }

                $mocksCalled = @(
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                )

                Invoke-TestTargetResourceTest -TestTargetResourceParameters $testTargetResourceParameters `
                                              -MocksCalled $mocksCalled `
                                              -ExpectedReturnValue $true
            }

            Context 'Specified package is present but should not be' {
                $testTargetResourceParameters = @{
                    ProductId = $script:testProductId
                    Path = $script:testPath
                    Ensure = 'Absent'
                }

                $mocksCalled = @(
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                )

                Invoke-TestTargetResourceTest -TestTargetResourceParameters $testTargetResourceParameters `
                                              -MocksCalled $mocksCalled `
                                              -ExpectedReturnValue $false
            }

            Mock -CommandName 'Get-ProductEntry' -MockWith { return $null }

            Context 'Specified package is Absent but should not be' {
                $testTargetResourceParameters = @{
                    ProductId = $script:testProductId
                    Path = $script:testPath
                    Ensure = 'Present'
                }

                $mocksCalled = @(
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                )

                Invoke-TestTargetResourceTest -TestTargetResourceParameters $testTargetResourceParameters `
                                              -MocksCalled $mocksCalled `
                                              -ExpectedReturnValue $false
            }

            Context 'Specified package is Absent and should be' {
                $testTargetResourceParameters = @{
                    ProductId = $script:testProductId
                    Path = $script:testPath
                    Ensure = 'Absent'
                }

                $mocksCalled = @(
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                )

                Invoke-TestTargetResourceTest -TestTargetResourceParameters $testTargetResourceParameters `
                                              -MocksCalled $mocksCalled `
                                              -ExpectedReturnValue $true
            }
        }
    }
}
