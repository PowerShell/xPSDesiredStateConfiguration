$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

Describe 'xMsiPackage Unit Tests' {
    BeforeAll {
        # Import CommonTestHelper for Enter-DscResourceTestEnvironment, Exit-DscResourceTestEnvironment
        $script:testsFolderFilePath = Split-Path $PSScriptRoot -Parent
        $script:commonTestHelperFilePath = Join-Path -Path $testsFolderFilePath -ChildPath 'CommonTestHelper.psm1'
        Import-Module -Name $commonTestHelperFilePath -Force

        $script:testEnvironment = Enter-DscResourceTestEnvironment `
            -DscResourceModuleName 'xPSDesiredStateConfiguration' `
            -DscResourceName 'MSFT_xMsiPackage' `
            -TestType 'Unit'
            <#
            $script:testStrings = ConvertFrom-StringData -StringData @'
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
                Get-WebRequestResponse = get the web request response
                Copy-ResponseStreamToFileStream = copy the response stream to the file stream
                Get-ItemProperty = retrieve the registry data
'@#>
    }
    AfterAll {
        Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
    }

    InModuleScope 'MSFT_xMsiPackage' {
        $script:testsFolderFilePath = Split-Path $PSScriptRoot -Parent
        $script:commonTestHelperFilePath = Join-Path -Path $script:testsFolderFilePath -ChildPath 'CommonTestHelper.psm1'
        Import-Module -Name $commonTestHelperFilePath

        $testUsername = 'TestUsername'
        $testPassword = 'TestPassword'
        $secureTestPassword = ConvertTo-SecureString -String $testPassword -AsPlainText -Force

        $script:testCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @( $testUsername, $secureTestPassword )
        $script:testProductId = '{deadbeef-80c6-41e6-a1b9-8bdb8a05027f}'
        $script:testIdentifyingNumber = '{DEADBEEF-80C6-41E6-A1B9-8BDB8A05027F}'
        $script:testWrongProductId = 'wrongId'
        $script:testPath = 'file://test.msi'
        $script:destinationPath = Join-Path -Path $script:packageCacheLocation -ChildPath 'C:\'
        $script:testUriHttp = [Uri] 'http://test.msi'
        $script:testUriHttps = [Uri] 'https://test.msi'
        $script:testUriFile = [Uri] 'file://test.msi'
        $script:testUriNonUnc = [Uri] 'file:///C:/test.msi'
        $script:testUriQuery = [Uri] 'http://C:/test.msi?sv=2017-01-31&spr=https'

        $script:mockStream = New-MockObject -Type 'System.IO.FileStream'
        $script:mockWebRequest = New-MockObject -Type 'System.Net.HttpWebRequest'

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
            InstalledOn = '4/4/2017'
            Size = 2048
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

        Describe 'Get-TargetResource' {

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
            Mock -CommandName 'Get-WebRequestResponse' -MockWith { return $script:mockStream }
            Mock -CommandName 'Copy-ResponseStreamToFileStream' -MockWith {}
            Mock -CommandName 'Assert-FileValid' -MockWith {}
            Mock -CommandName 'Get-MsiProductCode' -MockWith { return $script:testWrongProductId }
            Mock -CommandName 'Invoke-PInvoke' -MockWith { Throw }
            Mock -CommandName 'Invoke-Process' -MockWith { Throw }
            Mock -CommandName 'Invoke-CimMethod' -MockWith {}
            Mock -CommandName 'Get-ItemProperty' -MockWith { return $null }
            Mock -CommandName 'Remove-PSDrive' -MockWith {}

            Context 'Error opening Log' {

                $mocksCalled = @(
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
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 2; Custom = 'Path' }
                    @{ Command = 'Remove-Item'; Times = 1; Custom = $setTargetResourceParameters.LogPath }
                    @{ Command = 'New-Item'; Times = 1; Custom = $setTargetResourceParameters.LogPath }
                    @{ Command = 'New-PSDrive'; Times = 1 }
                    @{ Command = 'Get-WebRequestResponse'; Times = 0 }
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
            Mock -CommandName 'New-Object' -MockWith { return $script:mockStream } -ParameterFilter { $TypeName -eq 'System.IO.FileStream' }
            Mock -CommandName 'Test-Path' -MockWith { return $false } -ParameterFilter { $Path -eq $script:destinationPath }
            $setTargetResourceParameters.Remove('LogPath')

            Context 'Uri scheme is https and specified Path does not exist' {

                $mocksCalled = @(
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 0 }
                    @{ Command = 'Test-Path'; Times = 2; Custom = 'Path' }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'New-Object'; Times = 1; Custom = 'System.IO.FileStream' }
                    @{ Command = 'Get-WebRequestResponse'; Times = 1 }
                    @{ Command = 'Copy-ResponseStreamToFileStream'; Times = 1 }
                    @{ Command = 'Close-Stream'; Times = 2 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.PathDoesNotExist -f $script:destinationPath) `
                                             -ErrorTestName $script:errorMessageTitles.PathDoesNotExist
            }

            Mock -CommandName 'Convert-PathToUri' -MockWith { return $script:testUriNonUnc }
            Mock -CommandName 'Get-MsiProductCode' -MockWith { return $script:testIdentifyingNumber }

            Context 'Uri scheme is file, RunAsCredential is specified and starting the process fails' {
                $mocksCalled = @(
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 0 }
                    @{ Command = 'Test-Path'; Times = 1; Custom = 'Path' }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'Get-WebRequestResponse'; Times = 0 }
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

            Context 'Uri scheme is file, RunAsCredential is not specified and starting the process fails' {
                $mocksCalled = @(
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 0 }
                    @{ Command = 'Test-Path'; Times = 1; Custom = 'Path' }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'Get-WebRequestResponse'; Times = 0 }
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

            Context 'Uri scheme is file, RunAsCredential is not specified and starting the process succeeds but there is a post validation error' {
                $mocksCalled = @(
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 1; Custom = 'Path' }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'Get-WebRequestResponse'; Times = 0 }
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
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 2; Custom = 'Path' }
                    @{ Command = 'Remove-Item'; Times = 1; Custom = $destinationPath }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'New-Object'; Times = 1; Custom = 'System.IO.FileStream' }
                    @{ Command = 'Get-WebRequestResponse'; Times = 1 }
                    @{ Command = 'Copy-ResponseStreamToFileStream'; Times = 1 }
                    @{ Command = 'Assert-FileValid'; Times = 1 }
                    @{ Command = 'Get-MsiProductCode'; Times = 1 }
                    @{ Command = 'Invoke-Process'; Times = 1 }
                    @{ Command = 'Invoke-CimMethod'; Times = 1 }
                    @{ Command = 'Get-ItemProperty'; Times = 1 }
                    @{ Command = 'Close-Stream'; Times = 2 }
                )

                Invoke-SetTargetResourceTest -SetTargetResourceParameters $setTargetResourceParameters `
                                             -MocksCalled $mocksCalled `
                                             -ShouldThrow $true `
                                             -ErrorMessage ($script:localizedData.PostValidationError -f $setTargetResourceParameters.Path) `
                                             -ErrorTestName $script:errorMessageTitles.PostValidationError
            }

            Mock -CommandName 'Convert-PathToUri' -MockWith { return $script:testUriQuery }
            Mock -CommandName 'Get-ProductEntry' -MockWith { return $script:mockProductEntry }

            Context 'Path is a query string' {
                
                It 'Should not throw' {
                    { $null = Set-TargetResource @setTargetResourceParameters } | Should Not Throw
                }

                It 'Should assert that the path with the query removed is valid' {
                    Assert-MockCalled -CommandName 'Assert-PathExtensionValid' -Exactly 1 -Scope 'Context' -ParameterFilter { $Path -eq 'test.msi' }
                }
            }

            Mock -CommandName 'Convert-PathToUri' -MockWith { return $script:testUriNonUnc }

            Context 'Uri scheme is file, RunAsCredential is not specified and installation succeeds' {
                $mocksCalled = @(
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 1; Custom = 'Path' }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'Get-WebRequestResponse'; Times = 0 }
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

            Context 'Uri scheme is file, RunAsCredential is not specified and uninstallation succeeds' {
                $mocksCalled = @(
                    @{ Command = 'Assert-PathExtensionValid'; Times = 1 }
                    @{ Command = 'Convert-PathToUri'; Times = 1 }
                    @{ Command = 'Convert-ProductIdToIdentifyingNumber'; Times = 1 }
                    @{ Command = 'Get-ProductEntry'; Times = 1 }
                    @{ Command = 'Test-Path'; Times = 0; Custom = 'Path' }
                    @{ Command = 'New-PSDrive'; Times = 0 }
                    @{ Command = 'Get-WebRequestResponse'; Times = 0 }
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

        Describe 'Assert-PathExtensionValid' {
            Context 'Path is a valid .msi path' {
                It 'Should not throw' {
                    { Assert-PathExtensionValid -Path 'testMsiFile.msi' } | Should Not Throw
                }
            }

            Context 'Path is not a valid .msi path' {
                It 'Should throw an invalid argument exception when an EXE file is passed in' {
                    $invalidPath = 'testMsiFile.exe'
                    $expectedErrorMessage = ($script:localizedData.InvalidBinaryType -f $invalidPath)

                    { Assert-PathExtensionValid -Path $invalidPath } | Should Throw $expectedErrorMessage
                }

                It 'Should throw an invalid argument exception when an invalid file type is passed in' {
                    $invalidPath = 'testMsiFilemsi'
                    $expectedErrorMessage = ($script:localizedData.InvalidBinaryType -f $invalidPath)

                    { Assert-PathExtensionValid -Path $invalidPath } | Should Throw $expectedErrorMessage
                }
            }
        }

        Describe 'Convert-PathToUri' {
            Context 'Path has a valid URI scheme' {
                It 'Should return the expected URI when scheme is a file' {
                    $filePath = (Join-Path -Path $PSScriptRoot -ChildPath 'testMsi.msi')
                    $expectedReturnValue = [Uri] $filePath

                    Convert-PathToUri -Path $filePath | Should Be $expectedReturnValue
                }
                
                It 'Should return the expected URI when scheme is http' {
                    $filePath = 'http://localhost:1242/testMsi.msi'
                    $expectedReturnValue = [Uri] $filePath

                    Convert-PathToUri -Path $filePath | Should Be $expectedReturnValue
                }

                It 'Should return the expected URI when scheme is https' {
                    $filePath = 'https://localhost:1243/testMsi.msi'
                    $expectedReturnValue = [Uri] $filePath

                    Convert-PathToUri -Path $filePath | Should Be $expectedReturnValue
                }
            }

            Context 'Invalid path passed in' {
                It 'Should throw an error when uri scheme is invalid' {
                    $filePath = 'ht://localhost:1243/testMsi.msi'
                    $expectedErrorMessage = ($script:localizedData.InvalidPath -f $filePath)

                    { Convert-PathToUri -Path $filePath } | Should Throw $expectedErrorMessage
                }

                It 'Should throw an error when path is not in valid format' {
                    $filePath = 'mri'
                    $expectedErrorMessage = ($script:localizedData.InvalidPath -f $filePath)

                    { Convert-PathToUri -Path $filePath } | Should Throw $expectedErrorMessage
                }
            }
        }

        Describe 'Convert-ProductIdToIdentifyingNumber' {
            Context 'Valid Product ID is passed in' {
                It 'Should return the same value that is passed in when the Product ID is already in the correct format' {
                    Convert-ProductIdToIdentifyingNumber -ProductId $script:testIdentifyingNumber | Should Be $script:testIdentifyingNumber
                }

                It 'Should convert a valid poduct ID to the identifying number format' {
                    Convert-ProductIdToIdentifyingNumber -ProductId $script:testProductId | Should Be $script:testIdentifyingNumber
                }
            }

            Context 'Invalid Product ID is passed in' {
                It 'Should throw an exception when an invalid product ID is passed in' {
                    $expectedErrorMessage = ($script:localizedData.InvalidIdentifyingNumber -f $script:testWrongProductId)
                    { Convert-ProductIdToIdentifyingNumber -ProductId $script:testWrongProductId } | Should Throw $expectedErrorMessage
                }
            }
        }

        Describe 'Get-ProductEntry' {
            $uninstallRegistryKeyLocation = (Join-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ChildPath $script:testIdentifyingNumber)
            $uninstallRegistryKeyWow64Location = (Join-Path -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ChildPath $script:testIdentifyingNumber)

            Mock -CommandName 'Get-Item' -MockWith { return $script:mockProductEntry } -ParameterFilter { $Path -eq $uninstallRegistryKeyLocation }
            Mock -CommandName 'Get-Item' -MockWith { return $script:mockProductEntry } -ParameterFilter { $Path -eq $uninstallRegistryKeyWow64Location }

            Context 'Product entry is found in the expected location' {
                It 'Should return the expected product entry' {
                    Get-ProductEntry -IdentifyingNumber $script:testIdentifyingNumber | Should Be $script:mockProductEntry
                }

                It 'Should retrieve the item' {
                    Assert-MockCalled -CommandName 'Get-Item' -Exactly 1 -Scope 'Context'
                }
            }

            Mock -CommandName 'Get-Item' -MockWith { return $null } -ParameterFilter { $Path -eq $uninstallRegistryKeyLocation }

            Context 'Product entry is found under Wow6432Node' {
                It 'Should return the expected product entry' {
                    Get-ProductEntry -IdentifyingNumber $script:testIdentifyingNumber | Should Be $script:mockProductEntry
                }

                It 'Should attempt to retrieve the item twice' {
                    Assert-MockCalled -CommandName 'Get-Item' -Exactly 2 -Scope 'Context'
                }
            }

            Mock -CommandName 'Get-Item' -MockWith { return $null } -ParameterFilter { $Path -eq $uninstallRegistryKeyWow64Location }

            Context 'Product entry is not found' {
                It 'Should return $null' {
                    Get-ProductEntry -IdentifyingNumber $script:testIdentifyingNumber | Should Be $null
                }

                It 'Should attempt to retrieve the item twice' {
                    Assert-MockCalled -CommandName 'Get-Item' -Exactly 2 -Scope 'Context'
                }
            }
        }

        Describe 'Get-ProductEntryInfo' {
            Mock -CommandName Get-ProductEntryValue -MockWith { return '20170404' } -ParameterFilter { $Property -eq 'InstallDate' }
            Mock -CommandName Get-ProductEntryValue -MockWith { return $script:mockProductEntryInfo.Publisher } -ParameterFilter { $Property -eq 'Publisher' }
            Mock -CommandName Get-ProductEntryValue -MockWith { return $script:mockProductEntryInfo.Size } -ParameterFilter { $Property -eq 'EstimatedSize' }
            Mock -CommandName Get-ProductEntryValue -MockWith { return $script:mockProductEntryInfo.Version } -ParameterFilter { $Property -eq 'DisplayVersion' }
            Mock -CommandName Get-ProductEntryValue -MockWith { return $script:mockProductEntryInfo.PackageDescription } -ParameterFilter { $Property -eq 'Comments' }
            Mock -CommandName Get-ProductEntryValue -MockWith { return $script:mockProductEntryInfo.Name } -ParameterFilter { $Property -eq 'DisplayName' }
            Mock -CommandName Get-ProductEntryValue -MockWith { return $script:mockProductEntryInfo.InstallSource } -ParameterFilter { $Property -eq 'InstallSource' }

            Context 'All properties are retrieved successfully' {

                $getProductEntryInfoResult = Get-ProductEntryInfo -ProductEntry $script:mockProductEntry

                It 'Should return the expected installed date' {
                     $getProductEntryInfoResult.InstalledOn | Should Be $script:mockProductEntryInfo.InstalledOn
                }

                It 'Should return the expected publisher' {
                     $getProductEntryInfoResult.Publisher | Should Be $script:mockProductEntryInfo.Publisher
                }

                It 'Should return the expected size' {
                     $getProductEntryInfoResult.Size | Should Be ($script:mockProductEntryInfo.Size / 1024)
                }

                It 'Should return the expected Version' {
                     $getProductEntryInfoResult.Version | Should Be $script:mockProductEntryInfo.Version
                }

                It 'Should return the expected package description' {
                     $getProductEntryInfoResult.PackageDescription | Should Be $script:mockProductEntryInfo.PackageDescription
                }

                It 'Should return the expected name' {
                     $getProductEntryInfoResult.Name | Should Be $script:mockProductEntryInfo.Name
                }

                It 'Should return the expected install source' {
                     $getProductEntryInfoResult.InstallSource | Should Be $script:mockProductEntryInfo.InstallSource
                }

                It 'Should retrieve 7 product entry values' {
                    Assert-MockCalled -CommandName 'Get-ProductEntryValue' -Exactly 7 -Scope 'Context'
                }
            }

            Mock -CommandName Get-ProductEntryValue -MockWith { return '4/4/2017' } -ParameterFilter { $Property -eq 'InstallDate' }

            Context 'Install date is in incorrect format' {

                $getProductEntryInfoResult = Get-ProductEntryInfo -ProductEntry $script:mockProductEntry

                It 'Should return $null for InstalledOn' {
                    $getProductEntryInfoResult.InstalledOn | Should Be $null
                }
            }
        }

        Describe 'Get-WebRequestResponse' {
            Mock -CommandName 'Get-WebRequest' -MockWith { return $script:mockWebRequest }
            Mock -CommandName 'Get-ScriptBlock' -MockWith { return { Write-Verbose 'Hello World' } }
            Mock -CommandName 'Get-WebRequestResponseStream' -MockWith { return $script:mockStream }

            Context 'URI scheme is Http and response is successfully retrieved' {
                $mocksCalled = @(
                    @{ Command = 'Get-WebRequest'; Times = 1 }
                    @{ Command = 'Get-ScriptBlock'; Times = 0 }
                    @{ Command = 'Get-WebRequestResponseStream'; Times = 1 }
                )

                It 'Should return the expected response stream' {
                    Get-WebRequestResponse -Uri $script:testUriHttp | Should Be $script:mockStream
                }
                
                Invoke-ExpectedMocksAreCalledTest -MocksCalled $mocksCalled
            }

            Context 'URI scheme is Https with no callback and response is successfully retrieved' {
                $mocksCalled = @(
                    @{ Command = 'Get-WebRequest'; Times = 1 }
                    @{ Command = 'Get-ScriptBlock'; Times = 0 }
                    @{ Command = 'Get-WebRequestResponseStream'; Times = 1 }
                )

                It 'Should return the expected response stream' {
                    Get-WebRequestResponse -Uri $script:testUriHttps | Should Be $script:mockStream
                }
                
                Invoke-ExpectedMocksAreCalledTest -MocksCalled $mocksCalled
            }

            Context 'URI scheme is Https with callback and response is successfully retrieved' {
                $mocksCalled = @(
                    @{ Command = 'Get-WebRequest'; Times = 1 }
                    @{ Command = 'Get-ScriptBlock'; Times = 1 }
                    @{ Command = 'Get-WebRequestResponseStream'; Times = 1 }
                )

                It 'Should return the expected response stream' {
                    Get-WebRequestResponse -Uri $script:testUriHttps -ServerCertificateValidationCallback 'TestCallbackFunction' | Should Be $script:mockStream
                }

                Invoke-ExpectedMocksAreCalledTest -MocksCalled $mocksCalled
            }

            Mock -CommandName 'Get-WebRequestResponseStream' -MockWith { Throw }

            Context 'Error occurred during while retrieving the response' {
                It 'Should throw the expected exception' {
                    $expectedErrorMessage = ($script:localizedData.CouldNotGetResponseFromWebRequest -f $script:testUriHttp.Scheme, $script:testUriHttp.OriginalString)
                    { Get-WebRequestResponse -Uri $script:testUriHttp } | Should Throw $expectedErrorMessage
                }
            }
        }

        Describe 'Assert-FileValid' {
            Mock -CommandName 'Assert-FileHashValid' -MockWith {}
            Mock -CommandName 'Assert-FileSignatureValid' -MockWith {}

            Context 'FileHash is passed in and SignerThumbprint and SignerSubject are not' {
                $mocksCalled = @(
                    @{ Command = 'Assert-FileHashValid'; Times = 1 }
                    @{ Command = 'Assert-FileSignatureValid'; Times = 0 }
                )

                It 'Should not throw' {
                    { Assert-FileValid -Path $script:testPath -FileHash 'mockFileHash' } | Should Not Throw
                }

                Invoke-ExpectedMocksAreCalledTest -MocksCalled $mocksCalled
            }

            Context 'FileHash and SignerThumbprint are passed in but SignerSubject is not' {
                $mocksCalled = @(
                    @{ Command = 'Assert-FileHashValid'; Times = 1 }
                    @{ Command = 'Assert-FileSignatureValid'; Times = 1 }
                )

                It 'Should not throw' {
                    { Assert-FileValid -Path $script:testPath -FileHash 'mockFileHash' -SignerThumbprint 'mockSignerThumbprint' } | Should Not Throw
                }

                Invoke-ExpectedMocksAreCalledTest -MocksCalled $mocksCalled
            }

            Context 'Only Path and SignerSubject are passed in' {
                $mocksCalled = @(
                    @{ Command = 'Assert-FileHashValid'; Times = 0 }
                    @{ Command = 'Assert-FileSignatureValid'; Times = 1 }
                )

                It 'Should not throw' {
                    { Assert-FileValid -Path $script:testPath -SignerSubject 'mockSignerSubject' } | Should Not Throw
                }

                Invoke-ExpectedMocksAreCalledTest -MocksCalled $mocksCalled
            }

            Context 'FileHash, SignerThumbprint, and SignerSubject are passed in' {
                $mocksCalled = @(
                    @{ Command = 'Assert-FileHashValid'; Times = 1 }
                    @{ Command = 'Assert-FileSignatureValid'; Times = 1 }
                )

                It 'Should not throw' {
                    { Assert-FileValid -Path $script:testPath -FileHash 'mockFileHash' `
                                                              -SignerThumbprint 'mockSignerThumbprint' `
                                                              -SignerSubject 'mockSignerSubject'
                    } | Should Not Throw
                }

                Invoke-ExpectedMocksAreCalledTest -MocksCalled $mocksCalled
            }

            Context 'SignerThumbprint and SignerSubject are passed in but FileHash is not' {
                $mocksCalled = @(
                    @{ Command = 'Assert-FileHashValid'; Times = 0 }
                    @{ Command = 'Assert-FileSignatureValid'; Times = 1 }
                )

                It 'Should not throw' {
                    { Assert-FileValid -Path $script:testPath -SignerThumbprint 'mockSignerThumbprint' `
                                                              -SignerSubject 'mockSignerSubject'
                    } | Should Not Throw
                }

                Invoke-ExpectedMocksAreCalledTest -MocksCalled $mocksCalled
            }

            Context 'Only path is passed in' {
                $mocksCalled = @(
                    @{ Command = 'Assert-FileHashValid'; Times = 0 }
                    @{ Command = 'Assert-FileSignatureValid'; Times = 0 }
                )

                It 'Should not throw' {
                    { Assert-FileValid -Path $script:testPath } | Should Not Throw
                }

                Invoke-ExpectedMocksAreCalledTest -MocksCalled $mocksCalled
            }
        }#>

        Describe 'Assert-FileHashValid' {
            $mockHash = @{ Hash = 'testHash' }
            Mock -CommandName 'Get-FileHash' -MockWith { return $mockHash }

            Context 'File hash is valid' {
                It 'Should not throw when hashes match' {
                    { Assert-FileHashValid -Path $script:testPath -Hash $mockHash.Hash -Algorithm 'SHA256' } | Should Not Throw
                }

                It 'Should fetch the file hash' {
                    Assert-MockCalled -CommandName 'Get-FileHash' -Exactly 1 -Scope 'Context'
                }
            }

            Context 'File hash is invalid' {
                $badHash = 'BadHash'
                $expectedErrorMessage = ($script:localizedData.InvalidFileHash -f $script:testPath, $badHash, 'SHA256')

                It 'Should throw when hashes do not match' {
                    { Assert-FileHashValid -Path $script:testPath -Hash $badHash -Algorithm 'SHA256' } | Should Throw $expectedErrorMessage
                }
            }
        }

        Describe 'Assert-FileSignatureValid' {
            $mockThumbprint = 'mockThumbprint'
            $mockSubject = 'mockSubject'
            $mockSignature = @{ 
                Status = [System.Management.Automation.SignatureStatus]::Valid
                SignerCertificate = @{ Thumbprint = $mockThumbprint; Subject = $mockSubject }
            }
            Mock -CommandName 'Get-AuthenticodeSignature' -MockWith { return $mockSignature }

            Context 'File signature status, thumbprint and subject are valid' {
                It 'Should not throw' {
                    { Assert-FileSignatureValid -Path $script:testPath -Thumbprint $mockThumbprint -Subject $mockSubject } | Should Not Throw
                }
            }

            Context 'File signature status and thumbprint are valid and Subject not passed in' {
                It 'Should not throw' {
                    { Assert-FileSignatureValid -Path $script:testPath -Thumbprint $mockThumbprint } | Should Not Throw
                }
            }

            Context 'File signature status and subject are valid and Thumbprint not passed in' {
                It 'Should not throw' {
                    { Assert-FileSignatureValid -Path $script:testPath -Subject $mockSubject } | Should Not Throw
                }
            }

            Context 'Only Path is passed in' {
                It 'Should not throw' {
                    { Assert-FileSignatureValid -Path $script:testPath } | Should Not Throw
                }
            }

            Context 'File signature status and thumbprint are valid and subject is invalid' {
                $badSubject = 'BadSubject'
                $expectedErrorMessage = ($script:localizedData.WrongSignerSubject -f $script:testPath, $badSubject)
                It 'Should throw expected error message' {
                    { Assert-FileSignatureValid -Path $script:testPath -Thumbprint $mockThumbprint -Subject $badSubject } | Should Throw $expectedErrorMessage
                }
            }

            Context 'File signature status and subject are valid and thumbprint is invalid' {
                $badThumbprint = 'BadThumbprint'
                $expectedErrorMessage = ($script:localizedData.WrongSignerThumbprint -f $script:testPath, $badThumbprint)
                It 'Should throw expected error message' {
                    { Assert-FileSignatureValid -Path $script:testPath -Thumbprint $badThumbprint -Subject $mockSubject } | Should Throw $expectedErrorMessage
                }
            }

            Context 'File signature status is invalid and subject and thumbprint are valid' {
                $mockSignature.Status = 'Invalid'
                $expectedErrorMessage = ($script:localizedData.InvalidFileSignature -f $script:testPath, $mockSignature.Status)
                It 'Should throw expected error message' {
                    { Assert-FileSignatureValid -Path $script:testPath -Thumbprint $mockThumbprint -Subject $mockSubject } | Should Throw $expectedErrorMessage
                }
            }
           
        }
    }
}
