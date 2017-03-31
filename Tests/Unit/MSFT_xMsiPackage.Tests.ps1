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
                Close-FileStream = close the file stream
                Close-ResponseStream = close the response stream
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
        $script:testPath = Join-Path -Path Test-Drive -ChildPath 'test.msi'
        $script:destinationPath = Join-Path -Path $script:packageCacheLocation -ChildPath 'C:\'
        $script:testUriNonUnc = [Uri] $script:testPath
        $script:testUriHttp = [Uri] 'http://testPath'
        $script:testUriHttps = [Uri] 'https://testPath'
        $script:testUriFile = [Uri] 'file://testPath'

        $script:testFileOutStream = New-MockObject -Type 'System.IO.FileStream'
        $script:testFileResponseStream = New-MockObject -Type 'System.Net.ResponseStream'
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
            Mock -CommandName 'Close-ResponseStream' -MockWith {}
            Mock -CommandName 'Close-FileStream' -MockWith {}
            Mock -CommandName 'Get-WebRequestResponse' -MockWith { return $script:testFileResponseStream }
            Mock -CommandName 'Copy-ResponseStreamToFileStream' -MockWith {}
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
                    @{ Command = 'Get-WebRequestResponse'; Times = 1 }
                    @{ Command = 'Copy-ResponseStreamToFileStream'; Times = 1 }
                    @{ Command = 'Close-ResponseStream'; Times = 1 }
                    @{ Command = 'Close-FileStream'; Times = 1 }
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

            Context 'Uri scheme is not file, http, or https, RunAsCredential is not specified and starting the process fails' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
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

            Context 'Uri scheme is not file, http, or https, RunAsCredential is not specified and starting the process succeeds but there is a post validation error' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
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
                    @{ Command = 'Test-TargetResource'; Times = 1 }
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
                    @{ Command = 'Close-ResponseStream'; Times = 1 }
                    @{ Command = 'Close-FileStream'; Times = 1 }
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

            Context 'Uri scheme is not file, http, or https, RunAsCredential is not specified and uninstallation succeeds' {
                $mocksCalled = @(
                    @{ Command = 'Test-TargetResource'; Times = 1 }
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
    }
}
