[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

Import-Module -Name (Join-Path -Path (Split-Path $PSScriptRoot -Parent) `
                               -ChildPath 'CommonTestHelper.psm1')

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DscResourceModuleName 'xPSDesiredStateConfiguration' `
    -DscResourceName 'MSFT_xProcessResource' `
    -TestType 'Unit'

try
{

    Import-Module -Name (Join-Path -Path  $PSScriptRoot `
                                   -ChildPath 'MSFT_xProcessResource.TestHelper.psm1')

    InModuleScope 'MSFT_xProcessResource' {
        Describe 'MSFT_xProcessResource Unit Tests' {
            BeforeAll {
                # Mock objects
                $script:validPath1 = 'ValidPath1'
                $script:validPath2 = 'ValidPath2'
                $script:validPath3 = 'ValidPath3'
                $script:invalidPath = 'InvalidPath'
                $testUserName = 'TestUserName12345'
                $testPassword = 'StrongOne7.'
                $testSecurePassword = ConvertTo-SecureString -String $testPassword -AsPlainText -Force
                $script:testCredential = New-Object PSCredential ($testUserName, $testSecurePassword)

                $script:mockProcess1 = @{
                    Path = $script:validPath1
                    CommandLine = 'c:\temp\test.exe argument1 argument2 argument3'
                    Arguments = 'argument1 argument2 argument3'
                    ProcessId = 12345
                    PagedMemorySize64 = 1048
                    NonpagedSystemMemorySize64 = 16
                    VirtualMemorySize64 = 256
                    HandleCount = 50
                }

                $script:mockProcess2 = @{
                    Path = $script:validPath2
                    CommandLine = ''
                    Arguments = ''
                    ProcessId = 54321
                    PagedMemorySize64 = 2096
                    NonpagedSystemMemorySize64 = 8
                    VirtualMemorySize64 = 512
                    HandleCount = 5
                }

                $script:mockProcess3 = @{
                    Path = $script:validPath1
                    CommandLine = 'c:\test.exe arg6'
                    Arguments = 'arg6'
                    ProcessId = 1111101
                    PagedMemorySize64 = 512
                    NonpagedSystemMemorySize64 = 32
                    VirtualMemorySize64 = 64
                    HandleCount = 0
                }

                $script:errorProcess = @{
                    Path = $script:validPath3
                    CommandLine = ''
                    Arguments = ''
                    ProcessId = 77777
                    PagedMemorySize64 = 0
                    NonpagedSystemMemorySize64 = 0
                    VirtualMemorySize64 = 0
                    HandleCount = 0
                }

                # Mock methods
                Mock -CommandName Expand-Path -MockWith { return $script:validPath1 } `
                                              -ParameterFilter { $Path -eq $script:validPath1 }
                Mock -CommandName Expand-Path -MockWith { return $script:validPath2 } `
                                              -ParameterFilter { $Path -eq $script:validPath2 }
                Mock -CommandName Expand-Path -MockWith { return $script:invalidPath } `
                                              -ParameterFilter { $Path -eq $script:invalidPath }
                Mock -CommandName Expand-Path -MockWith { return $script:validPath3 } `
                                              -ParameterFilter { $Path -eq $script:validPath3 }
                Mock -CommandName Get-Win32Process -MockWith { return @() } `
                                                   -ParameterFilter { $Path -eq $script:invalidPath }
                Mock -CommandName Get-Win32Process -MockWith { return @($script:mockProcess1, $script:mockProcess3) } `
                                                   -ParameterFilter { $Path -eq $script:validPath1 }
                Mock -CommandName Get-Win32Process -MockWith { return @($script:mockProcess2) } `
                                                   -ParameterFilter { $Path -eq $script:validPath2 }
                Mock -CommandName Get-Win32Process -MockWith { return @($script:errorProcess) } `
                                                   -ParameterFilter { $Path -eq $script:validPath3 }
            }

            AfterAll {
                
            }

            BeforeEach {
                
            }

            Context 'Get-TargetResource' {
                Mock -CommandName Get-Process -MockWith { return $script:mockProcess1 } `
                                              -ParameterFilter { $ID -eq $script:mockProcess1.ProcessId }
                Mock -CommandName Get-Process -MockWith { return $script:mockProcess2 } `
                                              -ParameterFilter { $ID -eq $script:mockProcess2.ProcessId }
                Mock -CommandName Get-Process -MockWith { return $script:mockProcess3 } `
                                              -ParameterFilter { $ID -eq $script:mockProcess3.ProcessId }

                It 'Should return the correct properties for a process that is Absent' {
                    $processArguments = 'TestGetProperties'

                    $getTargetResourceResult = Get-TargetResource -Path $invalidPath `
                                                                  -Arguments $processArguments

                    $getTargetResourceResult.Arguments | Should Be $processArguments
                    $getTargetResourceResult.Ensure | Should Be 'Absent'
                    $getTargetResourceResult.Path  | Should Be $invalidPath

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                }

                It 'Should return the correct properties for one process with a credential' {

                    $getTargetResourceResult = Get-TargetResource -Path $script:validPath2 `
                                                                  -Arguments $script:mockProcess2.Arguments `
                                                                  -Credential $script:testCredential
                    
                    $getTargetResourceResult.VirtualMemorySize | Should Be $script:mockProcess2.VirtualMemorySize64
                    $getTargetResourceResult.Arguments | Should Be $script:mockProcess2.Arguments
                    $getTargetResourceResult.Ensure | Should Be 'Present'
                    $getTargetResourceResult.PagedMemorySize | Should Be $script:mockProcess2.PagedMemorySize64
                    $getTargetResourceResult.Path | Should Be $script:mockProcess2.Path
                    $getTargetResourceResult.NonPagedMemorySize | Should Be $script:mockProcess2.NonpagedSystemMemorySize64
                    $getTargetResourceResult.HandleCount | Should Be $script:mockProcess2.HandleCount
                    $getTargetResourceResult.ProcessId | Should Be $script:mockProcess2.ProcessId

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Process -Exactly 1 -Scope It
                }
             
                It 'Should return the correct properties when there are multiple processes' {

                    $getTargetResourceResult = Get-TargetResource -Path $script:validPath1 `
                                                                  -Arguments $script:mockProcess1.Arguments
                    
                    $getTargetResourceResult.Count | Should Be 2
                    $getTargetResourceResult[0].VirtualMemorySize | Should Be $script:mockProcess1.VirtualMemorySize64
                    $getTargetResourceResult[0].Arguments | Should Be $script:mockProcess1.Arguments
                    $getTargetResourceResult[0].Ensure | Should Be 'Present'
                    $getTargetResourceResult[0].PagedMemorySize | Should Be $script:mockProcess1.PagedMemorySize64
                    $getTargetResourceResult[0].Path | Should Be $script:mockProcess1.Path
                    $getTargetResourceResult[0].NonPagedMemorySize | Should Be $script:mockProcess1.NonpagedSystemMemorySize64
                    $getTargetResourceResult[0].HandleCount | Should Be $script:mockProcess1.HandleCount
                    $getTargetResourceResult[0].ProcessId | Should Be $script:mockProcess1.ProcessId
                    $getTargetResourceResult[1].VirtualMemorySize | Should Be $script:mockProcess3.VirtualMemorySize64
                    $getTargetResourceResult[1].Arguments | Should Be $script:mockProcess3.Arguments
                    $getTargetResourceResult[1].Ensure | Should Be 'Present'
                    $getTargetResourceResult[1].PagedMemorySize | Should Be $script:mockProcess3.PagedMemorySize64
                    $getTargetResourceResult[1].Path | Should Be $script:mockProcess3.Path
                    $getTargetResourceResult[1].NonPagedMemorySize | Should Be $script:mockProcess3.NonpagedSystemMemorySize64
                    $getTargetResourceResult[1].HandleCount | Should Be $script:mockProcess3.HandleCount
                    $getTargetResourceResult[1].ProcessId | Should Be $script:mockProcess3.ProcessId

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Process -Exactly 2 -Scope It
                }
            }

            Context 'Set-TargetResource' {
                Mock -CommandName Stop-Process -MockWith { return $null } `
                                               -ParameterFilter { ($Id -contains $script:mockProcess1.ProcessId) -or `
                                                                  ($Id -contains $script:mockProcess2.ProcessId) -or `
                                                                  ($Id -contains $script:mockProcess3.ProcessId) }
                Mock -CommandName Stop-Process -MockWith { return 'error' } `
                                               -ParameterFilter { $Id -contains $script:errorProcess.ProcessId}
                Mock -CommandName Start-Process -MockWith { return $null } `
                                                -ParameterFilter { ($FilePath -eq $script:validPath1) -or `
                                                                   ($FilePath -eq $script:validPath2) -or `
                                                                   ($FilePath -eq $script:invalidPath) }
                Mock -CommandName Start-Process -MockWith { return 'error' } `
                                                -ParameterFilter { $FilePath -eq $script:validPath3 }
                Mock -CommandName Test-IsRunFromLocalSystemUser -MockWith { return $true }

                It 'Should not throw when Ensure set to Absent and processes are running' {
                    Mock -CommandName Wait-ProcessCount -MockWith { return $true }

                    { Set-TargetResource -Path $script:validPath1 `
                                         -Arguments $script:mockProcess1.Arguments `
                                         -Credential $script:testCredential `
                                         -Ensure 'Absent'
                    } | Should Not Throw

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Stop-Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Wait-ProcessCount -Exactly 1 -Scope It
                }

                It 'Should not throw when Ensure set to Absent and processes are not running' {
                    Mock -CommandName Wait-ProcessCount -MockWith { return $true }

                    { Set-TargetResource -Path $script:invalidPath `
                                         -Arguments '' `
                                         -Ensure 'Absent'
                    } | Should Not Throw

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Stop-Process -Exactly 0 -Scope It
                    Assert-MockCalled -CommandName Wait-ProcessCount -Exactly 0 -Scope It
                }

                It 'Should throw an invalid operation exception when Stop-Process throws an error' {
                    Mock -CommandName Wait-ProcessCount -MockWith { return $true }

                    $exceptionMessage = 'Test Invalid Operation Exception'
                    Mock -CommandName New-InvalidOperationException -MockWith { Throw $exceptionMessage }

                    { Set-TargetResource -Path $script:errorProcess.Path `
                                         -Arguments '' `
                                         -Ensure 'Absent'
                    } | Should Throw $exceptionMessage

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Stop-Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName New-InvalidOperationException -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Wait-ProcessCount -Exactly 0 -Scope It
                }

                It 'Should throw an invalid operation exception when there is a problem waiting for the processes' {
                    Mock -CommandName Wait-ProcessCount -MockWith { return $false }

                    $exceptionMessage = 'Test Invalid Operation Exception'
                    Mock -CommandName New-InvalidOperationException -MockWith { Throw $exceptionMessage }

                    { Set-TargetResource -Path $script:validPath1 `
                                         -Arguments $script:mockProcess1.Arguments `
                                         -Ensure 'Absent'
                    } | Should Throw $exceptionMessage

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Stop-Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Wait-ProcessCount -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName New-InvalidOperationException -Exactly 1 -Scope It
                }

                It 'Should not throw when Ensure set to Present and processes are not running and credential passed in' {
                    Mock -CommandName Wait-ProcessCount -MockWith { return $true }
                    Mock -CommandName Start-ProcessAsLocalSystemUser -MockWith {}

                    { Set-TargetResource -Path $script:invalidPath `
                                         -Arguments $script:mockProcess1.Arguments `
                                         -Credential $script:testCredential `
                                         -Ensure 'Present'
                    } | Should Not Throw

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Test-IsRunFromLocalSystemUser -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Start-ProcessAsLocalSystemUser -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Wait-ProcessCount -Exactly 1 -Scope It
                }
            }
            <#
            Context 'Test-TargetResource' {
                It 'Should return correct value based on Arguments' {
                    $actualArguments = 'TestProcessResourceWithArguments'

                    Set-TargetResource -Path $script:cmdProcessFullPath -Arguments $actualArguments
 
                    Test-TargetResource -Path $script:cmdProcessFullPath -Arguments '' | Should Be $false
 
                    Test-TargetResource -Path $script:cmdProcessFullPath -Arguments 'NotTheOriginalArguments' | Should Be $false

                    Test-TargetResource -Path $script:cmdProcessFullPath -Arguments $actualArguments | Should Be $true
                }

                It 'Should return false for absent process with directory arguments' {
                    $testTargetResourceResult = Test-TargetResource `
                        -Path $script:cmdProcessFullPath `
                        -WorkingDirectory 'something' `
                        -StandardOutputPath 'something' `
                        -StandardErrorPath 'something' `
                        -StandardInputPath 'something' `
                        -Arguments ''
                        
                    $testTargetResourceResult | Should Be $false
                }

            }

            Context 'Get-Win32Process' {
                It 'Should only return one process when arguments were changed for that process' {
                    Set-TargetResource -Path $script:cmdProcessFullPath -Arguments ''
                    Set-TargetResource -Path $script:cmdProcessFullPath -Arguments 'abc'

                    $processes = @( Get-Win32Process -Path $script:cmdProcessFullPath -UseGetCimInstanceThreshold 0 )
                    $processes.Count | Should Be 1

                    $processes = @( Get-Win32Process -Path $script:cmdProcessFullPath -UseGetCimInstanceThreshold 5 )
                    $processes.Count | Should Be 1
                }
            }

            Context 'Get-ArgumentsFromCommandLineInput' {
                It 'Should retrieve expected arguments from command line input' {
                    $testCases = @( @{
                            CommandLineInput = 'c    a   '
                            ExpectedArguments = 'a'
                        },
                        @{
                            CommandLineInput = '"c b d" e  '
                            ExpectedArguments = 'e'
                        },
                        @{
                            CommandLineInput = '    a b'
                            ExpectedArguments = 'b'
                        },
                        @{
                            CommandLineInput = ' abc '
                            ExpectedArguments = ''
                        }
                    )

                    foreach ($testCase in $testCases)
                    {
                        $commandLineInput = $testCase.CommandLineInput
                        $expectedArguments = $testCase.ExpectedArguments
                        $actualArguments = Get-ArgumentsFromCommandLineInput -CommandLineInput $commandLineInput

                        $actualArguments | Should Be $expectedArguments
                    }
                }
            }

            Context 'Split-Credential' {
                It 'Should return correct domain and username with @ seperator' {
                    $testUsername = 'user@domain'
                    $testPassword = ConvertTo-SecureString -String 'dummy' -AsPlainText -Force
                    $testCredential = New-Object -TypeName 'PSCredential' -ArgumentList @($testUsername, $testPassword)

                    $splitCredentialResult = Split-Credential -Credential $testCredential

                    $splitCredentialResult.Domain | Should Be 'domain'
                    $splitCredentialResult.Username | Should Be 'user'
                }
    
                It 'Should return correct domain and username with \ seperator' {
                    $testUsername = 'domain\user'
                    $testPassword = ConvertTo-SecureString -String 'dummy' -AsPlainText -Force
                    $testCredential = New-Object -TypeName 'PSCredential' -ArgumentList @($testUsername, $testPassword)

                    $splitCredentialResult = Split-Credential -Credential $testCredential

                    $splitCredentialResult.Domain | Should Be 'domain'
                    $splitCredentialResult.Username | Should Be 'user'
                }
    
                It 'Should return correct domain and username with a local user' {
                    $testUsername = 'localuser'
                    $testPassword = ConvertTo-SecureString -String 'dummy' -AsPlainText -Force
                    $testCredential = New-Object -TypeName 'PSCredential' -ArgumentList @($testUsername, $testPassword)

                    $splitCredentialResult = Split-Credential -Credential $testCredential

                    $splitCredentialResult.Username | Should Be 'localuser'
                }
    
                It 'Should throw when more than one \ in username' {
                    $testUsername = 'user\domain\foo'
                    $testPassword = ConvertTo-SecureString -String 'dummy' -AsPlainText -Force
                    $testCredential = New-Object -TypeName 'PSCredential' -ArgumentList @($testUsername, $testPassword)
                    
                    { $splitCredentialResult = Split-Credential -Credential $testCredential } | Should Throw
                }
    
                It 'Should throw when more than one @ in username' {
                    $testUsername = 'user@domain@foo'
                    $testPassword = ConvertTo-SecureString -String 'dummy' -AsPlainText -Force
                    $testCredential = New-Object -TypeName 'PSCredential' -ArgumentList @($testUsername, $testPassword)
                    
                    { $splitCredentialResult = Split-Credential -Credential $testCredential } | Should Throw
                }
            }#>
        }
    }
}
finally
{
    Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
}
