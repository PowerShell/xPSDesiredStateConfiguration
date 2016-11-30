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
        # Mock objects
                $script:validPath1 = 'ValidPath1'
                $script:validPath2 = 'ValidPath2'
                $script:validPath3 = 'ValidPath3'
                $script:invalidPath = 'InvalidPath'
                $script:testUserName = 'TestUserName12345'
                $testPassword = 'StrongOne7.'
                $testSecurePassword = ConvertTo-SecureString -String $testPassword -AsPlainText -Force
                $script:testCredential = New-Object PSCredential ($script:testUserName, $testSecurePassword)
                $script:exceptionMessage = 'Test Invalid Operation Exception'

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
        Describe 'Exported Methods Tests' {
            BeforeAll {
                

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
                Mock -CommandName New-InvalidOperationException -MockWith { Throw $script:exceptionMessage }
                Mock -CommandName New-InvalidArgumentException -MockWith { Throw $script:exceptionMessage }
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
                    
                    $getTargetResourceResult.VirtualMemorySize | Should Be $script:mockProcess1.VirtualMemorySize64
                    $getTargetResourceResult.Arguments | Should Be $script:mockProcess1.Arguments
                    $getTargetResourceResult.Ensure | Should Be 'Present'
                    $getTargetResourceResult.PagedMemorySize | Should Be $script:mockProcess1.PagedMemorySize64
                    $getTargetResourceResult.Path | Should Be $script:mockProcess1.Path
                    $getTargetResourceResult.NonPagedMemorySize | Should Be $script:mockProcess1.NonpagedSystemMemorySize64
                    $getTargetResourceResult.HandleCount | Should Be $script:mockProcess1.HandleCount
                    $getTargetResourceResult.ProcessId | Should Be $script:mockProcess1.ProcessId
                    
                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Process -Exactly 1 -Scope It
                }
            }

            Context 'Set-TargetResource' {
                Mock -CommandName Stop-Process -MockWith { return $null } `
                                               -ParameterFilter { ($Id -contains $script:mockProcess1.ProcessId) -or `
                                                                  ($Id -contains $script:mockProcess2.ProcessId) -or `
                                                                  ($Id -contains $script:mockProcess3.ProcessId) }
                Mock -CommandName Stop-Process -MockWith { return 'error' } `
                                               -ParameterFilter { $Id -contains $script:errorProcess.ProcessId}
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

                    { Set-TargetResource -Path $script:errorProcess.Path `
                                         -Arguments '' `
                                         -Ensure 'Absent'
                    } | Should Throw $script:exceptionMessage

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Stop-Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName New-InvalidOperationException -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Wait-ProcessCount -Exactly 0 -Scope It
                }

                It 'Should throw an invalid operation exception when there is a problem waiting for the processes' {
                    Mock -CommandName Wait-ProcessCount -MockWith { return $false }

                    { Set-TargetResource -Path $script:validPath1 `
                                         -Arguments $script:mockProcess1.Arguments `
                                         -Ensure 'Absent'
                    } | Should Throw $script:exceptionMessage

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

                It 'Should throw when Ensure set to Present, processes not running and credential and WorkingDirectory passed' {
                    Mock -CommandName Wait-ProcessCount -MockWith { return $true }
                    Mock -CommandName Start-ProcessAsLocalSystemUser -MockWith {}
                    Mock -CommandName Assert-PathArgumentRooted -MockWith {}
                    Mock -CommandName Assert-PathArgumentValid -MockWith {}

                    { Set-TargetResource -Path $script:invalidPath `
                                         -Arguments $script:mockProcess1.Arguments `
                                         -Credential $script:testCredential `
                                         -WorkingDirectory 'test working directory' `
                                         -Ensure 'Present'
                    } | Should Throw $script:exceptionMessage

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Test-IsRunFromLocalSystemUser -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Start-ProcessAsLocalSystemUser -Exactly 0 -Scope It
                    Assert-MockCalled -CommandName Wait-ProcessCount -Exactly 0 -Scope It
                    Assert-MockCalled -CommandName Assert-PathArgumentRooted -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Assert-PathArgumentValid -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName New-InvalidArgumentException -Exactly 1 -Scope It
                }

                It 'Should throw when Ensure set to Present and Start-processAsLocalSystemUser fails' {
                    Mock -CommandName Wait-ProcessCount -MockWith { return $true }
                    $testErrorRecord = 'test Start-ProcessAsLocalSystemUser error record'
                    Mock -CommandName Start-ProcessAsLocalSystemUser -MockWith { Throw $testErrorRecord }

                    { Set-TargetResource -Path $script:invalidPath `
                                         -Arguments $script:mockProcess1.Arguments `
                                         -Credential $script:testCredential `
                                         -Ensure 'Present'
                    } | Should Throw $testErrorRecord

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Test-IsRunFromLocalSystemUser -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Start-ProcessAsLocalSystemUser -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Wait-ProcessCount -Exactly 0 -Scope It
                }

                It 'Should not throw when Ensure set to Present and processes are not running and no credential passed' {
                    Mock -CommandName Wait-ProcessCount -MockWith { return $true }
                    Mock -CommandName Start-Process -MockWith {}

                    { Set-TargetResource -Path $script:invalidPath `
                                         -Arguments $script:mockProcess1.Arguments `
                                         -Ensure 'Present'
                    } | Should Not Throw

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Start-Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Wait-ProcessCount -Exactly 1 -Scope It
                }

                It 'Should throw when Ensure set to Present and Start-Process fails' {
                    Mock -CommandName Wait-ProcessCount -MockWith { return $true }
                    Mock -CommandName Start-Process -MockWith { Throw 'test' }

                    { Set-TargetResource -Path $script:invalidPath `
                                         -Arguments $script:mockProcess1.Arguments `
                                         -Ensure 'Present'
                    } | Should Throw $script:exceptionMessage

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Start-Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Wait-ProcessCount -Exactly 0 -Scope It
                    Assert-MockCalled -CommandName New-InvalidOperationException -Exactly 1 -Scope It
                }

                It 'Should throw when there is a failure waiting for the process to start' {
                    Mock -CommandName Wait-ProcessCount -MockWith { return $false }
                    Mock -CommandName Start-Process -MockWith {}

                    { Set-TargetResource -Path $script:invalidPath `
                                         -Arguments $script:mockProcess1.Arguments `
                                         -Ensure 'Present'
                    } | Should Throw $script:exceptionMessage

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Start-Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Wait-ProcessCount -Exactly 1 -Scope It
                }

                It 'Should not throw when Ensure set to Present and processes are already running' {
                    Mock -CommandName Wait-ProcessCount -MockWith { return $true }
                    Mock -CommandName Start-Process -MockWith {}

                    { Set-TargetResource -Path $script:validPath1 `
                                         -Arguments $script:mockProcess1.Arguments `
                                         -Ensure 'Present'
                    } | Should Not Throw

                    Assert-MockCalled -CommandName Expand-Path -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Start-Process -Exactly 0 -Scope It
                    Assert-MockCalled -CommandName Wait-ProcessCount -Exactly 0 -Scope It
                }
            }

            Context 'Test-TargetResource' {
                It 'Should return true when Ensure set to Present and process is running' {
                    $testTargetResourceResult = Test-TargetResource -Path $script:validPath1 `
                                                                    -Arguments $script:mockProcess1.Arguments `
                                                                    -Ensure 'Present'
                    $testTargetResourceResult | Should Be $true
                }

                It 'Should return false when Ensure set to Present and process is not running' {
                    $testTargetResourceResult = Test-TargetResource -Path $script:invalidPath `
                                                                    -Arguments $script:mockProcess1.Arguments `
                                                                    -Ensure 'Present'
                    $testTargetResourceResult | Should Be $false
                }

                It 'Should return true when Ensure set to Absent and process is not running and Credential passed' {
                    $testTargetResourceResult = Test-TargetResource -Path $script:invalidPath `
                                                                    -Arguments $script:mockProcess1.Arguments `
                                                                    -Credential $script:testCredential `
                                                                    -Ensure 'Absent'
                    $testTargetResourceResult | Should Be $true
                }

                It 'Should return false when Ensure set to Absent and process is running' {
                    $testTargetResourceResult = Test-TargetResource -Path $script:validPath1 `
                                                                    -Arguments $script:mockProcess1.Arguments `
                                                                    -Ensure 'Absent'
                    $testTargetResourceResult | Should Be $false
                }

            }
        }

        Describe 'Private Methods Tests' {
            BeforeAll {
                Mock -CommandName New-InvalidOperationException -MockWith { Throw $script:exceptionMessage }
                Mock -CommandName New-InvalidArgumentException -MockWith { Throw $script:exceptionMessage }
            }
            
            Context 'Expand-Path' {
                
                It 'Should return the original path when path is rooted' {
                    $rootedPath = 'C:\testProcess.exe'
                    Mock -CommandName Test-Path -MockWith { return $true }

                    $expandPathResult = Expand-Path -Path $rootedPath
                    $expandPathResult | Should Be $rootedPath
                }

                It 'Should throw an invalid argument exception when Path is rooted and does not exist' {
                    $rootedPath = 'C:\invalidProcess.exe'
                    Mock -CommandName Test-Path -MockWith { return $false }

                    { Expand-Path -Path $rootedPath} | Should Throw $script:exceptionMessage

                    Assert-MockCalled -CommandName New-InvalidArgumentException -Exactly 1 -Scope It
                }

                It 'Should throw an invalid argument exception when Path is unrooted and does not exist' {
                     $unrootedPath = 'invalidfile.txt'
                     Mock -CommandName Test-Path -MockWith { return $false }

                     { Expand-Path -Path $unrootedPath} | Should Throw $script:exceptionMessage

                     Assert-MockCalled -CommandName New-InvalidArgumentException -Exactly 1 -Scope It
                }
            }

            Context 'Get-Win32Process' {
                It 'Should return the correct process when it exists and no arguments passed' {
                    Mock -CommandName Get-Process -MockWith { return @($script:mockProcess2) }
                    Mock -CommandName Get-CimInstance -MockWith { return $script:mockProcess2 }

                    $resultProcess = Get-Win32Process -Path $script:mockProcess2.Path
                    $resultProcess | Should Be @($script:mockProcess2)

                    Assert-MockCalled -CommandName Get-Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-CimInstance -Exactly 1 -Scope It
                }

                It 'Should return the correct process when it exists and arguments are passed' {
                    Mock -CommandName Get-Process -MockWith { return @($script:mockProcess1) }
                    Mock -CommandName Get-CimInstance -MockWith { return $script:mockProcess1 }

                    $resultProcess = Get-Win32Process -Path $script:mockProcess1.Path `
                                                      -Arguments $script:mockProcess1.Arguments
                    $resultProcess | Should Be @($script:mockProcess1)

                    Assert-MockCalled -CommandName Get-Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-CimInstance -Exactly 1 -Scope It
                }

                It 'Should return the correct processes when multiple exist' {
                    Mock -CommandName Get-Process -MockWith { return @($script:mockProcess1, $script:mockProcess1, $script:mockProcess1) }
                    Mock -CommandName Get-CimInstance -MockWith { return @($script:mockProcess1, $script:mockProcess1, $script:mockProcess1) }

                    $resultProcess = Get-Win32Process -Path $script:mockProcess1.Path `
                                                      -Arguments $script:mockProcess1.Arguments
                    $resultProcess | Should Be @($script:mockProcess1, $script:mockProcess1, $script:mockProcess1)

                    Assert-MockCalled -CommandName Get-Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-CimInstance -Exactly 3 -Scope It
                }

                It 'Should return the correct processes when they exists and cim instance threshold is lower than number of processes found' {
                    Mock -CommandName Get-Process -MockWith { return @($script:mockProcess2, $script:mockProcess2) }
                    Mock -CommandName Get-CimInstance -MockWith { return @($script:mockProcess2, $script:mockProcess2) }

                    $resultProcess = Get-Win32Process -Path $script:mockProcess2.Path `
                                                      -Arguments $script:mockProcess2.Arguments `
                                                      -UseGetCimInstanceThreshold 1
                    $resultProcess | Should Be @($script:mockProcess2, $script:mockProcess2)

                    Assert-MockCalled -CommandName Get-Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-CimInstance -Exactly 1 -Scope It
                }

                It 'Should return the correct process when it exists and Credential is passed in' {
                    Mock -CommandName Get-Process -MockWith { return @($script:mockProcess2) }
                    Mock -CommandName Get-CimInstance -MockWith { return $script:mockProcess2 }
                    Mock -CommandName Get-Win32ProcessOwner -MockWith { return ($env:computerName + '\' + $script:testUsername) } `
                                                            -ParameterFilter { ($Process -eq $script:mockProcess2) }

                    $resultProcess = Get-Win32Process -Path $script:mockProcess2.Path `
                                                      -Credential $script:testCredential
                    $resultProcess | Should Be @($script:mockProcess2)

                    Assert-MockCalled -CommandName Get-Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-CimInstance -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-Win32ProcessOwner -Exactly 1 -Scope It
                }

                It 'Should return only processes that match Credential' {
                    Mock -CommandName Get-Process -MockWith { return @($script:mockProcess2, $script:mockProcess1) }
                    Mock -CommandName Get-CimInstance -MockWith { return @($script:mockProcess2, $script:mockProcess1) }
                    Mock -CommandName Get-Win32ProcessOwner -MockWith { return ($env:computerName + '\' + $script:testUsername) } `
                                                            -ParameterFilter { ($Process -eq $script:mockProcess2) }
                    Mock -CommandName Get-Win32ProcessOwner -MockWith { return ('wrongDomain' + '\' + $script:testUsername) } `
                                                            -ParameterFilter { ($Process -eq $script:mockProcess1) }

                    $resultProcess = Get-Win32Process -Path $script:mockProcess2.Path `
                                                      -Credential $script:testCredential `
                                                      -UseGetCimInstanceThreshold 1
                    $resultProcess | Should Be @($script:mockProcess2)

                    Assert-MockCalled -CommandName Get-Process -Exactly 1 -Scope It
                    Assert-MockCalled -CommandName Get-CimInstance -Exactly 1 -Scope It
                }
            
            }
        }



            <#
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
finally
{
    Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
}
