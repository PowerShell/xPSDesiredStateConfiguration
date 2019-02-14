$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

$script:testsFolderFilePath = Split-Path $PSScriptRoot -Parent
$script:commonTestHelperFilePath = Join-Path -Path $testsFolderFilePath -ChildPath 'CommonTestHelper.psm1'
Import-Module -Name $commonTestHelperFilePath

if (Test-SkipContinuousIntegrationTask -Type 'Unit')
{
    return
}

Describe 'CommonResourceHelper Unit Tests' {
    BeforeAll {
        # Import the CommonResourceHelper module to test
        $testsFolderFilePath = Split-Path -Path $PSScriptRoot -Parent
        $moduleRootFilePath = Split-Path -Path $testsFolderFilePath -Parent
        $dscResourcesFolderFilePath = Join-Path -Path $moduleRootFilePath -ChildPath 'DscResources'
        $commonResourceHelperFilePath = Join-Path -Path $dscResourcesFolderFilePath -ChildPath 'CommonResourceHelper.psm1'
        Import-Module -Name $commonResourceHelperFilePath
    }

    InModuleScope 'CommonResourceHelper' {
        # Declaring the function Get-ComputerInfo if we are testing on a machine with an older WMF
        if ($null -eq (Get-Command -Name 'Get-ComputerInfo' -ErrorAction 'SilentlyContinue'))
        {
            function Get-ComputerInfo {}
        }

        Describe 'Test-IsNanoServer' {
            $testComputerInfoNanoServer = @{
                OsProductType = 'Server'
                OsServerLevel = 'NanoServer'
            }

            $testComputerInfoServerNotNano = @{
                OsProductType = 'Server'
                OsServerLevel = 'NotNano'
            }

            $testComputerInfoNotServer = @{
                OsProductType = 'NotServer'
                OsServerLevel = 'NotNano'
            }

            Mock -CommandName 'Test-CommandExists' -MockWith { return $true }
            Mock -CommandName 'Get-ComputerInfo' -MockWith { return $testComputerInfoNanoServer }

            Context 'Get-ComputerInfo command exists' {
                Context 'Computer OS type is Server and OS server level is NanoServer' {
                    It 'Should not throw' {
                        { $null = Test-IsNanoServer } | Should -Not -Throw
                    }

                    It 'Should test if the Get-ComputerInfo command exists' {
                        $testCommandExistsParameterFilter = {
                            return $Name -eq 'Get-ComputerInfo'
                        }

                        Assert-MockCalled -CommandName 'Test-CommandExists' -ParameterFilter $testCommandExistsParameterFilter -Exactly 1 -Scope 'Context'
                    }

                    It 'Should retrieve the computer info' {
                        Assert-MockCalled -CommandName 'Get-ComputerInfo' -Exactly 1 -Scope 'Context'
                    }

                    It 'Should return true' {
                        Test-IsNanoServer | Should -Be $true
                    }
                }

                Context 'Computer OS type is Server and OS server level is not NanoServer' {
                    Mock -CommandName 'Get-ComputerInfo' -MockWith { return $testComputerInfoServerNotNano }

                    It 'Should not throw' {
                        { $null = Test-IsNanoServer } | Should -Not -Throw
                    }

                    It 'Should test if the Get-ComputerInfo command exists' {
                        $testCommandExistsParameterFilter = {
                            return $Name -eq 'Get-ComputerInfo'
                        }

                        Assert-MockCalled -CommandName 'Test-CommandExists' -ParameterFilter $testCommandExistsParameterFilter -Exactly 1 -Scope 'Context'
                    }

                    It 'Should retrieve the computer info' {
                        Assert-MockCalled -CommandName 'Get-ComputerInfo' -Exactly 1 -Scope 'Context'
                    }

                    It 'Should return false' {
                        Test-IsNanoServer | Should -Be $false
                    }
                }

                Context 'Computer OS type is not Server' {
                    Mock -CommandName 'Get-ComputerInfo' -MockWith { return $testComputerInfoNotServer }

                    It 'Should not throw' {
                        { $null = Test-IsNanoServer } | Should -Not -Throw
                    }

                    It 'Should test if the Get-ComputerInfo command exists' {
                        $testCommandExistsParameterFilter = {
                            return $Name -eq 'Get-ComputerInfo'
                        }

                        Assert-MockCalled -CommandName 'Test-CommandExists' -ParameterFilter $testCommandExistsParameterFilter -Exactly 1 -Scope 'Context'
                    }

                    It 'Should retrieve the computer info' {
                        Assert-MockCalled -CommandName 'Get-ComputerInfo' -Exactly 1 -Scope 'Context'
                    }

                    It 'Should return false' {
                        Test-IsNanoServer | Should -Be $false
                    }
                }
            }

            Context 'Get-ComputerInfo command does not exist' {
                Mock -CommandName 'Test-CommandExists' -MockWith { return $false }

                It 'Should not throw' {
                    { $null = Test-IsNanoServer } | Should -Not -Throw
                }

                It 'Should test if the Get-ComputerInfo command exists' {
                    $testCommandExistsParameterFilter = {
                        return $Name -eq 'Get-ComputerInfo'
                    }

                    Assert-MockCalled -CommandName 'Test-CommandExists' -ParameterFilter $testCommandExistsParameterFilter -Exactly 1 -Scope 'Context'
                }

                It 'Should not attempt to retrieve the computer info' {
                    Assert-MockCalled -CommandName 'Get-ComputerInfo' -Exactly 0 -Scope 'Context'
                }

                It 'Should return false' {
                    Test-IsNanoServer | Should -Be $false
                }
            }
        }

        Describe 'Test-CommandExists' {
            $testCommandName = 'TestCommandName'

            Mock -CommandName 'Get-Command' -MockWith { return $Name }

            Context 'Get-Command returns the command' {
                It 'Should not throw' {
                    { $null = Test-CommandExists -Name $testCommandName } | Should -Not -Throw
                }

                It 'Should retrieve the command with the specified name' {
                    $getCommandParameterFilter = {
                        return $Name -eq $testCommandName
                    }

                    Assert-MockCalled -CommandName 'Get-Command' -ParameterFilter $getCommandParameterFilter -Exactly 1 -Scope 'Context'
                }

                It 'Should return true' {
                    Test-CommandExists -Name $testCommandName | Should -Be $true
                }
            }

            Context 'Get-Command returns null' {
                Mock -CommandName 'Get-Command' -MockWith { return $null }

                It 'Should not throw' {
                    { $null = Test-CommandExists -Name $testCommandName } | Should -Not -Throw
                }

                It 'Should retrieve the command with the specified name' {
                    $getCommandParameterFilter = {
                        return $Name -eq $testCommandName
                    }

                    Assert-MockCalled -CommandName 'Get-Command' -ParameterFilter $getCommandParameterFilter -Exactly 1 -Scope 'Context'
                }

                It 'Should return false' {
                    Test-CommandExists -Name $testCommandName | Should -Be $false
                }
            }
        }

        Describe 'Set-DSCMachineStatus' {
            Context 'When called' {
                It 'Should set the desired DSCMachineStatus value' {
                    # A new value we'll attempt to set to $global:DSCMachineStatus
                    $newValue = 100

                    # Store the previous $global:DSCMachineStatus value
                    $prevDSCMachineStatus = $global:DSCMachineStatus
                    
                    # Make sure DSCMachineStatus is set to a value that will have to be updated
                    $global:DSCMachineStatus = 99

                    # Set and test for the new value
                    Set-DSCMachineStatus -NewDSCMachineStatus $newValue
                    $global:DSCMachineStatus | Should -Be $newValue

                    # Revert to previous $global:DSCMachineStatus value
                    $global:DSCMachineStatus = $prevDSCMachineStatus
                }
            }
        }
    }
}
