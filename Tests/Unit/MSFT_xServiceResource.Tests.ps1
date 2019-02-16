# Need to be able to create a password from plain text to create test credentials
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

# Import CommonTestHelper for Enter-DscResourceTestEnvironment, Exit-DscResourceTestEnvironment
$script:testsFolderFilePath = Split-Path $PSScriptRoot -Parent
$script:commonTestHelperFilePath = Join-Path -Path $testsFolderFilePath -ChildPath 'CommonTestHelper.psm1'
Import-Module -Name $commonTestHelperFilePath

if (Test-SkipContinuousIntegrationTask -Type 'Unit')
{
    return
}

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DSCResourceModuleName 'xPSDesiredStateConfiguration' `
    -DSCResourceName 'MSFT_xServiceResource' `
    -TestType 'Unit'

try
{
    # This is needed so that the ServiceControllerStatus enum is recognized as a valid type
    Add-Type -AssemblyName 'System.ServiceProcess'

    InModuleScope 'MSFT_xServiceResource' {
        $script:testServiceName = 'DscTestService'

        $script:testUsername1 = 'TestUser1'
        $script:testUsername2 = 'TestUser2'

        $script:testPassword = 'DummyPassword'
        $secureTestPassword = ConvertTo-SecureString $script:testPassword -AsPlainText -Force

        $script:testCredential1 = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList ($script:testUsername1, $secureTestPassword)
        $script:testCredential2 = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList ($script:testUsername2, $secureTestPassword)

        $script:gMSAUser1 = 'DOMAIN\gMSA1$'
        $script:gMSAUser2 = 'DOMAIN\gMSA2$'

        Describe 'xService\Get-TargetResource' {
            <#
                .SYNOPSIS
                    Invokes Get-TargetResource, ensures that it does not throw an exception,
                    and tests whether expected functions were called.

                .PARAMETER GetTargetResourceParameters
                    The parameters to pass to Get-TargetResource

                .PARAMETER TestServiceCimInstance
                    The TestServiceCimInstance object to use when checking whether
                    ConvertTo-StartupTypeString was called.

                .PARAMETER ExpectServiceCIMInstance
                    Whether or not the function should expect Get-ServiceCimInstance
                    to be called. Defaults to $true.
            #>
            function Test-GetTargetResourceDoesntThrow
            {
                [CmdletBinding()]
                param
                (
                    [Parameter(Mandatory = $true)]
                    [System.Collections.Hashtable]
                    $GetTargetResourceParameters,

                    [Parameter()]
                    [System.Collections.Hashtable]
                    $TestServiceCimInstance,

                    [Parameter()]
                    [System.Boolean]
                    $ExpectServiceCIMInstance = $true
                )

                It 'Should not throw' {
                    { $null = Get-TargetResource @GetTargetResourceParameters } | Should -Not -Throw
                }

                It 'Should retrieve service' {
                    Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $GetTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                if ($ExpectServiceCIMInstance)
                {
                    $expectedTimes = 1
                }
                else
                {
                    $expectedTimes = 0
                }

                It 'Should retrieve the service CIM instance' {
                    Assert-MockCalled 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $GetTargetResourceParameters.Name } -Times $expectedTimes -Scope 'Context'
                }

                It 'Should convert the service start mode to a startup type string' {
                    Assert-MockCalled -CommandName 'ConvertTo-StartupTypeString' -ParameterFilter { $StartMode -eq $TestServiceCimInstance.StartMode } -Times $expectedTimes -Scope 'Context'
                }
            }

            <#
                .SYNOPSIS
                    Invokes Get-TargetResource, and performs tests against the return variable.

                .PARAMETER GetTargetResourceParameters
                    The parameters to pass to Get-TargetResource

                .PARAMETER ExpectedValues
                    A hashtable containing values that are expected to be returned by
                    Get-TargetResource.
            #>
            function Test-GetTargetResourceResult
            {
                [CmdletBinding()]
                param
                (
                    [Parameter(Mandatory = $true)]
                    [System.Collections.Hashtable]
                    $GetTargetResourceParameters,

                    [Parameter(Mandatory = $true)]
                    [System.Collections.Hashtable]
                    $ExpectedValues
                )

                $getTargetResourceResult = Get-TargetResource @GetTargetResourceParameters

                It 'Should return a hashtable' {
                    $getTargetResourceResult -is [System.Collections.Hashtable] | Should Be $true
                }

                if ($ExpectedValues.ContainsKey('Name'))
                {
                    It 'Should return the service name' {
                        $getTargetResourceResult.Name | Should -Be $ExpectedValues.Name
                    }
                }

                if ($ExpectedValues.ContainsKey('Ensure'))
                {
                    It 'Should return the service Ensure state as Present' {
                        $getTargetResourceResult.Ensure | Should -Be $ExpectedValues.Ensure
                    }
                }

                if ($ExpectedValues.ContainsKey('Path'))
                {
                    It 'Should return the service path' {
                        $getTargetResourceResult.Path | Should -Be $ExpectedValues.Path
                    }
                }

                if ($ExpectedValues.ContainsKey('StartupType'))
                {
                    It 'Should return the service startup type' {
                        $getTargetResourceResult.StartupType | Should -Be $ExpectedValues.StartupType
                    }
                }

                if ($ExpectedValues.ContainsKey('BuiltInAccount'))
                {
                    It 'Should return the service startup account name' {
                        $getTargetResourceResult.BuiltInAccount | Should -Be $ExpectedValues.BuiltInAccount
                    }
                }

                if ($ExpectedValues.ContainsKey('State'))
                {
                    It 'Should return the service state' {
                        $getTargetResourceResult.State | Should -Be $ExpectedValues.State
                    }
                }

                if ($ExpectedValues.ContainsKey('DisplayName'))
                {
                    It 'Should return the service display name' {
                        $getTargetResourceResult.DisplayName | Should -Be $ExpectedValues.DisplayName
                    }
                }

                if ($ExpectedValues.ContainsKey('Description'))
                {
                    It 'Should return the service description as null' {
                        $getTargetResourceResult.Description | Should -Be $ExpectedValues.Description
                    }
                }

                if ($ExpectedValues.ContainsKey('DesktopInteract'))
                {
                    It 'Should return the service desktop interation setting' {
                        $getTargetResourceResult.DesktopInteract | Should -Be $ExpectedValues.DesktopInteract
                    }
                }

                if ($ExpectedValues.ContainsKey('Dependencies'))
                {
                    It 'Should return the service dependencies' {
                        $getTargetResourceResult.Dependencies | Should -Be $ExpectedValues.Dependencies
                    }
                }
            }

            Mock -CommandName 'Get-Service' -MockWith { }
            Mock -CommandName 'Get-ServiceCimInstance' -MockWith { }
            Mock -CommandName 'ConvertTo-StartupTypeString' -MockWith { }

            $getTargetResourceParameters = @{
                Name = 'TestServiceName'
            }

            $convertToStartupTypeStringResult = 'TestStartupTypeString'

            Context 'When a service does not exist' {
                Test-GetTargetResourceDoesntThrow -GetTargetResourceParameters $getTargetResourceParameters -ExpectServiceCIMInstance $false

                $expectedValues = @{
                    Name            = $getTargetResourceParameters.Name
                    Ensure          = 'Absent'
                }

                Test-GetTargetResourceResult -GetTargetResourceParameters $getTargetResourceParameters -ExpectedValues $expectedValues
            }

            Context 'When a service exists with all properties defined and custom startup account name' {
                $testService = @{
                    Name = 'TestServiceName'
                    DisplayName = 'TestDisplayName'
                    Status = 'TestServiceStatus'
                    StartType = 'TestServiceStartType'
                    ServicesDependedOn = @(
                        @{
                            Name = 'ServiceDependency1'
                        },
                        @{
                            Name = 'ServiceDependency2'
                        }
                    )
                }

                $testServiceCimInstance = @{
                    Name = $testService.Name
                    PathName = 'TestServicePath'
                    Description = 'Test service description'
                    StartName = 'CustomStartName'
                    StartMode = 'Auto'
                    DesktopInteract = $true
                }

                Mock -CommandName 'Get-Service' -MockWith { return $testService }
                Mock -CommandName 'Get-ServiceCimInstance' -MockWith { return $testServiceCimInstance }
                Mock -CommandName 'ConvertTo-StartupTypeString' -MockWith { return $convertToStartupTypeStringResult }

                Test-GetTargetResourceDoesntThrow -GetTargetResourceParameters $getTargetResourceParameters -TestServiceCimInstance $testServiceCimInstance

                $expectedValues = @{
                    Name            = $getTargetResourceParameters.Name
                    Ensure          = 'Present'
                    Path            = $testServiceCimInstance.PathName
                    StartupType     = $convertToStartupTypeStringResult
                    BuiltInAccount  = $testServiceCimInstance.StartName
                    State           = $testService.Status
                    DisplayName     = $testService.DisplayName
                    Description     = $testServiceCimInstance.Description
                    DesktopInteract = $testServiceCimInstance.DesktopInteract
                    Dependencies    = [System.Object[]] $testService.ServicesDependedOn.Name
                }

                Test-GetTargetResourceResult -GetTargetResourceParameters $getTargetResourceParameters -ExpectedValues $expectedValues
            }

            Context 'When a service exists with no dependencies and startup account name as NT Authority\LocalService' {
                $testService = @{
                    Name = 'TestServiceName'
                    DisplayName = 'TestDisplayName'
                    Status = 'TestServiceStatus'
                    StartType = 'TestServiceStartType'
                    ServicesDependedOn = $null
                }

                $expectedBuiltInAccountValue = 'LocalService'

                $testServiceCimInstance = @{
                    Name = $testService.Name
                    PathName = 'TestServicePath'
                    Description = 'Test service description'
                    StartName = "NT Authority\$expectedBuiltInAccountValue"
                    StartMode = 'Manual'
                    DesktopInteract = $false
                }

                Mock -CommandName 'Get-Service' -MockWith { return $testService }
                Mock -CommandName 'Get-ServiceCimInstance' -MockWith { return $testServiceCimInstance }
                Mock -CommandName 'ConvertTo-StartupTypeString' -MockWith { return $convertToStartupTypeStringResult }

                Test-GetTargetResourceDoesntThrow -GetTargetResourceParameters $getTargetResourceParameters -TestServiceCimInstance $testServiceCimInstance

                $expectedValues = @{
                    Name            = $getTargetResourceParameters.Name
                    Ensure          = 'Present'
                    Path            = $testServiceCimInstance.PathName
                    StartupType     = $convertToStartupTypeStringResult
                    BuiltInAccount  = $expectedBuiltInAccountValue
                    State           = $testService.Status
                    DisplayName     = $testService.DisplayName
                    Description     = $testServiceCimInstance.Description
                    DesktopInteract = $testServiceCimInstance.DesktopInteract
                    Dependencies    = $null
                }

                Test-GetTargetResourceResult -GetTargetResourceParameters $getTargetResourceParameters -ExpectedValues $expectedValues
            }

            Context 'When a service exists with no description or display name and startup account name as NT Authority\NetworkService' {
                $testService = @{
                    Name = 'TestServiceName'
                    DisplayName = $null
                    Status = 'TestServiceStatus'
                    StartType = 'TestServiceStartType'
                    ServicesDependedOn = @(
                        @{
                            Name = 'ServiceDependency1'
                        },
                        @{
                            Name = 'ServiceDependency2'
                        }
                    )
                }

                $expectedBuiltInAccountValue = 'NetworkService'

                $testServiceCimInstance = @{
                    Name = $testService.Name
                    PathName = 'TestServicePath'
                    Description = $null
                    StartName = "NT Authority\$expectedBuiltInAccountValue"
                    StartMode = 'Disabled'
                    DesktopInteract = $false
                }

                Mock -CommandName 'Get-Service' -MockWith { return $testService }
                Mock -CommandName 'Get-ServiceCimInstance' -MockWith { return $testServiceCimInstance }
                Mock -CommandName 'ConvertTo-StartupTypeString' -MockWith { return $convertToStartupTypeStringResult }

                Test-GetTargetResourceDoesntThrow -GetTargetResourceParameters $getTargetResourceParameters -TestServiceCimInstance $testServiceCimInstance

                $expectedValues = @{
                    Name            = $getTargetResourceParameters.Name
                    Ensure          = 'Present'
                    Path            = $testServiceCimInstance.PathName
                    StartupType     = $convertToStartupTypeStringResult
                    BuiltInAccount  = $expectedBuiltInAccountValue
                    State           = $testService.Status
                    DisplayName     = $null
                    Description     = $null
                    DesktopInteract = $testServiceCimInstance.DesktopInteract
                    Dependencies    = [System.Object[]] $testService.ServicesDependedOn.Name
                }

                Test-GetTargetResourceResult -GetTargetResourceParameters $getTargetResourceParameters -ExpectedValues $expectedValues
            }

            Context 'When a service exists with with stale or corrupt dependencies' {
                <#
                    Due to a failed install or uninstall, it's possible to get in a scenario where a service
                    has a dependency configured in the registry (in the DependOnService REG_MULTI_SZ value), but
                    where the specified service no longer exists. When this occurs, Get-Service will return a member with null
                    properties within the ServicesDependedOn property for the missing service. Get-TargetResource should
                    be able to handle this.

                    Here's an example where XboxNetApiSvc has a dependency on BADSVC, which no longer exists as an actual service:

                    PS D:\> (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc' -Name 'DependOnService').DependOnService
                    BFE
                    mpssvc
                    IKEEXT
                    KeyIso
                    BADSVC

                    PS D:\> $s = Get-Service XboxNetApiSvc

                    PS D:\> $s.ServicesDependedOn

                    Status   Name               DisplayName
                    ------   ----               -----------

                    Running  KeyIso             CNG Key Isolation
                    Running  IKEEXT             IKE and AuthIP IPsec Keying Modules
                    Running  mpssvc             Windows Defender Firewall
                    Running  BFE                Base Filtering Engine


                    PS D:\> $s.ServicesDependedOn[0]

                    Status   Name               DisplayName
                    ------   ----               -----------


                    PS D:\> $s.ServicesDependedOn[0].Name -eq $null
                    True
                #>

                $testService = @{
                    Name               = 'TestServiceName'
                    DisplayName        = 'TestDisplayName'
                    Status             = 'TestServiceStatus'
                    StartType          = 'TestServiceStartType'
                    ServicesDependedOn = @(
                        @{
                            Name = 'ServiceDependency1'
                        },
                        @{
                            Name = $null
                        }
                    )
                }

                $testServiceCimInstance = @{
                    Name            = $testService.Name
                    PathName        = 'TestServicePath'
                    Description     = 'Test service description'
                    StartName       = 'LocalService'
                    StartMode       = 'Auto'
                    DesktopInteract = $false
                }

                Mock -CommandName 'Get-Service' -MockWith { return $testService }
                Mock -CommandName 'Get-ServiceCimInstance' -MockWith { return $testServiceCimInstance }
                Mock -CommandName 'ConvertTo-StartupTypeString' -MockWith { return $convertToStartupTypeStringResult }
                Mock -CommandName 'Write-Warning'

                Test-GetTargetResourceDoesntThrow -GetTargetResourceParameters $getTargetResourceParameters -TestServiceCimInstance $testServiceCimInstance

                It 'Should warn that a service dependency is corrupt' {
                    Assert-MockCalled -CommandName 'Write-Warning' -ParameterFilter { $Message -like "*has a corrupt dependency*" } -Times 1 -Scope 'Context'
                }

                $expectedValues = @{
                    Name            = $getTargetResourceParameters.Name
                    Ensure          = 'Present'
                    Path            = $testServiceCimInstance.PathName
                    StartupType     = $convertToStartupTypeStringResult
                    BuiltInAccount  = $testServiceCimInstance.StartName
                    State           = $testService.Status
                    DisplayName     = $testService.DisplayName
                    Description     = $testServiceCimInstance.Description
                    DesktopInteract = $testServiceCimInstance.DesktopInteract
                    Dependencies    = [System.Object[]] ($testService.ServicesDependedOn | Where-Object -FilterScript {![System.String]::IsNullOrEmpty($_.Name)}).Name
                }

                Test-GetTargetResourceResult -GetTargetResourceParameters $getTargetResourceParameters -ExpectedValues $expectedValues
            }
        }

        Describe 'xService\Set-TargetResource' {
            Mock -CommandName 'Assert-NoStartupTypeStateConflict' -MockWith { }

            Mock -CommandName 'Get-Service' -MockWith { }
            Mock -CommandName 'New-Service' -MockWith { }
            Mock -CommandName 'Remove-ServiceWithTimeout' -MockWith { }

            Mock -CommandName 'Set-ServicePath' -MockWith { return $true }
            Mock -CommandName 'Set-ServiceProperty' -MockWith { }

            Mock -CommandName 'Start-ServiceWithTimeout' -MockWith { }
            Mock -CommandName 'Stop-ServiceWithTimeout' -MockWith { }

            Context 'When both BuiltInAccount, Credential or GroupManagedServiceAccount specified' {
                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    BuiltInAccount = 'LocalSystem'
                    Credential = $script:testCredential1
                }

                It 'Should throw an error for BuiltInAccount and Credential conflict' {
                    $expectedErrorMessage = $script:localizedData.CredentialParametersAreMutallyExclusive -f $setTargetResourceParameters.Name
                    { Set-TargetResource @setTargetResourceParameters } | Should Throw $expectedErrorMessage
                }

                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    BuiltInAccount = 'LocalSystem'
                    GroupManagedServiceAccount = $script:gMSAUser1
                }

                It 'Should throw an error for BuiltInAccount and GroupManagedServiceAccount conflict' {
                    $expectedErrorMessage = $script:localizedData.CredentialParametersAreMutallyExclusive -f $setTargetResourceParameters.Name
                    { Set-TargetResource @setTargetResourceParameters } | Should Throw $expectedErrorMessage
                }

                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    GroupManagedServiceAccount = $script:gMSAUser1
                    Credential = $script:testCredential1
                }

                It 'Should throw an error for Credential and GroupManagedServiceAccount conflict' {
                    $expectedErrorMessage = $script:localizedData.CredentialParametersAreMutallyExclusive -f $setTargetResourceParameters.Name
                    { Set-TargetResource @setTargetResourceParameters } | Should Throw $expectedErrorMessage
                }
            }

            Context 'When a service does not exist and Ensure set to Absent' {
                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Absent'
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to create the service' {
                    Assert-MockCalled -CommandName 'New-Service' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to remove the service' {
                    Assert-MockCalled -CommandName 'Remove-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to change the service path' {
                    Assert-MockCalled -CommandName 'Set-ServicePath' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to change the service properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceProperty' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to start the service' {
                    Assert-MockCalled -CommandName 'Start-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to stop or restart the service' {
                    Assert-MockCalled -CommandName 'Stop-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }
            }

            Context 'When a service does not exist, Ensure set to Present, and Path not specified' {
                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Present'
                }

                It 'Should throw an error for the missing path' {
                    $expectedErrorMessage = $script:localizedData.ServiceDoesNotExistPathMissingError -f $script:testServiceName
                    { Set-TargetResource @setTargetResourceParameters } | Should Throw $expectedErrorMessage
                }
            }

            Context 'When a service does not exist, Ensure set to Present, and Path specified' {
                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Present'
                    Path = 'FakePath'
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should create the service' {
                    Assert-MockCalled -CommandName 'New-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name -and $BinaryPathName -eq $setTargetResourceParameters.Path } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to remove the service' {
                    Assert-MockCalled -CommandName 'Remove-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to change the service path' {
                    Assert-MockCalled -CommandName 'Set-ServicePath' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to change the service properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceProperty' -Times 0 -Scope 'Context'
                }

                It 'Should start the service' {
                    Assert-MockCalled -CommandName 'Start-ServiceWithTimeout' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to stop or restart the service' {
                    Assert-MockCalled -CommandName 'Stop-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }
            }

            Context 'When a service does not exist, Ensure set to Present, State set to Running, and all parameters except Credential and GroupManagedServiceAccount specified' {
                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Present'
                    Path = 'FakePath'
                    StartupType = 'Automatic'
                    BuiltInAccount = 'LocalSystem'
                    DesktopInteract = $true
                    State = 'Running'
                    DisplayName = 'TestDisplayName'
                    Description = 'Test device description'
                    Dependencies = @( 'TestServiceDependency1', 'TestServiceDependency2' )
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should Not Throw
                }

                It 'Should check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name -and $StartupType -eq $setTargetResourceParameters.StartupType -and $State -eq $setTargetResourceParameters.State } -Times 1 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should create the service' {
                    Assert-MockCalled -CommandName 'New-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name -and $BinaryPathName -eq $setTargetResourceParameters.Path } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to remove the service' {
                    Assert-MockCalled -CommandName 'Remove-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to change the service path' {
                    Assert-MockCalled -CommandName 'Set-ServicePath' -Times 0 -Scope 'Context'
                }

                It 'Should change all service properties except Credential' {
                    Assert-MockCalled -CommandName 'Set-ServiceProperty' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name -and $StartupType -eq $setTargetResourceParameters.StartupType -and $BuiltInAccount -eq $setTargetResourceParameters.BuiltInAccount -and $DesktopInteract -eq $setTargetResourceParameters.DesktopInteract -and $DisplayName -eq $setTargetResourceParameters.DisplayName -and $Description -eq $setTargetResourceParameters.Description -and $null -eq (Compare-Object -ReferenceObject $setTargetResourceParameters.Dependencies -DifferenceObject $Dependencies) } -Times 1 -Scope 'Context'
                }

                It 'Should start the service' {
                    Assert-MockCalled -CommandName 'Start-ServiceWithTimeout' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to stop or restart the service' {
                    Assert-MockCalled -CommandName 'Stop-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }
            }

            Context 'When a service does not exist, Ensure set to Present, State set to Stopped, and all parameters except BuiltInAccount and GroupManagedServiceAccount specified' {
                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Present'
                    Path = 'FakePath'
                    StartupType = 'Disabled'
                    Credential = $script:testCredential1
                    DesktopInteract = $true
                    State = 'Stopped'
                    DisplayName = 'TestDisplayName'
                    Description = 'Test device description'
                    Dependencies = @( 'TestServiceDependency1', 'TestServiceDependency2' )
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should Not Throw
                }

                It 'Should check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name -and $StartupType -eq $setTargetResourceParameters.StartupType -and $State -eq $setTargetResourceParameters.State } -Times 1 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should create the service' {
                    Assert-MockCalled -CommandName 'New-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name -and $BinaryPathName -eq $setTargetResourceParameters.Path } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to remove the service' {
                    Assert-MockCalled -CommandName 'Remove-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to change the service path' {
                    Assert-MockCalled -CommandName 'Set-ServicePath' -Times 0 -Scope 'Context'
                }

                It 'Should change all service properties except BuiltInAccount' {
                    Assert-MockCalled -CommandName 'Set-ServiceProperty' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name -and $StartupType -eq $setTargetResourceParameters.StartupType -and $null -eq (Compare-Object -ReferenceObject $setTargetResourceParameters.Credential -DifferenceObject $Credential) -and $DesktopInteract -eq $setTargetResourceParameters.DesktopInteract -and $DisplayName -eq $setTargetResourceParameters.DisplayName -and $Description -eq $setTargetResourceParameters.Description -and $null -eq (Compare-Object -ReferenceObject $setTargetResourceParameters.Dependencies -DifferenceObject $Dependencies) } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to start the service' {
                    Assert-MockCalled -CommandName 'Start-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should stop the service' {
                    Assert-MockCalled -CommandName 'Stop-ServiceWithTimeout' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }
            }

            Context 'When a service does not exist, Ensure set to Present, State set to Stopped, and all parameters except BuiltInAccount and Credential specified' {
                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Present'
                    Path = 'FakePath'
                    StartupType = 'Disabled'
                    GroupManagedServiceAccount = $script:gMSAUser1
                    DesktopInteract = $true
                    State = 'Stopped'
                    DisplayName = 'TestDisplayName'
                    Description = 'Test device description'
                    Dependencies = @( 'TestServiceDependency1', 'TestServiceDependency2' )
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should Not Throw
                }

                It 'Should check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name -and $StartupType -eq $setTargetResourceParameters.StartupType -and $State -eq $setTargetResourceParameters.State } -Times 1 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should create the service' {
                    Assert-MockCalled -CommandName 'New-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name -and $BinaryPathName -eq $setTargetResourceParameters.Path } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to remove the service' {
                    Assert-MockCalled -CommandName 'Remove-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to change the service path' {
                    Assert-MockCalled -CommandName 'Set-ServicePath' -Times 0 -Scope 'Context'
                }

                It 'Should set the service to start with the GroupManagedServiceAccount' {
                    Assert-MockCalled -CommandName 'Set-ServiceProperty' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name -and $StartupType -eq $setTargetResourceParameters.StartupType -and $GroupManagedServiceAccount -eq $setTargetResourceParameters.GroupManagedServiceAccount } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to start the service' {
                    Assert-MockCalled -CommandName 'Start-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should stop the service' {
                    Assert-MockCalled -CommandName 'Stop-ServiceWithTimeout' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }
            }

            $testService = @{
                Name = 'TestServiceName'
                DisplayName = 'TestDisplayName'
                Status = 'TestServiceStatus'
                StartType = 'TestServiceStartType'
                ServicesDependedOn = @(
                    @{
                        Name = 'TestServiceDependency1'
                    },
                    @{
                        Name = 'TestServiceDependency2'
                    }
                )
            }

            Mock -CommandName 'Get-Service' -MockWith { return $testService }

            Context 'When a service exists and Ensure set to Absent' {
                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Absent'
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to create the service' {
                    Assert-MockCalled -CommandName 'New-Service' -Times 0 -Scope 'Context'
                }

                It 'Should stop the service' {
                    Assert-MockCalled -CommandName 'Stop-ServiceWithTimeout' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should remove the service' {
                    Assert-MockCalled -CommandName 'Remove-ServiceWithTimeout' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to change the service path' {
                    Assert-MockCalled -CommandName 'Set-ServicePath' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to change the service properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceProperty' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to start the service' {
                    Assert-MockCalled -CommandName 'Start-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }
            }

            Context 'When a service exists and Ensure set to Present' {
                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Present'
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to create the service' {
                    Assert-MockCalled -CommandName 'New-Service' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to remove the service' {
                    Assert-MockCalled -CommandName 'Remove-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to change the service path' {
                    Assert-MockCalled -CommandName 'Set-ServicePath' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to change the service properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceProperty' -Times 0 -Scope 'Context'
                }

                It 'Should start the service' {
                    Assert-MockCalled -CommandName 'Start-ServiceWithTimeout' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to stop or restart the service' {
                    Assert-MockCalled -CommandName 'Stop-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }
            }

            Context 'When a service exists, Ensure set to Present, and Path specified' {
                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Present'
                    Path = 'TestPath'
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to create the service' {
                    Assert-MockCalled -CommandName 'New-Service' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to remove the service' {
                    Assert-MockCalled -CommandName 'Remove-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should change the service path' {
                    Assert-MockCalled -CommandName 'Set-ServicePath' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name -and $Path -eq $setTargetResourceParameters.Path } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to change the service properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceProperty' -Times 0 -Scope 'Context'
                }

                It 'Should stop the service to restart it' {
                    Assert-MockCalled -CommandName 'Stop-ServiceWithTimeout' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should start the service' {
                    Assert-MockCalled -CommandName 'Start-ServiceWithTimeout' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }
            }

            Context 'When a service exists, Ensure set to Present, State set to Stopped, and all parameters except Credential and GroupManagedServiceAccount specified' {
                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Present'
                    Path = 'FakePath'
                    StartupType = 'Automatic'
                    BuiltInAccount = 'LocalSystem'
                    DesktopInteract = $true
                    State = 'Stopped'
                    DisplayName = 'TestDisplayName'
                    Description = 'Test device description'
                    Dependencies = @( 'TestServiceDependency1', 'TestServiceDependency2' )
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should Not Throw
                }

                It 'Should check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name -and $StartupType -eq $setTargetResourceParameters.StartupType -and $State -eq $setTargetResourceParameters.State } -Times 1 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to create the service' {
                    Assert-MockCalled -CommandName 'New-Service' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to remove the service' {
                    Assert-MockCalled -CommandName 'Remove-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should change the service path' {
                    Assert-MockCalled -CommandName 'Set-ServicePath' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name -and $Path -eq $setTargetResourceParameters.Path } -Times 1 -Scope 'Context'
                }

                It 'Should change all service properties except Credential' {
                    Assert-MockCalled -CommandName 'Set-ServiceProperty' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name -and $StartupType -eq $setTargetResourceParameters.StartupType -and $BuiltInAccount -eq $setTargetResourceParameters.BuiltInAccount -and $DesktopInteract -eq $setTargetResourceParameters.DesktopInteract -and $DisplayName -eq $setTargetResourceParameters.DisplayName -and $Description -eq $setTargetResourceParameters.Description -and $null -eq (Compare-Object -ReferenceObject $setTargetResourceParameters.Dependencies -DifferenceObject $Dependencies) } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to start the service' {
                    Assert-MockCalled -CommandName 'Start-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should stop the service' {
                    Assert-MockCalled -CommandName 'Stop-ServiceWithTimeout' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }
            }

            Context 'When a service exists, Ensure set to Present, State set to Ignore, and all parameters except Path, BuiltInAccount and GroupManagedServiceAccount specified' {
                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Present'
                    StartupType = 'Manual'
                    Credential = $script:testCredential1
                    DesktopInteract = $true
                    State = 'Ignore'
                    DisplayName = 'TestDisplayName'
                    Description = 'Test device description'
                    Dependencies = @( 'TestServiceDependency1', 'TestServiceDependency2' )
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should Not Throw
                }

                It 'Should check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name -and $StartupType -eq $setTargetResourceParameters.StartupType -and $State -eq $setTargetResourceParameters.State } -Times 1 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to create the service' {
                    Assert-MockCalled -CommandName 'New-Service' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to remove the service' {
                    Assert-MockCalled -CommandName 'Remove-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to change the service path' {
                    Assert-MockCalled -CommandName 'Set-ServicePath' -Times 0 -Scope 'Context'
                }

                It 'Should change all service properties except BuiltInAccount' {
                    Assert-MockCalled -CommandName 'Set-ServiceProperty' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name -and $StartupType -eq $setTargetResourceParameters.StartupType -and $BuiltInAccount -eq $setTargetResourceParameters.BuiltInAccount -and $DesktopInteract -eq $setTargetResourceParameters.DesktopInteract -and $DisplayName -eq $setTargetResourceParameters.DisplayName -and $Description -eq $setTargetResourceParameters.Description -and $null -eq (Compare-Object -ReferenceObject $setTargetResourceParameters.Dependencies -DifferenceObject $Dependencies) } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to start the service' {
                    Assert-MockCalled -CommandName 'Start-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to stop the service' {
                    Assert-MockCalled -CommandName 'Stop-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }
            }

            Context 'When a service exists, Ensure set to Present, and DesktopInteract specified' {
                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Present'
                    DesktopInteract = $true
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to create the service' {
                    Assert-MockCalled -CommandName 'New-Service' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to remove the service' {
                    Assert-MockCalled -CommandName 'Remove-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to change the service path' {
                    Assert-MockCalled -CommandName 'Set-ServicePath' -Times 0 -Scope 'Context'
                }

                It 'Should change only DesktopInteract service property' {
                    Assert-MockCalled -CommandName 'Set-ServiceProperty' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name -and $DesktopInteract -eq $setTargetResourceParameters.DesktopInteract } -Times 1 -Scope 'Context'
                }

                It 'Should start the service' {
                    Assert-MockCalled -CommandName 'Start-ServiceWithTimeout' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to stop the service' {
                    Assert-MockCalled -CommandName 'Stop-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }
            }

            Mock -CommandName 'Set-ServicePath' -MockWith { return $false }

            Context 'When a service exists, Ensure set to Present, and matching Path to service path specified' {
                $setTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Present'
                    Path = 'TestPath'
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to create the service' {
                    Assert-MockCalled -CommandName 'New-Service' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to remove the service' {
                    Assert-MockCalled -CommandName 'Remove-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should attempt to change the service path' {
                    Assert-MockCalled -CommandName 'Set-ServicePath' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name -and $Path -eq $setTargetResourceParameters.Path } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to change the service properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceProperty' -Times 0 -Scope 'Context'
                }

                It 'Should not stop the service to restart it' {
                    Assert-MockCalled -CommandName 'Stop-ServiceWithTimeout' -Times 0 -Scope 'Context'
                }

                It 'Should start the service' {
                    Assert-MockCalled -CommandName 'Start-ServiceWithTimeout' -ParameterFilter { $ServiceName -eq $setTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }
            }
        }

        Describe 'xService\Test-TargetResource' {
            Mock -CommandName 'Assert-NoStartupTypeStateConflict' -MockWith { }
            Mock -CommandName 'Get-TargetResource' -MockWith {
                return @{
                    Name = $script:testServiceName
                    Ensure = 'Absent'
                }
            }
            Mock -CommandName 'Test-PathsMatch' -MockWith { return $true }
            Mock -CommandName 'ConvertTo-StartName' -MockWith { return $Username }

            Context 'When multiple of BuiltInAccount, Credential or GroupManagedServiceAccount are specified' {
                $testTargetResourceParameters = @{
                    Name = $script:testServiceName
                    BuiltInAccount = 'LocalSystem'
                    Credential = $script:testCredential1
                }

                It 'Should throw an error for BuiltInAccount and Credential conflict' {
                    $expectedErrorMessage = $script:localizedData.CredentialParametersAreMutallyExclusive -f $testTargetResourceParameters.Name
                    { Test-TargetResource @testTargetResourceParameters } | Should Throw $expectedErrorMessage
                }

                $testTargetResourceParameters = @{
                    Name = $script:testServiceName
                    BuiltInAccount = 'LocalSystem'
                    GroupManagedServiceAccount = $script:gMSAUser1
                }

                It 'Should throw an error for BuiltInAccount and GroupManagedServiceAccount conflict' {
                    $expectedErrorMessage = $script:localizedData.CredentialParametersAreMutallyExclusive -f $testTargetResourceParameters.Name
                    { Test-TargetResource @testTargetResourceParameters } | Should Throw $expectedErrorMessage
                }

                $testTargetResourceParameters = @{
                    Name = $script:testServiceName
                    GroupManagedServiceAccount = $script:gMSAUser1
                    Credential = $script:testCredential1
                }

                It 'Should throw an error for Credential and GroupManagedServiceAccount conflict' {
                    $expectedErrorMessage = $script:localizedData.CredentialParametersAreMutallyExclusive -f $testTargetResourceParameters.Name
                    { Test-TargetResource @testTargetResourceParameters } | Should Throw $expectedErrorMessage
                }
            }

            Context 'When a service does not exist and Ensure set to Absent' {
                $testTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Absent'
                }

                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to test if the service path matches the specified path' {
                    Assert-MockCalled -CommandName 'Test-PathsMatch' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to convert a credential username to a service start name' {
                    Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                }

                It 'Should return true' {
                    Test-TargetResource @testTargetResourceParameters | Should Be $true
                }
            }

            Context 'When a service does not exist and Ensure set to Present' {
                $testTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Present'
                }

                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to test if the service path matches the specified path' {
                    Assert-MockCalled -CommandName 'Test-PathsMatch' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to convert a credential username to a service start name' {
                    Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                }

                It 'Should return false' {
                    Test-TargetResource @testTargetResourceParameters | Should Be $false
                }
            }

        Context 'When a service does not exist, Ensure set to Present, and StartupType is set to Disabled' {
                $testTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Present'
                    StartupType = 'Disabled'
                }

                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -ParameterFilter { $ServiceName -eq $testTargetResourceParameters.Name -and $StartupType -eq $testTargetResourceParameters.StartupType } -Times 1 -Scope 'Context'
                }

                It 'Should attempt retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to test if the service path matches the specified path' {
                    Assert-MockCalled -CommandName 'Test-PathsMatch' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to convert a credential username to a service start name' {
                    Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                }

                It 'Should return true' {
                    Test-TargetResource @testTargetResourceParameters | Should Be $true
                }
            }

            $serviceResourceWithAllProperties = @{
                Name            = $script:testServiceName
                Ensure          = 'Present'
                StartupType     = 'Automatic'
                BuiltInAccount  = 'LocalSystem'
                DesktopInteract = $false
                State           = 'Running'
                Path            = 'TestPath'
                DisplayName     = 'TestDisplayName'
                Description     = 'Test service description'
                Dependencies    = @( 'TestServiceDependency1', 'TestServiceDependency2' )
            }

            Mock -CommandName 'Get-TargetResource' -MockWith { return $serviceResourceWithAllProperties }

            Context 'When a service exists and Ensure set to Absent' {
                $testTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Absent'
                }

                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to test if the service path matches the specified path' {
                    Assert-MockCalled -CommandName 'Test-PathsMatch' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to convert a credential username to a service start name' {
                    Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                }

                It 'Should return false' {
                    Test-TargetResource @testTargetResourceParameters | Should Be $false
                }
            }

            Context 'When a service exists and Ensure set to Present' {
                $testTargetResourceParameters = @{
                    Name = $script:testServiceName
                    Ensure = 'Present'
                }

                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to test if the service path matches the specified path' {
                    Assert-MockCalled -CommandName 'Test-PathsMatch' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to convert a credential username to a service start name' {
                    Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                }

                It 'Should return true' {
                    Test-TargetResource @testTargetResourceParameters | Should Be $true
                }
            }

            Context 'When a service exists, Ensure set to Present, and all matching parameters specified except Credential and GroupManagedServiceAccount' {
                $testTargetResourceParameters = $serviceResourceWithAllProperties

                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                }

                It 'Should check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -ParameterFilter { $ServiceName -eq $testTargetResourceParameters.Name -and $StartupType -eq $testTargetResourceParameters.StartupType -and $State -eq $testTargetResourceParameters.State } -Times 1 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should test if the service path matches the specified path' {
                    Assert-MockCalled -CommandName 'Test-PathsMatch' -ParameterFilter { $ExpectedPath -eq $testTargetResourceParameters.Path -and $ActualPath -eq $serviceResourceWithAllProperties.Path } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to convert a credential username to a service start name' {
                    Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                }

                It 'Should return true' {
                    Test-TargetResource @testTargetResourceParameters | Should Be $true
                }
            }

            $mismatchingParameters = @{
                StartupType = 'Manual'
                BuiltInAccount = 'NetworkService'
                DesktopInteract = $true
                State = 'Stopped'
                DisplayName = 'MismatchingDisplayName'
                Description = 'Mismatching service description'
                Dependencies    = @( 'TestServiceDependency3', 'TestServiceDependency4' )
            }

            foreach ($mismatchingParameterName in $mismatchingParameters.Keys)
            {
                Context "Service exists, Ensure set to Present, and mismatching $mismatchingParameterName specified" {
                    $testTargetResourceParameters = @{
                        Name = $serviceResourceWithAllProperties.Name
                        Ensure = 'Present'
                        $mismatchingParameterName = $mismatchingParameters[$mismatchingParameterName]
                    }

                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                    }



                    if ($mismatchingParameterName -eq 'StartupType')
                    {
                        It 'Should check for a startup type and state conflict' {
                            Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -ParameterFilter { $ServiceName -eq $testTargetResourceParameters.Name -and $StartupType -eq $testTargetResourceParameters.StartupType -and $State -eq 'Running' } -Times 1 -Scope 'Context'
                        }
                    }
                    else
                    {
                        It 'Should not check for a startup type and state conflict' {
                            Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                        }
                    }

                    It 'Should retrieve the service' {
                        Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                    }

                    It 'Should not test if the service path matches the specified path' {
                        Assert-MockCalled -CommandName 'Test-PathsMatch' -Times 0 -Scope 'Context'
                    }

                    It 'Should not attempt to convert a credential username to a service start name' {
                        Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                    }

                    It 'Should return false' {
                        Test-TargetResource @testTargetResourceParameters | Should Be $false
                    }
                }
            }

            Context 'When a service exists, Ensure set to Present, and State is set to Ignore' {
                $testTargetResourceParameters = @{
                    Name = $serviceResourceWithAllProperties.Name
                    Ensure = 'Present'
                    State = 'Ignore'
                }

                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not test if the service path matches the specified path' {
                    Assert-MockCalled -CommandName 'Test-PathsMatch' -Times 0 -Scope 'Context'
                }

                It 'Should not attempt to convert a credential username to a service start name' {
                    Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                }

                It 'Should return true' {
                    Test-TargetResource @testTargetResourceParameters | Should Be $true
                }
            }

            $serviceResourceWithCustomBuiltInAccount = @{
                Name            = $script:testServiceName
                Ensure          = 'Present'
                State           = 'Running'
                BuiltInAccount  = $script:testCredential1.UserName
                DisplayName     = 'TestDisplayName'
                Description     = 'Test service description'
                Dependencies    = @( 'TestServiceDependency1', 'TestServiceDependency2' )
            }

            Mock -CommandName 'Get-TargetResource' -MockWith { return $serviceResourceWithCustomBuiltInAccount }

            Context 'When a service exists, Ensure set to Present, and matching Credential specified' {
                $testTargetResourceParameters = @{
                    Name = $serviceResourceWithCustomBuiltInAccount.Name
                    Ensure = 'Present'
                    Credential = $script:testCredential1
                }

                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not test if the service path matches the specified path' {
                    Assert-MockCalled -CommandName 'Test-PathsMatch' -Times 0 -Scope 'Context'
                }

                It 'Should convert the credential username to a service start name' {
                    Assert-MockCalled -CommandName 'ConvertTo-StartName' -ParameterFilter { $Username -eq $script:testCredential1.UserName } -Times 1 -Scope 'Context'
                }

                It 'Should return true' {
                    Test-TargetResource @testTargetResourceParameters | Should Be $true
                }
            }

            Context 'When a service exists, Ensure set to Present, and mismatching Credential specified' {
                $testTargetResourceParameters = @{
                    Name = $serviceResourceWithCustomBuiltInAccount.Name
                    Ensure = 'Present'
                    Credential = $script:testCredential2
                }

                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not test if the service path matches the specified path' {
                    Assert-MockCalled -CommandName 'Test-PathsMatch' -Times 0 -Scope 'Context'
                }

                It 'Should convert the credential username to a service start name' {
                    Assert-MockCalled -CommandName 'ConvertTo-StartName' -ParameterFilter { $Username -eq $script:testCredential2.UserName } -Times 1 -Scope 'Context'
                }

                It 'Should return false' {
                    Test-TargetResource @testTargetResourceParameters | Should Be $false
                }
            }

            $allowedEmptyPropertyNames = @( 'DisplayName', 'Description', 'Dependencies' )

            foreach ($allowedEmptyPropertyName in $allowedEmptyPropertyNames)
            {
                Context "Service exists, Ensure set to Present, $allowedEmptyPropertyName specified as empty" {
                    $testTargetResourceParameters = @{
                        Name = $serviceResourceWithCustomBuiltInAccount.Name
                        Ensure = 'Present'
                    }

                    if ($allowedEmptyPropertyName -eq 'Dependencies')
                    {
                        $testTargetResourceParameters[$allowedEmptyPropertyName] = @()
                    }
                    else
                    {
                        $testTargetResourceParameters[$allowedEmptyPropertyName] = ''
                    }

                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                    }

                    It 'Should not check for a startup type and state conflict' {
                        Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                    }

                    It 'Should retrieve the service' {
                        Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                    }

                    It 'Should not test if the service path matches the specified path' {
                        Assert-MockCalled -CommandName 'Test-PathsMatch' -Times 0 -Scope 'Context'
                    }

                    It 'Should not attempt to convert a credential username to a service start name' {
                        Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                    }

                    It 'Should return false' {
                        Test-TargetResource @testTargetResourceParameters | Should Be $false
                    }
                }
            }

            $serviceResourceWithNullProperties = @{
                Name   = $script:testServiceName
                Ensure = 'Present'
                Path   = 'TestPath'
                State  = 'Running'
            }

            foreach ($nullPropertyName in $allowedEmptyPropertyNames)
            {
                $serviceResourceWithNullProperties[$nullPropertyName] = $null
            }

            Mock -CommandName 'Get-TargetResource' -MockWith { return $serviceResourceWithNullProperties }

            foreach ($nullPropertyName in $allowedEmptyPropertyNames)
            {
                Context "Service exists but DisplayName, Description, and Dependencies are null, Ensure set to Present, $nullPropertyName specified" {
                    $testTargetResourceParameters = @{
                        Name = $serviceResourceWithNullProperties.Name
                        Ensure = 'Present'
                        $nullPropertyName = 'Something'
                    }

                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                    }

                    It 'Should not check for a startup type and state conflict' {
                        Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                    }

                    It 'Should retrieve the service' {
                        Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                    }

                    It 'Should not test if the service path matches the specified path' {
                        Assert-MockCalled -CommandName 'Test-PathsMatch' -Times 0 -Scope 'Context'
                    }

                    It 'Should not attempt to convert a credential username to a service start name' {
                        Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                    }

                    It 'Should return false' {
                        Test-TargetResource @testTargetResourceParameters | Should Be $false
                    }
                }

                Context "Service exists but DisplayName, Description, and Dependencies are null, Ensure set to Present, $nullPropertyName not specified" {
                    $testTargetResourceParameters = @{
                        Name = $serviceResourceWithNullProperties.Name
                        Ensure = 'Present'
                    }

                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                    }

                    It 'Should not check for a startup type and state conflict' {
                        Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                    }

                    It 'Should retrieve the service' {
                        Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                    }

                    It 'Should not test if the service path matches the specified path' {
                        Assert-MockCalled -CommandName 'Test-PathsMatch' -Times 0 -Scope 'Context'
                    }

                    It 'Should not attempt to convert a credential username to a service start name' {
                        Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                    }

                    It 'Should return true' {
                        Test-TargetResource @testTargetResourceParameters | Should Be $true
                    }
                }
            }

            Mock -CommandName 'Test-PathsMatch' -MockWith { return $false }

            Context 'When a service exists, Ensure set to Present, and mismatching Path specified' {
                $testTargetResourceParameters = @{
                    Name = $serviceResourceWithCustomBuiltInAccount.Name
                    Ensure = 'Present'
                    Path = 'Mismatching path'
                }

                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should test if the service path matches the specified path' {
                    Assert-MockCalled -CommandName 'Test-PathsMatch' -ParameterFilter { $ExpectedPath -eq $testTargetResourceParameters.Path -and $ActualPath -eq $serviceResourceWithNullProperties.Path } -Times 1 -Scope 'Context'
                }

                It 'Should not attempt to convert a credential username to a service start name' {
                    Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                }

                It 'Should return false' {
                    Test-TargetResource @testTargetResourceParameters | Should Be $false
                }
            }

            $serviceResourceWithGroupManagedServiceAccount = @{
                Name            = $script:testServiceName
                Ensure          = 'Present'
                State           = 'Running'
                BuiltInAccount  = $script:gMSAUser1
                DisplayName     = 'TestDisplayName'
                Description     = 'Test service description'
                Dependencies    = @( 'TestServiceDependency1', 'TestServiceDependency2' )
            }

            Mock -CommandName 'Get-TargetResource' -MockWith { return $serviceResourceWithGroupManagedServiceAccount }

            Context 'When a service exists, Ensure set to Present, and mismatching GroupManagedServiceAccount specified' {
                $testTargetResourceParameters = @{
                    Name = $serviceResourceWithCustomBuiltInAccount.Name
                    Ensure = 'Present'
                    GroupManagedServiceAccount = $script:gMSAUser2
                }

                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                }

                It 'Should not check for a startup type and state conflict' {
                    Assert-MockCalled -CommandName 'Assert-NoStartupTypeStateConflict' -Times 0 -Scope 'Context'
                }

                It 'Should retrieve the service' {
                    Assert-MockCalled -CommandName 'Get-TargetResource' -ParameterFilter { $Name -eq $testTargetResourceParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should not test if the service path matches the specified path' {
                    Assert-MockCalled -CommandName 'Test-PathsMatch' -Times 0 -Scope 'Context'
                }

                It 'Should convert the credential username to a service start name' {
                    Assert-MockCalled -CommandName 'ConvertTo-StartName' -ParameterFilter { $Username -eq $script:gMSAUser2 } -Times 1 -Scope 'Context'
                }

                It 'Should return false' {
                    Test-TargetResource @testTargetResourceParameters | Should Be $false
                }
            }

            Context 'When a service exists, Ensure set to Present, and matching GroupManagedServiceAccount specified' {
                $testTargetResourceParameters = @{
                    Name = $serviceResourceWithCustomBuiltInAccount.Name
                    Ensure = 'Present'
                    GroupManagedServiceAccount = $script:gMSAUser1
                }

                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourceParameters } | Should Not Throw
                }

                It 'Should return true' {
                    Test-TargetResource @testTargetResourceParameters | Should Be $true
                }
            }
        }

        Describe 'xService\Get-ServiceCimInstance' {
            Mock -CommandName 'Get-CimInstance' -MockWith { }

            Context 'When a service does not exist' {
                It 'Should not throw' {
                    { Get-ServiceCimInstance -ServiceName $script:testServiceName } | Should Not Throw
                }

                It 'Should retrieve the CIM instance of the service with the given name' {
                    Assert-MockCalled -CommandName 'Get-CimInstance' -ParameterFilter {$ClassName -ieq 'Win32_Service' -and $Filter.Contains($script:testServiceName)} -Times 1 -Scope 'Context'
                }

                It 'Should return null' {
                    Get-ServiceCimInstance -ServiceName $script:testServiceName | Should Be $null
                }
            }

            $testCimInstance = 'TestCimInstance'

            Mock -CommandName 'Get-CimInstance' -MockWith { return $testCimInstance }

            Context 'When a service exists' {
                It 'Should not throw' {
                    { Get-ServiceCimInstance -ServiceName $script:testServiceName } | Should Not Throw
                }

                It 'Should retrieve the CIM instance of the service with the given name' {
                    Assert-MockCalled -CommandName 'Get-CimInstance' -ParameterFilter {$ClassName -ieq 'Win32_Service' -and $Filter.Contains($script:testServiceName)} -Times 1 -Scope 'Context'
                }

                It 'Should return the retrieved CIM instance' {
                    Get-ServiceCimInstance -ServiceName $script:testServiceName | Should Be $testCimInstance
                }
            }
        }

        Describe 'xService\ConvertTo-StartupTypeString' {
            Context 'When StartupType is specifed as Auto' {
                It 'Should return Automatic' {
                    ConvertTo-StartupTypeString -StartMode 'Auto' | Should Be 'Automatic'
                }
            }

            Context 'When StartupType is specifed as Manual' {
                It 'Should return Manual' {
                    ConvertTo-StartupTypeString -StartMode 'Manual' | Should Be 'Manual'
                }
            }

            Context 'When StartupType is specifed as Disabled' {
                It 'Should return Disabled' {
                    ConvertTo-StartupTypeString -StartMode 'Disabled' | Should Be 'Disabled'
                }
            }
        }

        Describe 'xService\Assert-NoStartupTypeStateConflict' {
            $stateValues = @( 'Running', 'Stopped', 'Ignore' )
            $startupTypeValues = @( 'Manual', 'Automatic', 'Disabled' )

            foreach ($startupTypeValue in $startupTypeValues)
            {
                foreach ($stateValue in $stateValues)
                {
                    Context "StartupType specified as $startupTypeValue and State specified as $stateValue" {
                        $assertNoStartupTypeStateConflictParameters = @{
                            ServiceName = $script:testServiceName
                            StartupType = $startupTypeValue
                            State = $stateValue
                        }

                        if ($stateValue -eq 'Running' -and $startupTypeValue -eq 'Disabled')
                        {
                            It 'Should throw error for conflicting state and startup type' {
                                $errorMessage = $script:localizedData.StartupTypeStateConflict -f $assertNoStartupTypeStateConflictParameters.ServiceName, $startupTypeValue, $stateValue
                                { Assert-NoStartupTypeStateConflict @assertNoStartupTypeStateConflictParameters } | Should Throw $errorMessage
                            }
                        }
                        elseif ($stateValue -eq 'Stopped' -and $startupTypeValue -eq 'Automatic')
                        {
                            It 'Should throw error for conflicting state and startup type' {
                                $errorMessage = $script:localizedData.StartupTypeStateConflict -f $assertNoStartupTypeStateConflictParameters.ServiceName, $startupTypeValue, $stateValue
                                { Assert-NoStartupTypeStateConflict @assertNoStartupTypeStateConflictParameters } | Should Throw $errorMessage
                            }
                        }
                        else
                        {
                            It 'Should not throw' {
                                { Assert-NoStartupTypeStateConflict @assertNoStartupTypeStateConflictParameters } | Should Not Throw
                            }
                        }
                    }
                }
            }
        }

        Describe 'xService\Test-PathsMatch' {
            Context 'When Specified paths match' {
                It 'Should return true' {
                    $matchingPath = 'MatchingPath'
                    Test-PathsMatch -ExpectedPath $matchingPath -ActualPath $matchingPath | Should Be $true
                }
            }

            Context 'When Specified paths do not match' {
                It 'Should return false' {
                    Test-PathsMatch -ExpectedPath 'Path1' -ActualPath 'Path2' | Should Be $false
                }
            }
        }

        Describe 'xService\ConvertTo-StartName' {
            Context 'When Username is specified as LocalSystem' {
                It 'Should return .\LocalSystem' {
                    ConvertTo-StartName -Username 'LocalSystem' | Should Be '.\LocalSystem'
                }
            }

            Context 'When Username is specified as LocalService' {
                It 'Should return NT Authority\LocalService' {
                    ConvertTo-StartName -Username 'LocalService' | Should Be 'NT Authority\LocalService'
                }
            }

            Context 'When Username is specified as NetworkService' {
                It 'Should return NT Authority\NetworkService' {
                    ConvertTo-StartName -Username 'NetworkService' | Should Be 'NT Authority\NetworkService'
                }
            }

            Context 'When custom username is specified without any \ or @ characters' {
                It 'Should return custom username prefixed with .\' {
                    $customUsername = 'TestUsername'
                    ConvertTo-StartName -Username $customUsername | Should Be ".\$customUsername"
                }
            }

            Context 'When custom username is specified that starts with the local computer name followed by a \ character' {
                It 'Should return custom username prefixed with .\ instead of the local computer name' {
                    $customUsername = 'TestUsername'
                    $customUsernameWithComputerNamePrefix = "$env:computerName\$customUsername"
                    ConvertTo-StartName -Username $customUsernameWithComputerNamePrefix | Should Be ".\$customUsername"
                }
            }

            Context 'When custom username is specified with a \ character and a custom domain' {
                It 'Should return the custom username with no changes' {
                    $customUsername = 'TestDomain\TestUsername'
                    ConvertTo-StartName -Username $customUsername | Should Be $customUsername
                }
            }

            Context 'When custom username is specified with an @ character' {
                It 'Should return the custom username with no changes' {
                    $customUsername = 'TestUsername@TestDomain'
                    ConvertTo-StartName -Username $customUsername | Should Be $customUsername
                }
            }
        }

        Describe 'xService\Set-ServicePath' {
            $testServiceCimInstance = New-CimInstance -ClassName 'Win32_Service' -Property @{ PathName = 'TestPath' } -ClientOnly

            try
            {
                Mock -CommandName 'Get-ServiceCimInstance' -MockWith { return $testServiceCimInstance }
                Mock -CommandName 'Test-PathsMatch' -MockWith { return $true }

                $invokeCimMethodSuccessResult = @{
                    ReturnValue = 0
                }

                Mock -CommandName 'Invoke-CimMethod' -MockWith { return $invokeCimMethodSuccessResult }

                Context 'When specified path matches the service path' {
                    $setServicePathParameters = @{
                        ServiceName = $script:testServiceName
                        Path = $testServiceCimInstance.PathName
                    }

                    It 'Should not throw' {
                        { Set-ServicePath @setServicePathParameters } | Should Not Throw
                    }

                    It 'Should retrieve the service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServicePathParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should test if the specfied path matches the service path' {
                        Assert-MockCalled -CommandName 'Test-PathsMatch' -ParameterFilter { $ExpectedPath -eq $setServicePathParameters.Path -and $ActualPath -eq $testServiceCimInstance.PathName } -Times 1 -Scope 'Context'
                    }

                    It 'Should not change the service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -Times 0 -Scope 'Context'
                    }

                    It 'Should return false' {
                        Set-ServicePath @setServicePathParameters | Should Be $false
                    }
                }

                Mock -CommandName 'Test-PathsMatch' -MockWith { return $false }

                Context 'When specified path does not match the service path and the path change succeeds' {
                    $setServicePathParameters = @{
                        ServiceName = $script:testServiceName
                        Path = 'NewTestPath'
                    }

                    It 'Should not throw' {
                        { Set-ServicePath @setServicePathParameters } | Should Not Throw
                    }

                    It 'Should retrieve the service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServicePathParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should test if the specfied path matches the service path' {
                        Assert-MockCalled -CommandName 'Test-PathsMatch' -ParameterFilter { $ExpectedPath -eq $setServicePathParameters.Path -and $ActualPath -eq $testServiceCimInstance.PathName } -Times 1 -Scope 'Context'
                    }

                    It 'Should change the service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -ParameterFilter { $InputObject -eq $testServiceCimInstance -and $MethodName -eq 'Change' -and $Arguments.PathName -eq $setServicePathParameters.Path} -Times 1 -Scope 'Context'
                    }

                    It 'Should return true' {
                        Set-ServicePath @setServicePathParameters | Should Be $true
                    }
                }

                $invokeCimMethodFailResult = @{
                    ReturnValue = 1
                }

                Mock -CommandName 'Invoke-CimMethod' -MockWith { return $invokeCimMethodFailResult }

                Context 'When specified path does not match the service path and the path change fails' {
                    $setServicePathParameters = @{
                        ServiceName = $script:testServiceName
                        Path = 'NewTestPath'
                    }

                    It 'Should throw error for failed service path change' {
                        $errorMessage = $script:localizedData.InvokeCimMethodFailed -f 'Change', $setServicePathParameters.ServiceName, 'PathName', $invokeCimMethodFailResult.ReturnValue

                        { Set-ServicePath @setServicePathParameters } | Should Throw $errorMessage
                    }
                }
            }
            finally
            {
                $testServiceCimInstance.Dispose()

                # Release the reference so the garbage collector can clean up
                $testServiceCimInstance = $null
            }
        }

        Describe 'xService\Set-ServiceDependency' {
            $testServiceCimInstance = New-CimInstance -ClassName 'Win32_Service' -ClientOnly

            try {
                $testService = @{
                    ServicesDependedOn = @( @{ Name = 'TestDependency1' }, @{ Name = 'TestDependency2'} )
                }

                Mock -CommandName 'Get-Service' -MockWith { return $testService }
                Mock -CommandName 'Get-ServiceCimInstance' -MockWith { return $testServiceCimInstance }

                $invokeCimMethodSuccessResult = @{
                    ReturnValue = 0
                }

                Mock -CommandName 'Invoke-CimMethod' -MockWith { return $invokeCimMethodSuccessResult }

                Context 'When specified dependencies match the service dependencies' {
                    $setServiceDependenciesParameters = @{
                        ServiceName = $script:testServiceName
                        Dependencies = $testService.ServicesDependedOn.Name
                    }

                    It 'Should not throw' {
                        { Set-ServiceDependency @setServiceDependenciesParameters } | Should Not Throw
                    }

                    It 'Should retrieve the service' {
                        Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setServiceDependenciesParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should not retrieve the service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -Times 0 -Scope 'Context'
                    }

                    It 'Should not change the service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -Times 0 -Scope 'Context'
                    }
                }

                Context 'When specified dependencies do not match the populated service dependencies and the dependency change succeeds' {
                    $setServiceDependenciesParameters = @{
                        ServiceName = $script:testServiceName
                        Dependencies = @( 'TestDependency3', 'TestDependency4' )
                    }

                    It 'Should not throw' {
                        { Set-ServiceDependency @setServiceDependenciesParameters } | Should Not Throw
                    }

                    It 'Should retrieve the service' {
                        Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setServiceDependenciesParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should retrieve the service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServiceDependenciesParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should change the service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -ParameterFilter { $InputObject -eq $testServiceCimInstance -and $MethodName -eq 'Change' -and $null -eq (Compare-Object -ReferenceObject $setServiceDependenciesParameters.Dependencies -DifferenceObject $Arguments.ServiceDependencies) } -Times 1 -Scope 'Context'
                    }
                }

                Context 'When specified empty dependencies do not match the populated service dependencies and the dependency change succeeds' {
                    $setServiceDependenciesParameters = @{
                        ServiceName = $script:testServiceName
                        Dependencies = @()
                    }

                    It 'Should not throw' {
                        { Set-ServiceDependency @setServiceDependenciesParameters } | Should Not Throw
                    }

                    It 'Should retrieve the service' {
                        Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setServiceDependenciesParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should retrieve the service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServiceDependenciesParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should change the service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -ParameterFilter { $InputObject -eq $testServiceCimInstance -and $MethodName -eq 'Change' -and $null -eq (Compare-Object -ReferenceObject $setServiceDependenciesParameters.Dependencies -DifferenceObject $Arguments.ServiceDependencies) } -Times 1 -Scope 'Context'
                    }
                }

                $testServiceWithNoDependencies = @{
                    ServicesDependedOn = $null
                }

                Mock -CommandName 'Get-Service' -MockWith { return $testServiceWithNoDependencies }

                Context 'When specified empty dependencies match the null service dependencies' {
                    $setServiceDependenciesParameters = @{
                        ServiceName = $script:testServiceName
                        Dependencies = @()
                    }

                    It 'Should not throw' {
                        { Set-ServiceDependency @setServiceDependenciesParameters } | Should Not Throw
                    }

                    It 'Should retrieve the service' {
                        Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setServiceDependenciesParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should not retrieve the service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -Times 0 -Scope 'Context'
                    }

                    It 'Should not change the service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -Times 0 -Scope 'Context'
                    }
                }

                Context 'When specified dependencies do not match the null service dependencies and the dependency change succeeds' {
                    $setServiceDependenciesParameters = @{
                        ServiceName = $script:testServiceName
                        Dependencies = @( 'TestDependency3', 'TestDependency4' )
                    }

                    It 'Should not throw' {
                        { Set-ServiceDependency @setServiceDependenciesParameters } | Should Not Throw
                    }

                    It 'Should retrieve the service' {
                        Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $setServiceDependenciesParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should retrieve the service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServiceDependenciesParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should change the service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -ParameterFilter { $InputObject -eq $testServiceCimInstance -and $MethodName -eq 'Change' -and $null -eq (Compare-Object -ReferenceObject $setServiceDependenciesParameters.Dependencies -DifferenceObject $Arguments.ServiceDependencies) } -Times 1 -Scope 'Context'
                    }
                }

                $invokeCimMethodFailResult = @{
                    ReturnValue = 1
                }

                Mock -CommandName 'Invoke-CimMethod' -MockWith { return $invokeCimMethodFailResult }

                Context 'When specified dependencies do not match the service dependencies and the dependency change fails' {
                    $setServiceDependenciesParameters = @{
                        ServiceName = $script:testServiceName
                        Dependencies = @( 'TestDependency3', 'TestDependency4' )
                    }

                    It 'Should throw error for failed service path change' {
                        $errorMessage = $script:localizedData.InvokeCimMethodFailed -f 'Change', $setServiceDependenciesParameters.ServiceName, 'ServiceDependencies', $invokeCimMethodFailResult.ReturnValue

                        { Set-ServiceDependency @setServiceDependenciesParameters } | Should Throw $errorMessage
                    }
                }
            }
            finally
            {
                $testServiceCimInstance.Dispose()
            }
        }

        Describe 'xService\Set-ServiceAccountProperty' {
            $testServiceCimInstance = New-CimInstance -ClassName 'Win32_Service' -Property @{ StartName = 'LocalSystem'; DesktopInteract = $true } -ClientOnly

            try {
                Mock -CommandName 'Get-ServiceCimInstance' -MockWith { return $testServiceCimInstance }
                Mock -CommandName 'Grant-LogOnAsServiceRight' -MockWith { }
                Mock -CommandName 'ConvertTo-StartName' -MockWith { return $Username }

                $invokeCimMethodSuccessResult = @{
                    ReturnValue = 0
                }

                Mock -CommandName 'Invoke-CimMethod' -MockWith { return $invokeCimMethodSuccessResult }

                Context 'When no parameters are specified' {
                    $setServiceAccountPropertyParameters = @{
                        ServiceName = $script:testServiceName
                    }

                    It 'Should not throw' {
                        { Set-ServiceAccountProperty @setServiceAccountPropertyParameters } | Should Not Throw
                    }

                    It 'Should retrieve service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServiceAccountPropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should not attempt to convert the built-in account or credential username to a service start name' {
                        Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                    }

                    It 'Should not attempt to grant Log on As a Service right' {
                        Assert-MockCalled -CommandName 'Grant-LogOnAsServiceRight' -Times 0 -Scope 'Context'
                    }

                    It 'Should not attempt to change service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -Times 0 -Scope 'Context'
                    }
                }

                Context 'When matching DesktopInteract specified' {
                    $setServiceAccountPropertyParameters = @{
                        ServiceName = $script:testServiceName
                        DesktopInteract = $testServiceCimInstance.DesktopInteract
                    }

                    It 'Should not throw' {
                        { Set-ServiceAccountProperty @setServiceAccountPropertyParameters } | Should Not Throw
                    }

                    It 'Should retrieve service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServiceAccountPropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should not attempt to convert the built-in account or credential username to a service start name' {
                        Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                    }

                    It 'Should not attempt to grant Log on As a Service right' {
                        Assert-MockCalled -CommandName 'Grant-LogOnAsServiceRight' -Times 0 -Scope 'Context'
                    }

                    It 'Should not attempt to change service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -Times 0 -Scope 'Context'
                    }
                }

                Context 'When mismatching DesktopInteract specified and service change succeeds' {
                    $setServiceAccountPropertyParameters = @{
                        ServiceName = $script:testServiceName
                        DesktopInteract = -not $testServiceCimInstance.DesktopInteract
                    }

                    It 'Should not throw' {
                        { Set-ServiceAccountProperty @setServiceAccountPropertyParameters } | Should Not Throw
                    }

                    It 'Should retrieve service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServiceAccountPropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should not attempt to convert the built-in account or credential username to a service start name' {
                        Assert-MockCalled -CommandName 'ConvertTo-StartName' -Times 0 -Scope 'Context'
                    }

                    It 'Should not attempt to grant Log on As a Service right' {
                        Assert-MockCalled -CommandName 'Grant-LogOnAsServiceRight' -Times 0 -Scope 'Context'
                    }

                    It 'Should change service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -ParameterFilter { $InputObject -eq $testServiceCimInstance -and $MethodName -eq 'Change' -and $Arguments.DesktopInteract -eq $setServiceAccountPropertyParameters.DesktopInteract} -Times 1 -Scope 'Context'
                    }
                }

                Context 'When credential with matching username specified' {
                    $secureTestPassword = ConvertTo-SecureString -String 'TestPassword' -AsPlainText -Force
                    $testCredentialWithMatchingUsername = New-Object -TypeName 'PSCredential' -ArgumentList @( $testServiceCimInstance.StartName, $secureTestPassword )

                    $setServiceAccountPropertyParameters = @{
                        ServiceName = $script:testServiceName
                        Credential = $testCredentialWithMatchingUsername
                    }

                    It 'Should not throw' {
                        { Set-ServiceAccountProperty @setServiceAccountPropertyParameters } | Should Not Throw
                    }

                    It 'Should retrieve service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServiceAccountPropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should convert the credential username to a service start name' {
                        Assert-MockCalled -CommandName 'ConvertTo-StartName' -ParameterFilter { $Username -eq $setServiceAccountPropertyParameters.Credential.UserName } -Times 1 -Scope 'Context'
                    }

                    It 'Should not attempt to grant Log on As a Service right' {
                        Assert-MockCalled -CommandName 'Grant-LogOnAsServiceRight' -Times 0 -Scope 'Context'
                    }

                    It 'Should not attempt to change service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -Times 0 -Scope 'Context'
                    }
                }

                Context 'When credential with mismatching username specified and service change succeeds' {
                    $setServiceAccountPropertyParameters = @{
                        ServiceName = $script:testServiceName
                        Credential = $script:testCredential1
                    }

                    It 'Should not throw' {
                        { Set-ServiceAccountProperty @setServiceAccountPropertyParameters } | Should Not Throw
                    }

                    It 'Should retrieve service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServiceAccountPropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should convert the credential username to a service start name' {
                        Assert-MockCalled -CommandName 'ConvertTo-StartName' -ParameterFilter { $Username -eq $setServiceAccountPropertyParameters.Credential.UserName } -Times 1 -Scope 'Context'
                    }

                    It 'Should grant Log on As a Service right' {
                        Assert-MockCalled -CommandName 'Grant-LogOnAsServiceRight' -ParameterFilter { $Username -eq $setServiceAccountPropertyParameters.Credential.UserName } -Times 1 -Scope 'Context'
                    }

                    It 'Should change service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -ParameterFilter { $InputObject -eq $testServiceCimInstance -and $MethodName -eq 'Change' -and $Arguments.StartName -eq $setServiceAccountPropertyParameters.Credential.UserName -and $Arguments.StartPassword -eq $setServiceAccountPropertyParameters.Credential.GetNetworkCredential().Password } -Times 1 -Scope 'Context'
                    }
                }

                Context 'When matching BuiltInAccount specified' {
                    $setServiceAccountPropertyParameters = @{
                        ServiceName = $script:testServiceName
                        BuiltInAccount = $testServiceCimInstance.StartName
                    }

                    It 'Should not throw' {
                        { Set-ServiceAccountProperty @setServiceAccountPropertyParameters } | Should Not Throw
                    }

                    It 'Should retrieve service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServiceAccountPropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should convert the built-in account to a service start name' {
                        Assert-MockCalled -CommandName 'ConvertTo-StartName' -ParameterFilter { $Username -eq $setServiceAccountPropertyParameters.BuiltInAccount } -Times 1 -Scope 'Context'
                    }

                    It 'Should not attempt to grant Log on As a Service right' {
                        Assert-MockCalled -CommandName 'Grant-LogOnAsServiceRight' -Times 0 -Scope 'Context'
                    }

                    It 'Should not attempt to change service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -Times 0 -Scope 'Context'
                    }
                }

                Context 'When mismatching BuiltInAccount specified and service change succeeds' {
                    $setServiceAccountPropertyParameters = @{
                        ServiceName = $script:testServiceName
                        BuiltInAccount = 'NetworkService'
                    }

                    It 'Should not throw' {
                        { Set-ServiceAccountProperty @setServiceAccountPropertyParameters } | Should Not Throw
                    }

                    It 'Should retrieve service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServiceAccountPropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should convert the built-in account to a service start name' {
                        Assert-MockCalled -CommandName 'ConvertTo-StartName' -ParameterFilter { $Username -eq $setServiceAccountPropertyParameters.BuiltInAccount } -Times 1 -Scope 'Context'
                    }

                    It 'Should not attempt to grant Log on As a Service right' {
                        Assert-MockCalled -CommandName 'Grant-LogOnAsServiceRight' -Times 0 -Scope 'Context'
                    }

                    It 'Should change service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -ParameterFilter { $InputObject -eq $testServiceCimInstance -and $MethodName -eq 'Change' -and $Arguments.StartName -eq $setServiceAccountPropertyParameters.BuiltInAccount -and $Arguments.StartPassword -eq [System.String]::Empty } -Times 1 -Scope 'Context'
                    }
                }

                $testServiceCimInstance = New-CimInstance -ClassName 'Win32_Service' -Property @{ StartName = $script:gMSAUser1; DesktopInteract = $true } -ClientOnly
                Mock -CommandName 'Get-ServiceCimInstance' -MockWith { return $testServiceCimInstance }

                Context 'When matching GroupManagedServiceAccount specified' {
                    $setServiceAccountPropertyParameters = @{
                        ServiceName = $script:testServiceName
                        GroupManagedServiceAccount = $script:gMSAUser1
                    }

                    It 'Should not throw' {
                        { Set-ServiceAccountProperty @setServiceAccountPropertyParameters } | Should Not Throw
                    }

                    It 'Should retrieve service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServiceAccountPropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should convert the GroupManagedServiceAccount to a service start name' {
                        Assert-MockCalled -CommandName 'ConvertTo-StartName' -ParameterFilter { $Username -eq $setServiceAccountPropertyParameters.GroupManagedServiceAccount } -Times 1 -Scope 'Context'
                    }

                    It 'Should not attempt to grant Log on As a Service right' {
                        Assert-MockCalled -CommandName 'Grant-LogOnAsServiceRight' -Times 0 -Scope 'Context'
                    }

                    It 'Should not attempt to change service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -Times 0 -Scope 'Context'
                    }
                }

                Context 'When mismatching GroupManagedServiceAccount specified and service change succeeds' {
                    $setServiceAccountPropertyParameters = @{
                        ServiceName = $script:testServiceName
                        GroupManagedServiceAccount = $script:gMSAUser2
                    }

                    It 'Should not throw' {
                        { Set-ServiceAccountProperty @setServiceAccountPropertyParameters } | Should Not Throw
                    }

                    It 'Should retrieve service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServiceAccountPropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should convert the GroupManagedServiceAccount to a service start name' {
                        Assert-MockCalled -CommandName 'ConvertTo-StartName' -ParameterFilter { $Username -eq $setServiceAccountPropertyParameters.GroupManagedServiceAccount } -Times 1 -Scope 'Context'
                    }

                    It 'Should attempt to grant Log on As a Service right' {
                        Assert-MockCalled -CommandName 'Grant-LogOnAsServiceRight' -Times 1 -Scope 'Context'
                    }

                    It 'Should change service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -ParameterFilter { $InputObject -eq $testServiceCimInstance -and $MethodName -eq 'Change' -and $Arguments.StartName -eq $setServiceAccountPropertyParameters.GroupManagedServiceAccount } -Times 1 -Scope 'Context'
                    }
                }

                $invokeCimMethodFailResult = @{
                    ReturnValue = 1
                }

                Mock -CommandName 'Invoke-CimMethod' -MockWith { return $invokeCimMethodFailResult }

                Context 'When mismatching DesktopInteract specified and service change fails' {
                    $setServiceAccountPropertyParameters = @{
                        ServiceName = $script:testServiceName
                        DesktopInteract = -not $testServiceCimInstance.DesktopInteract
                    }

                    It 'Should throw an error for service change failure' {
                        $errorMessage = $script:localizedData.InvokeCimMethodFailed -f 'Change', $setServiceAccountPropertyParameters.ServiceName, 'DesktopInteract', $invokeCimMethodFailResult.ReturnValue

                        { Set-ServiceAccountProperty @setServiceAccountPropertyParameters } | Should Throw $errorMessage
                    }
                }

                Context 'When Credential with mismatching username specified and service change fails' {
                    $setServiceAccountPropertyParameters = @{
                        ServiceName = $script:testServiceName
                        Credential = $script:testCredential1
                    }

                    It 'Should throw an error for service change failure' {
                        $errorMessage = $script:localizedData.InvokeCimMethodFailed -f 'Change', $setServiceAccountPropertyParameters.ServiceName, 'StartName, StartPassword', $invokeCimMethodFailResult.ReturnValue

                        { Set-ServiceAccountProperty @setServiceAccountPropertyParameters } | Should Throw $errorMessage
                    }
                }

                Context 'When mismatching BuiltInAccount specified and service change fails' {
                    $setServiceAccountPropertyParameters = @{
                        ServiceName = $script:testServiceName
                        BuiltInAccount = 'NetworkService'
                    }

                    It 'Should throw an error for service change failure' {
                        $errorMessage = $script:localizedData.InvokeCimMethodFailed -f 'Change', $setServiceAccountPropertyParameters.ServiceName, 'StartName, StartPassword', $invokeCimMethodFailResult.ReturnValue

                        { Set-ServiceAccountProperty @setServiceAccountPropertyParameters } | Should Throw $errorMessage
                    }
                }
            }
            finally
            {
                $testServiceCimInstance.Dispose()

                # Release the reference so the garbage collector can clean up
                $testServiceCimInstance = $null
            }
        }

        Describe 'xService\Set-ServiceStartupType' {
            $testServiceCimInstance = New-CimInstance -ClassName 'Win32_Service' -Property @{ StartMode = 'Manual' } -ClientOnly

            try {
                Mock -CommandName 'Get-ServiceCimInstance' -MockWith { return $testServiceCimInstance }
                Mock -CommandName 'ConvertTo-StartupTypeString' -MockWith { return $testServiceCimInstance.StartMode }

                $invokeCimMethodSuccessResult = @{
                    ReturnValue = 0
                }

                Mock -CommandName 'Invoke-CimMethod' -MockWith { return $invokeCimMethodSuccessResult }

                Context 'When specified startup type matches the service startup type' {
                    $setServiceStartupTypeParameters = @{
                        ServiceName = $script:testServiceName
                        StartupType = $testServiceCimInstance.StartMode
                    }

                    It 'Should not throw' {
                        { Set-ServiceStartupType @setServiceStartupTypeParameters } | Should Not Throw
                    }

                    It 'Should retrieve the service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServiceStartupTypeParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should not attempt to change the service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -Times 0 -Scope 'Context'
                    }
                }

                Context 'When specified startup type does not match the service startup type and service change succeeds' {
                    $setServiceStartupTypeParameters = @{
                        ServiceName = $script:testServiceName
                        StartupType = 'Automatic'
                    }

                    It 'Should not throw' {
                        { Set-ServiceStartupType @setServiceStartupTypeParameters } | Should Not Throw
                    }

                    It 'Should retrieve the service CIM instance' {
                        Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServiceStartupTypeParameters.ServiceName } -Times 1 -Scope 'Context'
                    }

                    It 'Should change the service' {
                        Assert-MockCalled -CommandName 'Invoke-CimMethod' -ParameterFilter { $InputObject -eq $testServiceCimInstance -and $MethodName -eq 'Change' -and $Arguments.StartMode -eq $setServiceStartupTypeParameters.StartupType } -Times 1 -Scope 'Context'
                    }
                }

                $invokeCimMethodFailResult = @{
                    ReturnValue = 1
                }

                Mock -CommandName 'Invoke-CimMethod' -MockWith { return $invokeCimMethodFailResult }

                Context 'When specified startup type does not match the service startup type and service change fails' {
                    $setServiceStartupTypeParameters = @{
                        ServiceName = $script:testServiceName
                        StartupType = 'Automatic'
                    }

                    It 'Should throw error for failed service change' {
                        $errorMessage = $script:localizedData.InvokeCimMethodFailed -f 'Change', $setServiceStartupTypeParameters.ServiceName, 'StartMode', $invokeCimMethodFailResult.ReturnValue

                        { Set-ServiceStartupType @setServiceStartupTypeParameters } | Should Throw $errorMessage
                    }
                }
            }
            finally
            {
                $testServiceCimInstance.Dispose()

                # Release the reference so the garbage collector can clean up
                $testServiceCimInstance = $null
            }
        }

        Describe 'xService\Set-ServiceProperty' {
            $testServiceCimInstance = @{
                Description = 'Test service description'
                DisplayName = 'TestDisplayName'
            }

            Mock -CommandName 'Get-ServiceCimInstance' -MockWith { return $testServiceCimInstance }
            Mock -CommandName 'Set-Service' -MockWith { }
            Mock -CommandName 'Set-ServiceDependency' -MockWith { }
            Mock -CommandName 'Set-ServiceAccountProperty' -MockWith { }
            Mock -CommandName 'Set-ServiceStartupType' -MockWith { }

            Context 'When no parameters are specified' {
                $setServicePropertyParameters = @{
                    ServiceName = $script:testServiceName
                }

                It 'Should not throw' {
                    { Set-ServiceProperty @setServicePropertyParameters } | Should Not Throw
                }

                It 'Should retrieve service CIM instance' {
                    Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServicePropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                }

                It 'Should not set service description or display name' {
                    Assert-MockCalled -CommandName 'Set-Service' -Times 0 -Scope 'Context'
                }

                It 'Should not set service dependencies' {
                    Assert-MockCalled -CommandName 'Set-ServiceDependency' -Times 0 -Scope 'Context'
                }

                It 'Should not set service account properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceAccountProperty' -Times 0 -Scope 'Context'
                }

                It 'Should not set service startup type' {
                    Assert-MockCalled -CommandName 'Set-ServiceStartupType' -Times 0 -Scope 'Context'
                }
            }

            Context 'When mismatching DisplayName is specified' {
                $setServicePropertyParameters = @{
                    ServiceName = $script:testServiceName
                    DisplayName = 'NewDisplayName'
                }

                It 'Should not throw' {
                    { Set-ServiceProperty @setServicePropertyParameters } | Should Not Throw
                }

                It 'Should retrieve service CIM instance' {
                    Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServicePropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                }

                It 'Should set service display name' {
                    Assert-MockCalled -CommandName 'Set-Service' -ParameterFilter { $Name -eq $setServicePropertyParameters.ServiceName -and $DisplayName -eq $setServicePropertyParameters.DisplayName } -Times 1 -Scope 'Context'
                }

                It 'Should not set service dependencies' {
                    Assert-MockCalled -CommandName 'Set-ServiceDependency' -Times 0 -Scope 'Context'
                }

                It 'Should not set service account properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceAccountProperty' -Times 0 -Scope 'Context'
                }

                It 'Should not set service startup type' {
                    Assert-MockCalled -CommandName 'Set-ServiceStartupType' -Times 0 -Scope 'Context'
                }
            }

            Context 'When mismatching Description is specified' {
                $setServicePropertyParameters = @{
                    ServiceName = $script:testServiceName
                    Description = 'New service description'
                }

                It 'Should not throw' {
                    { Set-ServiceProperty @setServicePropertyParameters } | Should Not Throw
                }

                It 'Should retrieve service CIM instance' {
                    Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServicePropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                }

                It 'Should set service description' {
                    Assert-MockCalled -CommandName 'Set-Service' -ParameterFilter { $Name -eq $setServicePropertyParameters.ServiceName -and $Description -eq $setServicePropertyParameters.Description } -Times 1 -Scope 'Context'
                }

                It 'Should not set service dependencies' {
                    Assert-MockCalled -CommandName 'Set-ServiceDependency' -Times 0 -Scope 'Context'
                }

                It 'Should not set service account properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceAccountProperty' -Times 0 -Scope 'Context'
                }

                It 'Should not set service startup type' {
                    Assert-MockCalled -CommandName 'Set-ServiceStartupType' -Times 0 -Scope 'Context'
                }
            }

            Context 'When matching Description and DisplayName specified' {
                $setServicePropertyParameters = @{
                    ServiceName = $script:testServiceName
                    DisplayName = $testServiceCimInstance.DisplayName
                    Description = $testServiceCimInstance.Description
                }

                It 'Should not throw' {
                    { Set-ServiceProperty @setServicePropertyParameters } | Should Not Throw
                }

                It 'Should retrieve service CIM instance' {
                    Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServicePropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                }

                It 'Should not set service description or display name' {
                    Assert-MockCalled -CommandName 'Set-Service' -Times 0 -Scope 'Context'
                }

                It 'Should not set service dependencies' {
                    Assert-MockCalled -CommandName 'Set-ServiceDependency' -Times 0 -Scope 'Context'
                }

                It 'Should not set service account properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceAccountProperty' -Times 0 -Scope 'Context'
                }

                It 'Should not set service startup type' {
                    Assert-MockCalled -CommandName 'Set-ServiceStartupType' -Times 0 -Scope 'Context'
                }
            }

            Context 'When Dependencies specified' {
                $setServicePropertyParameters = @{
                    ServiceName = $script:testServiceName
                    Dependencies = @( 'TestDependency1' )
                }

                It 'Should not throw' {
                    { Set-ServiceProperty @setServicePropertyParameters } | Should Not Throw
                }

                It 'Should retrieve service CIM instance' {
                    Assert-MockCalled `
                        -CommandName 'Get-ServiceCimInstance' `
                        -ParameterFilter {
                            $ServiceName -eq $setServicePropertyParameters.ServiceName
                        } `
                        -Times 1 `
                        -Scope 'Context'
                }

                It 'Should not set service description or display name' {
                    Assert-MockCalled -CommandName 'Set-Service' -Times 0 -Scope 'Context'
                }

                It 'Should set service dependencies' {
                    Assert-MockCalled `
                        -CommandName 'Set-ServiceDependency' `
                        -ParameterFilter {
                            $ServiceName -eq $setServicePropertyParameters.ServiceName -and `
                            $null -eq (Compare-Object -ReferenceObject $setServicePropertyParameters.Dependencies -DifferenceObject $Dependencies)
                        } `
                        -Times 1 `
                        -Scope 'Context'
                }

                It 'Should not set service account properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceAccountProperty' -Times 0 -Scope 'Context'
                }

                It 'Should not set service startup type' {
                    Assert-MockCalled -CommandName 'Set-ServiceStartupType' -Times 0 -Scope 'Context'
                }
            }

            Context 'When Credential specified' {
                $setServicePropertyParameters = @{
                    ServiceName = $script:testServiceName
                    Credential = $script:testCredential1
                }

                It 'Should not throw' {
                    { Set-ServiceProperty @setServicePropertyParameters } | Should Not Throw
                }

                It 'Should retrieve service CIM instance' {
                    Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServicePropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                }

                It 'Should not set service description or display name' {
                    Assert-MockCalled -CommandName 'Set-Service' -Times 0 -Scope 'Context'
                }

                It 'Should not set service dependencies' {
                    Assert-MockCalled -CommandName 'Set-ServiceDependency' -Times 0 -Scope 'Context'
                }

                It 'Should set service account properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceAccountProperty' -ParameterFilter { $ServiceName -eq $setServicePropertyParameters.ServiceName -and [System.Management.Automation.PSCredential]::Equals($setServicePropertyParameters.Credential, $Credential) } -Times 1 -Scope 'Context'
                }

                It 'Should not set service startup type' {
                    Assert-MockCalled -CommandName 'Set-ServiceStartupType' -Times 0 -Scope 'Context'
                }
            }

            Context 'When BuiltInAccount specified' {
                $setServicePropertyParameters = @{
                    ServiceName = $script:testServiceName
                    BuiltInAccount = 'LocalService'
                }

                It 'Should not throw' {
                    { Set-ServiceProperty @setServicePropertyParameters } | Should Not Throw
                }

                It 'Should retrieve service CIM instance' {
                    Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServicePropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                }

                It 'Should not set service description or display name' {
                    Assert-MockCalled -CommandName 'Set-Service' -Times 0 -Scope 'Context'
                }

                It 'Should not set service dependencies' {
                    Assert-MockCalled -CommandName 'Set-ServiceDependency' -Times 0 -Scope 'Context'
                }

                It 'Should set service account properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceAccountProperty' -ParameterFilter { $ServiceName -eq $setServicePropertyParameters.ServiceName -and $BuiltInAccount -eq $setServicePropertyParameters.BuiltInAccount } -Times 1 -Scope 'Context'
                }

                It 'Should not set service startup type' {
                    Assert-MockCalled -CommandName 'Set-ServiceStartupType' -Times 0 -Scope 'Context'
                }
            }

            Context 'When GroupManagedServiceAccount specified' {
                $setServicePropertyParameters = @{
                    ServiceName = $script:testServiceName
                    GroupManagedServiceAccount = $script:gMSAUser1
                }

                It 'Should not throw' {
                    { Set-ServiceProperty @setServicePropertyParameters } | Should Not Throw
                }

                It 'Should retrieve service CIM instance' {
                    Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServicePropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                }

                It 'Should not set service description or display name' {
                    Assert-MockCalled -CommandName 'Set-Service' -Times 0 -Scope 'Context'
                }

                It 'Should not set service dependencies' {
                    Assert-MockCalled -CommandName 'Set-ServiceDependency' -Times 0 -Scope 'Context'
                }

                It 'Should set service account properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceAccountProperty' -ParameterFilter { $ServiceName -eq $setServicePropertyParameters.ServiceName -and $GroupManagedServiceAccount -eq $setServicePropertyParameters.GroupManagedServiceAccount } -Times 1 -Scope 'Context'
                }

                It 'Should not set service startup type' {
                    Assert-MockCalled -CommandName 'Set-ServiceStartupType' -Times 0 -Scope 'Context'
                }
            }


            Context 'When DesktopInteract specified' {
                $setServicePropertyParameters = @{
                    ServiceName = $script:testServiceName
                    DesktopInteract = $true
                }

                It 'Should not throw' {
                    { Set-ServiceProperty @setServicePropertyParameters } | Should Not Throw
                }

                It 'Should retrieve service CIM instance' {
                    Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServicePropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                }

                It 'Should not set service description or display name' {
                    Assert-MockCalled -CommandName 'Set-Service' -Times 0 -Scope 'Context'
                }

                It 'Should not set service dependencies' {
                    Assert-MockCalled -CommandName 'Set-ServiceDependency' -Times 0 -Scope 'Context'
                }

                It 'Should set service account properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceAccountProperty' -ParameterFilter { $ServiceName -eq $setServicePropertyParameters.ServiceName -and $DesktopInteract -eq $setServicePropertyParameters.DesktopInteract } -Times 1 -Scope 'Context'
                }

                It 'Should not set service startup type' {
                    Assert-MockCalled -CommandName 'Set-ServiceStartupType' -Times 0 -Scope 'Context'
                }
            }

            Context 'When StartupType specified' {
                $setServicePropertyParameters = @{
                    ServiceName = $script:testServiceName
                    StartupType = 'Manual'
                }

                It 'Should not throw' {
                    { Set-ServiceProperty @setServicePropertyParameters } | Should Not Throw
                }

                It 'Should retrieve service CIM instance' {
                    Assert-MockCalled -CommandName 'Get-ServiceCimInstance' -ParameterFilter { $ServiceName -eq $setServicePropertyParameters.ServiceName } -Times 1 -Scope 'Context'
                }

                It 'Should not set service description or display name' {
                    Assert-MockCalled -CommandName 'Set-Service' -Times 0 -Scope 'Context'
                }

                It 'Should not set service dependencies' {
                    Assert-MockCalled -CommandName 'Set-ServiceDependency' -Times 0 -Scope 'Context'
                }

                It 'Should not set service account properties' {
                    Assert-MockCalled -CommandName 'Set-ServiceAccountProperty' -Times 0 -Scope 'Context'
                }

                It 'Should set service startup type' {
                    Assert-MockCalled -CommandName 'Set-ServiceStartupType' -ParameterFilter { $ServiceName -eq $setServicePropertyParameters.ServiceName -and $StartupType -eq $setServicePropertyParameters.StartupType } -Times 1 -Scope 'Context'
                }
            }
        }

        Describe 'xService\Remove-ServiceWithTimeout' {
            Mock -CommandName 'Remove-Service' -MockWith { }
            Mock -CommandName 'Get-Service' -MockWith { }

            Context 'When a service removal succeeds' {
                $removeServiceWithTimeoutParameters = @{
                    Name = $script:testServiceName
                    TerminateTimeout = 500
                }

                It 'Should not throw' {
                    { Remove-ServiceWithTimeout @removeServiceWithTimeoutParameters } | Should Not Throw
                }

                It 'Should remove service' {
                    Assert-MockCalled -CommandName 'Remove-Service' -ParameterFilter { $Name -eq $removeServiceWithTimeoutParameters.Name } -Times 1 -Scope 'Context'
                }

                It 'Should retrieve service to check for removal once' {
                    Assert-MockCalled -CommandName 'Get-Service' -ParameterFilter { $Name -eq $removeServiceWithTimeoutParameters.Name } -Times 1 -Scope 'Context'
                }
            }

            Mock -CommandName 'Get-Service' -MockWith { return 'Not null' }

            Context 'When a service removal fails' {
                $removeServiceWithTimeoutParameters = @{
                    Name = $script:testServiceName
                    TerminateTimeout = 500
                }

                It 'Should throw error for service removal timeout' {
                    $errorMessage = $script:localizedData.ServiceDeletionFailed -f $removeServiceWithTimeoutParameters.Name
                    { Remove-ServiceWithTimeout @removeServiceWithTimeoutParameters } | Should Throw $errorMessage
                }
            }
        }

        Describe 'xService\Start-ServiceWithTimeout' {
            Mock -CommandName 'Start-Service' -MockWith { }
            Mock -CommandName 'Wait-ServiceStateWithTimeout' -MockWith { }

            $startServiceWithTimeoutParameters = @{
                ServiceName = $script:testServiceName
                StartupTimeout = 500
            }

            $expectedTimeSpan = [System.TimeSpan]::FromMilliseconds($startServiceWithTimeoutParameters.StartupTimeout)

            It 'Should not throw' {
                { Start-ServiceWithTimeout @startServiceWithTimeoutParameters } | Should Not Throw
            }

            It 'Should start service' {
                Assert-MockCalled -CommandName 'Start-Service' -ParameterFilter { $Name -eq $startServiceWithTimeoutParameters.ServiceName } -Times 1 -Scope 'Describe'
            }

            It 'Should wait for service to start' {
                Assert-MockCalled -CommandName 'Wait-ServiceStateWithTimeout' -ParameterFilter { $ServiceName -eq $startServiceWithTimeoutParameters.ServiceName -and $State -eq [System.ServiceProcess.ServiceControllerStatus]::Running -and [System.TimeSpan]::Equals($expectedTimeSpan, $WaitTimeSpan) } -Times 1 -Scope 'Describe'
            }
        }

        Describe 'xService\Stop-ServiceWithTimeout' {
            Mock -CommandName 'Stop-Service' -MockWith { }
            Mock -CommandName 'Wait-ServiceStateWithTimeout' -MockWith { }

            $stopServiceWithTimeoutParameters = @{
                ServiceName = $script:testServiceName
                TerminateTimeout = 500
            }

            $expectedTimeSpan = [System.TimeSpan]::FromMilliseconds($stopServiceWithTimeoutParameters.TerminateTimeout)

            It 'Should not throw' {
                { Stop-ServiceWithTimeout @stopServiceWithTimeoutParameters } | Should Not Throw
            }

            It 'Should stop service' {
                Assert-MockCalled -CommandName 'Stop-Service' -ParameterFilter { $Name -eq $stopServiceWithTimeoutParameters.ServiceName } -Times 1 -Scope 'Describe'
            }

            It 'Should wait for service to stop' {
                Assert-MockCalled -CommandName 'Wait-ServiceStateWithTimeout' -ParameterFilter { $ServiceName -eq $stopServiceWithTimeoutParameters.ServiceName -and $State -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped -and [System.TimeSpan]::Equals($expectedTimeSpan, $WaitTimeSpan) } -Times 1 -Scope 'Describe'
            }
        }
    }
}
finally
{
    Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
}
