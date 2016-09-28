# Suppressed as per PSSA Rule Severity guidelines for unit/integration tests:
# https://github.com/PowerShell/DscResources/blob/master/PSSARuleSeverities.md
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

$script:DSCModuleName      = 'xPSDesiredStateConfiguration'
$script:DSCResourceName    = 'MSFT_xServiceResource'

#region HEADER
# Integration Test Template Version: 1.1.0
[String] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:DSCModuleName `
    -DSCResourceName $script:DSCResourceName `
    -TestType Unit
#endregion

# Begin Testing
try
{

    # This is needed so that the ServiceControllerStatus enum is recognized as a valid type
    Add-Type -AssemblyName 'System.ServiceProcess'

    InModuleScope $script:DSCResourceName {
        $DSCResourceName = 'MSFT_xServiceResource'

        $script:testServiceName = 'DscTestService'
        $script:testServiceDisplayName = 'DSC test service display name'
        $script:testServiceDescription = 'This is DSC test service used for integration testing MSFT_xServiceResource'
        $script:testServiceDependsOn = @('winrm','spooler')
        $script:testServiceDependsOnHash = @( @{ name = 'winrm' }, @{ name = 'spooler' } )
        $script:testServiceExecutablePath = Join-Path -Path $ENV:Temp -ChildPath 'DscTestService.exe'
        $script:testServiceStartupType = 'Automatic'
        $script:testServiceStartupTypeWin32 = 'Auto'
        $script:testServiceStatusRunning = [System.ServiceProcess.ServiceControllerStatus]::Running
        $script:testServiceStatusStopped = [System.ServiceProcess.ServiceControllerStatus]::Stopped
        $script:testUsername = 'TestUser'
        $script:testPassword = 'DummyPassword'
        $script:testCredential = New-Object `
            -TypeName System.Management.Automation.PSCredential `
            -ArgumentList ($script:testUsername, `
                (ConvertTo-SecureString $script:testPassword -AsPlainText -Force))
        $script:testNewUsername = 'DifferentUser'
        $script:testNewCredential = New-Object `
            -TypeName System.Management.Automation.PSCredential `
            -ArgumentList ($script:testNewUsername, `
                (ConvertTo-SecureString $script:testPassword -AsPlainText -Force))

        $script:testServiceMockRunning = New-Object -TypeName PSObject -Property @{
            Name               = $script:testServiceName
            ServiceName        = $script:testServiceName
            DisplayName        = $script:testServiceDisplayName
            StartType          = $script:testServiceStartupType
            Status             = $script:testServiceStatusRunning
            ServicesDependedOn = $script:testServiceDependsOnHash
        }

        Add-Member -InputObject  $script:testServiceMockRunning `
            -MemberType ScriptMethod `
            -Name Stop -Value { $global:ServiceStopped = $True }

        Add-Member -InputObject  $script:testServiceMockRunning `
            -MemberType ScriptMethod `
            -Name WaitForStatus -Value {
                param(
                    $Status, $WaitTimeSpan
                )
            }

        $script:testServiceMockStopped = New-Object -TypeName PSObject -Property @{
            Name               = $script:testServiceName
            ServiceName        = $script:testServiceName
            DisplayName        = $script:testServiceDisplayName
            StartType          = $script:testServiceStartupType
            Status             = $script:testServiceStatusStopped
            ServicesDependedOn = $script:testServiceDependsOnHash
        }

        Add-Member -InputObject  $script:testServiceMockStopped `
            -MemberType ScriptMethod `
            -Name Start -Value { $global:ServiceStarted = $True }

        Add-Member -InputObject  $script:testServiceMockStopped `
            -MemberType ScriptMethod `
            -Name WaitForStatus -Value {
                param(
                    $Status, $WaitTimeSpan
                )
            }

        $script:testWin32ServiceMockRunningLocalSystem = New-Object -TypeName PSObject -Property @{
            Name                    = $script:testServiceName
            Status                  = 'OK'
            DesktopInteract         = $true
            PathName                = $script:testServiceExecutablePath
            StartMode               = $script:testServiceStartupTypeWin32
            Description             = $script:testServiceDescription
            Started                 = $true
            DisplayName             = $script:testServiceDisplayName
            StartName               = 'LocalSystem'
            State                   = $script:testServiceStatusRunning
        }

        $script:splatServiceExistsAutomatic = @{
            Name                    = $script:testServiceName
            StartupType             = $script:testServiceStartupType
            BuiltInAccount          = 'LocalSystem'
            DesktopInteract         = $true
            State                   = $script:testServiceStatusRunning
            Ensure                  = 'Present'
            Path                    = $script:testServiceExecutablePath
            DisplayName             = $script:testServiceDisplayName
            Description             = $script:testServiceDescription
        }

        function Get-InvalidArgumentError
        {
            [CmdletBinding()]
            param
            (
                [Parameter(Mandatory)]
                [ValidateNotNullOrEmpty()]
                [System.String]
                $ErrorId,

                [Parameter(Mandatory)]
                [ValidateNotNullOrEmpty()]
                [System.String]
                $ErrorMessage
            )

            $exception = New-Object -TypeName System.InvalidOperationException `
                -ArgumentList $ErrorMessage
            $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidOperation
            $errorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord `
                -ArgumentList $exception, $ErrorId, $errorCategory, $null
            return $errorRecord
        } # end function Get-InvalidArgumentError

        Describe "$DSCResourceName\Get-TargetResource" {
            Context 'Service exists' {
                # Mocks that should be called
                Mock `
                    -CommandName Test-ServiceExist `
                    -MockWith { $true } `
                    -Verifiable

                Mock `
                    -CommandName Get-ServiceResource `
                    -MockWith { $script:testServiceMockRunning } `
                    -Verifiable

                Mock `
                    -CommandName Get-Win32ServiceObject `
                    -MockWith { $script:testWin32ServiceMockRunningLocalSystem } `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:service = Get-TargetResource `
                            -Name $script:testServiceName `
                            -Verbose } | Should Not Throw
                }

                It 'Should return the correct hashtable properties' {
                    $service.Ensure          | Should Be 'Present'
                    $service.Name            | Should Be $script:testServiceName
                    $service.StartupType     | Should Be $script:testServiceStartupType
                    $service.BuiltInAccount  | Should Be 'LocalSystem'
                    $service.State           | Should Be $script:testServiceStatusRunning
                    $service.Path            | Should Be $script:testServiceExecutablePath
                    $service.DisplayName     | Should Be $script:testServiceDisplayName
                    $service.Description     | Should Be $script:testServiceDescription
                    $service.DesktopInteract | Should Be $true
                    $service.Dependencies    | Should Be $script:testServiceDependsOn
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Get-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                }
            }

            Context 'Service does not exist' {
                # Mocks that should be called
                Mock -CommandName Test-ServiceExist -MockWith { $false } -Verifiable

                # Mocks that should not be called
                Mock -CommandName Get-serviceResource

                Mock -CommandName Get-Win32ServiceObject

                It 'Should not throw an exception' {
                    { $script:service = Get-TargetResource `
                        -Name $script:testServiceName `
                        -Verbose } | Should Not Throw
                }

                It 'Should return the correct hashtable properties' {
                    $service.Ensure          | Should Be 'Absent'
                    $service.Name            | Should Be $script:testServiceName
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Get-serviceResource -Exactly 0
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 0
                }
            }
        }

        Describe "$DSCResourceName\Test-TargetResource" {
            # Mocks that should be called
            Mock `
                -CommandName Test-ServiceExist `
                -MockWith { $true } `
                -Verifiable

            Mock `
                -CommandName Test-StartupType `
                -Verifiable

            Mock `
                -CommandName Get-ServiceResource `
                -MockWith { $script:testServiceMockRunning } `
                -Verifiable

            Mock `
                -CommandName Get-Win32ServiceObject `
                -MockWith { $script:testWin32ServiceMockRunningLocalSystem } `
                -Verifiable

            Mock `
                -CommandName Compare-ServicePath `
                -MockWith { $true } `
                -Verifiable

            Mock `
                -CommandName Test-UserName `
                -MockWith { $true } `
                -Verifiable

            Context 'Service exists and should, and all parameters match' {
                It 'Should not throw an exception' {
                    $Splat = $script:splatServiceExistsAutomatic.Clone()
                    { $script:result = Test-TargetResource @Splat `
                        -Verbose } | Should Not Throw
                }

                It 'Should return true' {
                    $script:result | Should Be $True
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Get-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Test-StartupType -Exactly 1
                    Assert-MockCalled -CommandName Compare-ServicePath -Exactly 1
                    Assert-MockCalled -CommandName Test-UserName -Exactly 1
                }
            }

            Context 'Service exists and should, path mistmatches' {
                # Mocks that should be called
                Mock `
                    -CommandName Compare-ServicePath `
                    -MockWith { $false } `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName Test-UserName

                It 'Should not throw an exception' {
                    $Splat = $script:splatServiceExistsAutomatic.Clone()
                    $Splat.Path = 'c:\ANewPath.exe'
                    { $script:result = Test-TargetResource @Splat `
                        -Verbose } | Should Not Throw
                }

                It 'Should return false' {
                    $script:result | Should Be $False
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Get-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Test-StartupType -Exactly 1
                    Assert-MockCalled -CommandName Compare-ServicePath -Exactly 1
                    Assert-MockCalled -CommandName Test-UserName -Exactly 0
                }
            }

            Context 'Service exists and should, startup type mistmatches' {
                # Mocks that should be called
                Mock `
                    -CommandName Test-UserName `
                    -MockWith { $true } `
                    -Verifiable

                It 'Should not throw an exception' {
                    $Splat = $script:splatServiceExistsAutomatic.Clone()
                    $Splat.StartupType = 'Manual'
                    { $script:result = Test-TargetResource @Splat `
                        -Verbose } | Should Not Throw
                }

                It 'Should return false' {
                    $script:result | Should Be $False
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Get-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Test-StartupType -Exactly 1
                    Assert-MockCalled -CommandName Compare-ServicePath -Exactly 1
                    Assert-MockCalled -CommandName Test-UserName -Exactly 1
                }
            }

            Context 'Service exists and should, credential mistmatches' {
                # Mocks that should be called
                Mock `
                    -CommandName Test-UserName `
                    -MockWith { $false } `
                    -Verifiable

                It 'Should not throw an exception' {
                    $Splat = $script:splatServiceExistsAutomatic.Clone()
                    $Splat.Credential = $script:testNewCredential
                    { $script:result = Test-TargetResource @Splat `
                        -Verbose } | Should Not Throw
                }

                It 'Should return false' {
                    $script:result | Should Be $False
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Get-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Test-StartupType -Exactly 1
                    Assert-MockCalled -CommandName Compare-ServicePath -Exactly 1
                    Assert-MockCalled -CommandName Test-UserName -Exactly 1
                }
            }

            Context 'Service exists and should, is running but should be stopped' {
                # Mocks that should be called
                Mock `
                    -CommandName Compare-ServicePath `
                    -MockWith { $false } `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName Test-UserName

                It 'Should not throw an exception' {
                    $Splat = $script:splatServiceExistsAutomatic.Clone()
                    $Splat.State = 'Stopped'
                    { $script:result = Test-TargetResource @Splat `
                        -Verbose } | Should Not Throw
                }

                It 'Should return false' {
                    $script:result | Should Be $False
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Get-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Test-StartupType -Exactly 1
                    Assert-MockCalled -CommandName Compare-ServicePath -Exactly 1
                    Assert-MockCalled -CommandName Test-UserName -Exactly 0
                }
            }

            Context 'Service exists and should not' {
                # Mocks that should not be called
                Mock -CommandName Compare-ServicePath
                Mock -CommandName Test-UserName
                Mock -CommandName Get-ServiceResource
                Mock -CommandName Get-Win32ServiceObject

                It 'Should not throw an exception' {
                    $Splat = $script:splatServiceExistsAutomatic.Clone()
                    $Splat.Ensure = 'Absent'
                    { $script:result = Test-TargetResource @Splat `
                        -Verbose } | Should Not Throw
                }

                It 'Should return false' {
                    $script:result | Should Be $False
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Get-ServiceResource -Exactly 0
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 0
                    Assert-MockCalled -CommandName Test-StartupType -Exactly 1
                    Assert-MockCalled -CommandName Compare-ServicePath -Exactly 0
                    Assert-MockCalled -CommandName Test-UserName -Exactly 0
                }
            }
        }

        Describe "$DSCResourceName\Set-TargetResource" {
            Context 'Service exists and should not' {
                # Mocks that should be called
                Mock `
                    -CommandName Test-StartupType `
                    -Verifiable

                Mock `
                    -CommandName Test-ServiceExist `
                    -MockWith { $true } `
                    -Verifiable

                Mock `
                    -CommandName Stop-ServiceResource `
                    -Verifiable

                Mock `
                    -CommandName Remove-Service `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName Start-ServiceResource
                Mock -CommandName New-Service
                Mock -CommandName Compare-ServicePath
                Mock -CommandName Write-WriteProperty

                It 'Should not throw an exception' {
                    $Splat = $script:splatServiceExistsAutomatic.Clone()
                    $Splat.Ensure = 'Absent'
                    { Set-TargetResource @Splat `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-StartupType -Exactly 1
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Start-ServiceResource -Exactly 0
                    Assert-MockCalled -CommandName Stop-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName Remove-Service -Exactly 1
                    Assert-MockCalled -CommandName New-Service -Exactly 0
                    Assert-MockCalled -CommandName Compare-ServicePath -Exactly 0
                    Assert-MockCalled -CommandName Write-WriteProperty -Exactly 0
                }
            }

            Context 'Service exists and should, should be running, all parameters passed and match' {
                # Mocks that should be called
                Mock `
                    -CommandName Test-StartupType `
                    -Verifiable

                Mock `
                    -CommandName Test-ServiceExist `
                    -MockWith { $true } `
                    -Verifiable

                Mock `
                    -CommandName Compare-ServicePath `
                    -MockWith { $true } `
                    -Verifiable

                Mock `
                    -CommandName Write-WriteProperty `
                    -MockWith { $false } `
                    -Verifiable

                Mock `
                    -CommandName Start-ServiceResource `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName Stop-ServiceResource
                Mock -CommandName New-Service
                Mock -CommandName Remove-Service

                It 'Should not throw an exception' {
                    $Splat = $script:splatServiceExistsAutomatic.Clone()
                    { Set-TargetResource @Splat `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-StartupType -Exactly 1
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Start-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName Stop-ServiceResource -Exactly 0
                    Assert-MockCalled -CommandName Remove-Service -Exactly 0
                    Assert-MockCalled -CommandName New-Service -Exactly 0
                    Assert-MockCalled -CommandName Compare-ServicePath -Exactly 1
                    Assert-MockCalled -CommandName Write-WriteProperty -Exactly 1
                }
            }

            Context 'Service exists and should, should be running, path needs change' {
                # Mocks that should be called
                Mock `
                    -CommandName Test-StartupType `
                    -Verifiable

                Mock `
                    -CommandName Test-ServiceExist `
                    -MockWith { $true } `
                    -Verifiable

                Mock `
                    -CommandName Compare-ServicePath `
                    -MockWith { $false } `
                    -Verifiable

                Mock `
                    -CommandName Write-WriteProperty `
                    -MockWith { $false } `
                    -Verifiable

                Mock `
                    -CommandName Start-ServiceResource `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName Stop-ServiceResource
                Mock -CommandName New-Service
                Mock -CommandName Remove-Service

                It 'Should not throw an exception' {
                    $Splat = $script:splatServiceExistsAutomatic.Clone()
                    $Splat.Path = 'c:\NewServicePath.exe'
                    { Set-TargetResource @Splat `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-StartupType -Exactly 1
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Start-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName Stop-ServiceResource -Exactly 0
                    Assert-MockCalled -CommandName Remove-Service -Exactly 0
                    Assert-MockCalled -CommandName New-Service -Exactly 0
                    Assert-MockCalled -CommandName Compare-ServicePath -Exactly 1
                    Assert-MockCalled -CommandName Write-WriteProperty -Exactly 1
                }
            }

            Context 'Service exists and should, should be running but needs restart, all parameters passed and match' {
                # Mocks that should be called
                Mock `
                    -CommandName Test-StartupType `
                    -Verifiable

                Mock `
                    -CommandName Test-ServiceExist `
                    -MockWith { $true } `
                    -Verifiable

                Mock `
                    -CommandName Compare-ServicePath `
                    -MockWith { $true } `
                    -Verifiable

                Mock `
                    -CommandName Write-WriteProperty `
                    -MockWith { $true } `
                    -Verifiable

                Mock `
                    -CommandName Start-ServiceResource `
                    -Verifiable

                Mock `
                    -CommandName Stop-ServiceResource `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName New-Service
                Mock -CommandName Remove-Service

                It 'Should not throw an exception' {
                    $Splat = $script:splatServiceExistsAutomatic.Clone()
                    { Set-TargetResource @Splat `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-StartupType -Exactly 1
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Start-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName Stop-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName Remove-Service -Exactly 0
                    Assert-MockCalled -CommandName New-Service -Exactly 0
                    Assert-MockCalled -CommandName Compare-ServicePath -Exactly 1
                    Assert-MockCalled -CommandName Write-WriteProperty -Exactly 1
                }
            }

            Context 'Service exists and should, should be stopped, all parameters passed and match' {
                # Mocks that should be called
                Mock `
                    -CommandName Test-StartupType `
                    -Verifiable

                Mock `
                    -CommandName Test-ServiceExist `
                    -MockWith { $true } `
                    -Verifiable

                Mock `
                    -CommandName Compare-ServicePath `
                    -MockWith { $true } `
                    -Verifiable

                Mock `
                    -CommandName Write-WriteProperty `
                    -MockWith { $false } `
                    -Verifiable

                Mock `
                    -CommandName Stop-ServiceResource `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName New-Service
                Mock -CommandName Remove-Service
                Mock -CommandName Start-ServiceResource

                It 'Should not throw an exception' {
                    $Splat = $script:splatServiceExistsAutomatic.Clone()
                    $Splat.State = 'Stopped'
                    { Set-TargetResource @Splat `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-StartupType -Exactly 1
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Start-ServiceResource -Exactly 0
                    Assert-MockCalled -CommandName Stop-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName Remove-Service -Exactly 0
                    Assert-MockCalled -CommandName New-Service -Exactly 0
                    Assert-MockCalled -CommandName Compare-ServicePath -Exactly 1
                    Assert-MockCalled -CommandName Write-WriteProperty -Exactly 1
                }
            }

            Context 'Service does not exist but should' {
                # Mocks that should be called
                Mock `
                    -CommandName Test-StartupType `
                    -Verifiable

                Mock `
                    -CommandName Test-ServiceExist `
                    -MockWith { $false } `
                    -Verifiable

                Mock `
                    -CommandName New-Service `
                    -Verifiable

                Mock `
                    -CommandName Write-WriteProperty `
                    -MockWith { $false } `
                    -Verifiable

                Mock `
                    -CommandName Start-ServiceResource `
                    -MockWith { $false } `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName Compare-ServicePath
                Mock -CommandName Remove-Service
                Mock -CommandName Stop-ServiceResource

                It 'Should not throw an exception' {
                    $Splat = $script:splatServiceExistsAutomatic.Clone()
                    { Set-TargetResource @Splat `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-StartupType -Exactly 1
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Start-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName Stop-ServiceResource -Exactly 0
                    Assert-MockCalled -CommandName Remove-Service -Exactly 0
                    Assert-MockCalled -CommandName New-Service -Exactly 1
                    Assert-MockCalled -CommandName Compare-ServicePath -Exactly 0
                    Assert-MockCalled -CommandName Write-WriteProperty -Exactly 1
                }
            }

            Context 'Service does not exist but should, but no path specified' {
                # Mocks that should be called
                Mock `
                    -CommandName Test-StartupType `
                    -Verifiable

                Mock `
                    -CommandName Test-ServiceExist `
                    -MockWith { $false } `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName New-Service
                Mock -CommandName Compare-ServicePath
                Mock -CommandName Start-ServiceResource
                Mock -CommandName Remove-Service
                Mock -CommandName Stop-ServiceResource
                Mock -CommandName Write-WriteProperty

                $errorRecord = Get-InvalidArgumentError `
                    -ErrorId 'ServiceDoesNotExistPathMissingError' `
                    -ErrorMessage ($LocalizedData.ServiceDoesNotExistPathMissingError `
                        -f $script:testServiceName)

                It 'Should not throw an exception' {
                    $Splat = $script:splatServiceExistsAutomatic.Clone()
                    $Splat.Remove('Path')
                    { Set-TargetResource @Splat `
                        -Verbose } | Should Throw $errorRecord
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Test-StartupType -Exactly 1
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Start-ServiceResource -Exactly 0
                    Assert-MockCalled -CommandName Stop-ServiceResource -Exactly 0
                    Assert-MockCalled -CommandName Remove-Service -Exactly 0
                    Assert-MockCalled -CommandName New-Service -Exactly 0
                    Assert-MockCalled -CommandName Compare-ServicePath -Exactly 0
                    Assert-MockCalled -CommandName Write-WriteProperty -Exactly 0
                }
            }
        }

        Describe "$DSCResourceName\Test-StartupType" {
            Context 'Service is stopped, startup is automatic' {
                $errorRecord = Get-InvalidArgumentError `
                    -ErrorId 'CannotStopServiceSetToStartAutomatically' `
                    -ErrorMessage ($LocalizedData.CannotStopServiceSetToStartAutomatically `
                        -f $script:testServiceName)

                It 'Shoult throw CannotStopServiceSetToStartAutomatically exception' {
                    { Test-StartupType `
                        -Name $script:testServiceName `
                        -StartupType 'Automatic' `
                        -State 'Stopped' `
                        -Verbose } | Should Throw $errorRecord
                }
            }

            Context 'Service is stopped, startup is not automatic' {
                It 'Shoult not throw exception' {
                    { Test-StartupType `
                        -Name $script:testServiceName `
                        -StartupType 'Disabled' `
                        -State 'Stopped' `
                        -Verbose } | Should Not Throw
                }
            }

            Context 'Service is running, startup is disabled' {
                $errorRecord = Get-InvalidArgumentError `
                    -ErrorId 'CannotStartAndDisable' `
                    -ErrorMessage ($LocalizedData.CannotStartAndDisable -f $script:testServiceName)

                It 'Shoult throw CannotStartAndDisable exception' {
                    { Test-StartupType `
                        -Name $script:testServiceName `
                        -StartupType 'Disabled' `
                        -State 'Running' `
                        -Verbose } | Should Throw $errorRecord
                }
            }

            Context 'Service is running, startup is not disabled' {
                It 'Shoult not throw exception' {
                    { Test-StartupType `
                        -Name $script:testServiceName `
                        -StartupType 'Manual' `
                        -State 'Running' `
                        -Verbose } | Should Not Throw
                }
            }
        }

        Describe "$DSCResourceName\ConvertTo-StartModeString" {
            Context 'StartupType is Automatic' {
                It 'Should return Automatic' {
                    ConvertTo-StartModeString -StartupType 'Automatic' | Should Be 'Auto'
                }
            }

            Context 'StartupType is Disabled' {
                It 'Should return Disabled' {
                    ConvertTo-StartModeString -StartupType 'Disabled' | Should Be 'Disabled'
                }
            }
        }

        Describe "$DSCResourceName\ConvertTo-StartupTypeString" {
            Context 'StartupType is Auto' {
                It 'Should return Automatic' {
                    ConvertTo-StartupTypeString -StartMode 'Auto' | Should Be 'Automatic'
                }
            }

            Context 'StartupType is Disabled' {
                It 'Should return Disabled' {
                    ConvertTo-StartupTypeString -StartMode 'Disabled' | Should Be 'Disabled'
                }
            }
        }

        Describe "$DSCResourceName\Get-Win32ServiceObject" {
            Context 'Service exists' {
                Mock `
                    -CommandName Get-CimInstance `
                    -MockWith { $script:testWin32ServiceMockRunningLocalSystem } `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:result = Get-Win32ServiceObject `
                        -Name $script:testServiceName `
                        -Verbose } | Should Not Throw
                }

                It 'Should return expected hash table' {
                    $script:result = $script:testWin32ServiceMockRunningLocalSystem
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-CimInstance -Exactly 1
                }
            }

            Context 'Service does not exist' {
                Mock `
                    -CommandName Get-CimInstance `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:result = Get-Win32ServiceObject `
                        -Name $script:testServiceName `
                        -Verbose } | Should Not Throw
                }

                It 'Should return $null' {
                    $script:result | Should BeNullOrEmpty
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-CimInstance -Exactly 1
                }
            }
        }

        Describe "$DSCResourceName\Set-ServiceStartMode" {
            # Dummy Functions
            function Invoke-CimMethod { param ( $InputObject,$MethodName,$Arguments ) }

            Context 'Current StartMode is set to Auto and should be' {
                Mock `
                    -CommandName Invoke-CimMethod

                It 'Should not throw an exception' {
                    { Set-ServiceStartMode `
                        -Win32ServiceObject $script:testWin32ServiceMockRunningLocalSystem `
                        -StartupType $script:testServiceStartupType `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 0
                }
            }

            Context 'Current StartMode needs to be changed, and is changed OK' {
                Mock `
                    -CommandName Invoke-CimMethod `
                    -MockWith { return @{ ReturnValue = 0 } } `
                    -Verifiable

                It 'Should not throw an exception' {
                    { Set-ServiceStartMode `
                        -Win32ServiceObject $script:testWin32ServiceMockRunningLocalSystem `
                        -StartupType 'Manual' `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 1
                }
            }

            Context 'Current StartMode needs to be changed, but an error occured' {
                Mock `
                    -CommandName Invoke-CimMethod `
                    -MockWith { return @{ ReturnValue = 99 } } `
                    -Verifiable

                $innerMessage = ($LocalizedData.MethodFailed `
                    -f 'Change', 'Win32_Service', '99' )
                $errorMessage = ($LocalizedData.ErrorChangingProperty `
                    -f 'StartupType', $innerMessage)
                $errorRecord = Get-InvalidArgumentError `
                    -ErrorId 'ChangeStartupTypeFailed' `
                    -ErrorMessage $errorMessage

                It 'Should throw an exception' {
                    { Set-ServiceStartMode `
                        -Win32ServiceObject $script:testWin32ServiceMockRunningLocalSystem `
                        -StartupType 'Manual' `
                        -Verbose } | Should Throw $errorMessage
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 1
                }
            }
        }

        Describe "$DSCResourceName\Write-WriteProperty" {
            # Dummy Functions
            function Invoke-CimMethod { param ( $InputObject,$MethodName,$Arguments ) }

            # Mocks that should be called
            Mock `
                -CommandName Get-Win32ServiceObject `
                -MockWith { $script:testServiceStartupTypeWin32 } `
                -Verifiable
            Mock `
                -CommandName Get-Service `
                -MockWith { $script:testServiceMockRunning } `
                -Verifiable

            # Mocks that should not be called
            Mock -CommandName Set-Service

            Context 'No parameters passed' {
                It 'Should not throw an exception' {
                    { Write-WriteProperty `
                        -Name $script:testServiceName `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Get-Service -Exactly 1
                    Assert-MockCalled -CommandName Set-Service -Exactly 0
                }
            }

            Context 'Different DisplayName passed, will not trigger restart' {
                # Mocks that should be called
                Mock `
                    -CommandName Set-Service `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:Result = Write-WriteProperty `
                        -Name $script:testServiceName `
                        -DisplayName 'NewDisplayName' `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Get-Service -Exactly 1
                    Assert-MockCalled -CommandName Set-Service -Exactly 1
                }
            }

            Context 'Different Description passed, will not trigger restart' {
                # Mocks that should be called
                Mock `
                    -CommandName Set-Service `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:Result = Write-WriteProperty `
                        -Name $script:testServiceName `
                        -Description 'NewDescription' `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Get-Service -Exactly 1
                    Assert-MockCalled -CommandName Set-Service -Exactly 1
                }
            }

            Context 'Different Dependencies passed and set OK, will not trigger restart' {
                # Mocks that should be called
                Mock `
                    -CommandName Invoke-CimMethod `
                    -MockWith { @{ ReturnValue = 0 } } `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:Result = Write-WriteProperty `
                        -Name $script:testServiceName `
                        -Dependencies 'DepService1','DepService2' `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Get-Service -Exactly 1
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 1
                }
            }

            Context 'Different Dependencies passed and set failed, will not trigger restart' {
                # Mocks that should be called
                Mock `
                    -CommandName Invoke-CimMethod `
                    -MockWith { @{ ReturnValue = 99 } } `
                    -Verifiable

                $innerMessage = ($LocalizedData.MethodFailed `
                    -f 'Change','Win32_Service','99')
                $errorMessage = ($LocalizedData.ErrorChangingProperty `
                    -f 'Dependencies',$innerMessage)
                $errorRecord = Get-InvalidArgumentError `
                    -ErrorId 'ChangeCredentialFailed' `
                    -ErrorMessage $errorMessage

                It 'Should throw an exception' {
                    { $script:Result = Write-WriteProperty `
                        -Name $script:testServiceName `
                        -Dependencies 'DepService1','DepService2' `
                        -Verbose } | Should Throw $errorRecord
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Get-Service -Exactly 1
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 1
                }
            }

            Context 'Path passed, will trigger restart' {
                # Mocks that should be called
                Mock `
                    -CommandName Write-BinaryProperty `
                    -MockWith { $true } `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:Result = Write-WriteProperty `
                        -Name $script:testServiceName `
                        -Path 'c:\NewExecutable.exe' `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Get-Service -Exactly 1
                    Assert-MockCalled -CommandName Write-BinaryProperty -Exactly 1
                }
            }

            Context 'StartupType passed, will not trigger restart' {
                # Mocks that should be called
                Mock `
                    -CommandName Set-ServiceStartMode `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:Result = Write-WriteProperty `
                        -Name $script:testServiceName `
                        -StartupType 'Manual' `
                        -Verbose } | Should Not Throw
                }

                It 'Should return true' {
                    $script:Result | Should Be $false
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Get-Service -Exactly 1
                    Assert-MockCalled -CommandName Set-ServiceStartMode -Exactly 1
                }
            }

            Context 'Credential passed, will not trigger restart' {
                # Mocks that should be called
                Mock `
                    -CommandName Write-CredentialProperty `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:Result = Write-WriteProperty `
                        -Name $script:testServiceName `
                        -Credential $script:testCredential `
                        -Verbose } | Should Not Throw
                }

                It 'Should return true' {
                    $script:Result | Should Be $false
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Get-Service -Exactly 1
                    Assert-MockCalled -CommandName Write-CredentialProperty -Exactly 1
                }
            }

            Context 'BuildinAccount passed, will not trigger restart' {
                # Mocks that should be called
                Mock `
                    -CommandName Write-CredentialProperty `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:Result = Write-WriteProperty `
                        -Name $script:testServiceName `
                        -BuiltInAccount 'LocalSystem' `
                        -Verbose } | Should Not Throw
                }

                It 'Should return true' {
                    $script:Result | Should Be $false
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Get-Service -Exactly 1
                    Assert-MockCalled -CommandName Write-CredentialProperty -Exactly 1
                }
            }

            Context 'DesktopInteract passed, will not trigger restart' {
                # Mocks that should be called
                Mock `
                    -CommandName Write-CredentialProperty `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:Result = Write-WriteProperty `
                        -Name $script:testServiceName `
                        -DesktopInteract $true `
                        -Verbose } | Should Not Throw
                }

                It 'Should return true' {
                    $script:Result | Should Be $false
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-Win32ServiceObject -Exactly 1
                    Assert-MockCalled -CommandName Get-Service -Exactly 1
                    Assert-MockCalled -CommandName Write-CredentialProperty -Exactly 1
                }
            }
        }

        Describe "$DSCResourceName\Write-CredentialProperty" {
            # Dummy Functions
            function Invoke-CimMethod { param ( $InputObject,$MethodName,$Arguments ) }

            Context 'No parameters to be changed passed' {
                # Mocks that should not be called
                Mock -CommandName Get-UserNameAndPassword
                Mock -CommandName Test-UserName
                Mock -CommandName Set-LogOnAsServicePolicy
                Mock -CommandName Invoke-CimMethod

                It 'Should not throw an exception' {
                    { Write-CredentialProperty `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-UserNameAndPassword -Exactly 0
                    Assert-MockCalled -CommandName Test-UserName -Exactly 0
                    Assert-MockCalled -CommandName Set-LogOnAsServicePolicy -Exactly 0
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 0
                }
            }

            Context 'Desktop interact passed but does not need to be changed' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-UserNameAndPassword `
                    -MockWith { $null,$null } `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName Test-UserName
                Mock -CommandName Set-LogOnAsServicePolicy
                Mock -CommandName Invoke-CimMethod

                It 'Should not throw an exception' {
                    { Write-CredentialProperty `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -DesktopInteract $true `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-UserNameAndPassword -Exactly 1
                    Assert-MockCalled -CommandName Test-UserName -Exactly 0
                    Assert-MockCalled -CommandName Set-LogOnAsServicePolicy -Exactly 0
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 0
                }
            }

            Context 'Desktop interact passed and does need to be changed' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-UserNameAndPassword `
                    -MockWith { $null,$null } `
                    -Verifiable

                Mock `
                    -CommandName Invoke-CimMethod `
                    -MockWith { @{ returnValue = 0 } } `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName Test-UserName
                Mock -CommandName Set-LogOnAsServicePolicy

                It 'Should not throw an exception' {
                    { Write-CredentialProperty `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -DesktopInteract $false `
                        -Verbose } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-UserNameAndPassword -Exactly 1
                    Assert-MockCalled -CommandName Test-UserName -Exactly 0
                    Assert-MockCalled -CommandName Set-LogOnAsServicePolicy -Exactly 0
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 1
                }
            }

            Context 'Desktop interact passed and does need to be changed but fails' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-UserNameAndPassword `
                    -MockWith { $null,$null } `
                    -Verifiable

                Mock `
                    -CommandName Invoke-CimMethod `
                    -MockWith { @{ returnValue = 99 } } `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName Test-UserName
                Mock -CommandName Set-LogOnAsServicePolicy

                $innerMessage = ($LocalizedData.MethodFailed `
                    -f 'Change','Win32_Service','99')
                $errorMessage = ($LocalizedData.ErrorChangingProperty `
                    -f 'Credential',$innerMessage)
                $errorRecord = Get-InvalidArgumentError `
                    -ErrorId 'ChangeCredentialFailed' `
                    -ErrorMessage $errorMessage

                It 'Should throw an exception' {
                    { Write-CredentialProperty `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -DesktopInteract $false `
                        -Verbose } | Should Throw $errorRecord
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-UserNameAndPassword -Exactly 1
                    Assert-MockCalled -CommandName Test-UserName -Exactly 0
                    Assert-MockCalled -CommandName Set-LogOnAsServicePolicy -Exactly 0
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 1
                }
            }

            Context 'Both credential and buildinaccount passed' {
                # Mocks that should not be called
                Mock -CommandName Get-UserNameAndPassword
                Mock -CommandName Invoke-CimMethod
                Mock -CommandName Test-UserName
                Mock -CommandName Set-LogOnAsServicePolicy

                $errorRecord = Get-InvalidArgumentError `
                   -ErrorId 'OnlyCredentialOrBuiltInAccount' `
                    -ErrorMessage ($LocalizedData.OnlyOneParameterCanBeSpecified `
                    -f 'Credential','BuiltInAccount')

                It 'Should throw an exception' {
                    { Write-CredentialProperty `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -Credential $script:testCredential `
                        -BuiltInAccount 'LocalSystem' } | Should Throw $errorRecord
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-UserNameAndPassword -Exactly 0
                    Assert-MockCalled -CommandName Test-UserName -Exactly 0
                    Assert-MockCalled -CommandName Set-LogOnAsServicePolicy -Exactly 0
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 0
                }
            }

            Context 'Credential passed but does not need to be changed' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-UserNameAndPassword `
                    -MockWith { $script:testUsername,$script:testPassword } `
                    -Verifiable

                Mock `
                    -CommandName Test-UserName `
                    -MockWith { $true } `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName Set-LogOnAsServicePolicy
                Mock -CommandName Invoke-CimMethod

                It 'Should not throw an exception' {
                    { Write-CredentialProperty `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -Credential $script:testCredential } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-UserNameAndPassword -Exactly 1
                    Assert-MockCalled -CommandName Test-UserName -Exactly 1
                    Assert-MockCalled -CommandName Set-LogOnAsServicePolicy -Exactly 0
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 0
                }
            }

            Context 'Credential and needs to be changed' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-UserNameAndPassword `
                    -MockWith { $script:testUsername,$script:testPassword } `
                    -Verifiable

                Mock `
                    -CommandName Test-UserName `
                    -MockWith { $false } `
                    -Verifiable

                Mock `
                    -CommandName Set-LogOnAsServicePolicy `
                    -Verifiable

                Mock `
                    -CommandName Invoke-CimMethod `
                    -MockWith { @{ returnValue = 0 } } `
                    -Verifiable

                It 'Should not throw an exception' {
                    { Write-CredentialProperty `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -Credential $script:testCredential } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-UserNameAndPassword -Exactly 1
                    Assert-MockCalled -CommandName Test-UserName -Exactly 1
                    Assert-MockCalled -CommandName Set-LogOnAsServicePolicy -Exactly 1
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 1
                }
            }

            Context 'Credential and needs to be changed, but throws exception' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-UserNameAndPassword `
                    -MockWith { $script:testUsername,$script:testPassword } `
                    -Verifiable

                Mock `
                    -CommandName Test-UserName `
                    -MockWith { $false } `
                    -Verifiable

                Mock `
                    -CommandName Set-LogOnAsServicePolicy `
                    -Verifiable

                Mock `
                    -CommandName Invoke-CimMethod `
                    -MockWith { @{ returnValue = 99 } } `
                    -Verifiable

                $innerMessage = ($LocalizedData.MethodFailed `
                    -f 'Change','Win32_Service','99')
                $errorMessage = ($LocalizedData.ErrorChangingProperty `
                    -f 'Credential',$innerMessage)
                $errorRecord = Get-InvalidArgumentError `
                    -ErrorId 'ChangeCredentialFailed' `
                    -ErrorMessage $errorMessage

                It 'Should not throw an exception' {
                    { Write-CredentialProperty `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -Credential $script:testCredential } | Should Throw $errorRecord
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-UserNameAndPassword -Exactly 1
                    Assert-MockCalled -CommandName Test-UserName -Exactly 1
                    Assert-MockCalled -CommandName Set-LogOnAsServicePolicy -Exactly 1
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 1
                }
            }

            Context 'BuiltInAccount passed but does not need to be changed' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-UserNameAndPassword `
                    -MockWith { '.\LocalSystem','' } `
                    -Verifiable

                Mock `
                    -CommandName Test-UserName `
                    -MockWith { $true } `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName Set-LogOnAsServicePolicy
                Mock -CommandName Invoke-CimMethod

                It 'Should not throw an exception' {
                    { Write-CredentialProperty `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -BuiltInAccount 'LocalSystem' } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-UserNameAndPassword -Exactly 1
                    Assert-MockCalled -CommandName Test-UserName -Exactly 1
                    Assert-MockCalled -CommandName Set-LogOnAsServicePolicy -Exactly 0
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 0
                }
            }

            Context 'BuiltInAccount passed and needs to be changed' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-UserNameAndPassword `
                    -MockWith { '.\LocalSystem',$null } `
                    -Verifiable

                Mock `
                    -CommandName Test-UserName `
                    -MockWith { $false } `
                    -Verifiable

                Mock `
                    -CommandName Invoke-CimMethod `
                    -MockWith { @{ returnValue = 0 } } `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName Set-LogOnAsServicePolicy

                It 'Should not throw an exception' {
                    { Write-CredentialProperty `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -BuiltInAccount 'LocalSystem' } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-UserNameAndPassword -Exactly 1
                    Assert-MockCalled -CommandName Test-UserName -Exactly 1
                    Assert-MockCalled -CommandName Set-LogOnAsServicePolicy -Exactly 0
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 1
                }
            }

            Context 'BuiltInAccount passed and needs to be changed, but throws exception' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-UserNameAndPassword `
                    -MockWith { '.\LocalSystem',$null } `
                    -Verifiable

                Mock `
                    -CommandName Test-UserName `
                    -MockWith { $false } `
                    -Verifiable

                Mock `
                    -CommandName Invoke-CimMethod `
                    -MockWith { @{ returnValue = 99 } } `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName Set-LogOnAsServicePolicy

                $innerMessage = ($LocalizedData.MethodFailed `
                    -f 'Change','Win32_Service','99')
                $errorMessage = ($LocalizedData.ErrorChangingProperty `
                    -f 'Credential',$innerMessage)
                $errorRecord = Get-InvalidArgumentError `
                    -ErrorId 'ChangeCredentialFailed' `
                    -ErrorMessage $errorMessage

                It 'Should not throw an exception' {
                    { Write-CredentialProperty `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -BuiltInAccount 'LocalSystem' } | Should Throw $errorRecord
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-UserNameAndPassword -Exactly 1
                    Assert-MockCalled -CommandName Test-UserName -Exactly 1
                    Assert-MockCalled -CommandName Set-LogOnAsServicePolicy -Exactly 0
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 1
                }
            }
        }

        Describe "$DSCResourceName\Write-BinaryProperty" {
            # Dummy Functions
            function Invoke-CimMethod { param ( $InputObject,$MethodName,$Arguments ) }

            Context 'Path is already correct' {
                # Mocks that should not be called
                Mock -CommandName Invoke-CimMethod

                It 'Should not throw an exception' {
                    { $script:result = Write-BinaryProperty `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -Path $script:testServiceExecutablePath } | Should Not Throw
                }

                It 'Should return false' {
                    $script:result = $false
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 0
                }
            }

            Context 'Path needs to be changed and is changed without error' {
                # Mocks that should be called
                Mock `
                    -CommandName Invoke-CimMethod `
                    -MockWith { @{ returnValue = 0 } } `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:result = Write-BinaryProperty `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -Path 'c:\NewServicePath.exe' } | Should Not Throw
                }

                It 'Should return true' {
                    $script:result = $true
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 1
                }
            }

            Context 'Path needs to be changed but an error occurs changing it' {
                # Mocks that should be called
                Mock `
                    -CommandName Invoke-CimMethod `
                    -MockWith { @{ returnValue = 99 } } `
                    -Verifiable

                $innerMessage = ($LocalizedData.MethodFailed `
                    -f 'Change', 'Win32_Service', 99)
                $errorMessage = ($LocalizedData.ErrorChangingProperty `
                    -f 'Binary Path', $innerMessage)
                $errorRecord = Get-InvalidArgumentError `
                    -ErrorId 'ChangeBinaryPathFailed' `
                    -ErrorMessage $errorMessage

                It 'Should not throw an exception' {
                    { $script:result = Write-BinaryProperty `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -Path 'c:\NewServicePath.exe' } | Should Throw $errorRecord
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Invoke-CimMethod -Exactly 1
                }
            }
        }

        Describe "$DSCResourceName\Test-UserName" {
            Context 'Username matches' {
                It 'Should not throw an exception' {
                    { $script:result = Test-Username `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -Username $script:testUsername } | Should Not Throw
                }

                It 'Should return true' {
                    $script:result = $true
                }
            }

            Context 'Username does not match' {
                It 'Should not throw an exception' {
                    { $script:result = Test-Username `
                        -ServiceWmi $script:testWin32ServiceMockRunningLocalSystem `
                        -Username 'mismatch' } | Should Not Throw
                }

                It 'Should return false' {
                    $script:result = $false
                }
            }
        }

        Describe "$DSCResourceName\Get-UserNameAndPassword" {
            Context 'Built-in account provided' {
                $script:result = Get-UserNameAndPassword -BuiltInAccount 'LocalService'

                It 'Should return: NT Authority\LocalService and $null' {
                     $script:result[0] | Should Be 'NT Authority\LocalService'
                     $script:result[1] | Should BeNullOrEmpty
                }
            }

            Context 'Credential provided' {
                $script:result = Get-UserNameAndPassword -Credential $script:testCredential

                It 'Should return the correct username and password' {
                     $script:result[0] | Should Be ".\$script:testUsername"
                     $script:result[1] | Should Be $script:testPassword
                }
            }

            Context 'Neither built-in account or credential provided' {
                $script:result = Get-UserNameAndPassword

                It 'Should return both results as null/empty' {
                     $script:result[0] | Should BeNullOrEmpty
                     $script:result[1] | Should BeNullOrEmpty
                }
            }
        }

        Describe "$DSCResourceName\Remove-Service" {
            # Mocks that should be called
            Mock -CommandName 'sc.exe' -Verifiable
            Mock -CommandName Test-ServiceExist -MockWith { $false } -Verifiable

            Context 'Service is deleted successfully' {
                # Mocks that should not be called
                Mock -CommandName Start-Sleep

                It 'Should not throw exception' {
                    {
                        Remove-Service -Name $script:testServiceName
                    } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName 'sc.exe' -Exactly 1
                    Assert-MockCalled -CommandName Test-ServiceExist -Exactly 1
                    Assert-MockCalled -CommandName Start-Sleep -Exactly 0
                }
            }

            Mock -CommandName Test-ServiceExist -MockWith { $true } -Verifiable

            Context 'Service can not be deleted (will take 5 seconds)' {
                Mock -CommandName Start-Sleep -Verifiable

                $errorRecord = Get-InvalidArgumentError `
                    -ErrorId 'ErrorDeletingService' `
                    -ErrorMessage ($LocalizedData.ErrorDeletingService -f $script:testServiceName)

                It 'Should throw ErrorDeletingService exception' {
                    {
                        Remove-Service -Name $script:testServiceName
                    } | Should Throw $errorRecord
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName 'sc.exe' -Exactly 1
                }
            }
        }

        Describe "$DSCResourceName\Start-ServiceResource" {
            Context 'Service is already running' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-ServiceResource `
                    -MockWith { $script:testServiceMockRunning } `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName New-Object

                It 'Should not throw exception' {
                    {
                        Start-ServiceResource -Name $script:testServiceName -StartUpTimeout 30000
                    } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName New-Object -Exactly 0
                }
            }

            Context 'Service is stopped' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-ServiceResource `
                    -MockWith { $script:testServiceMockStopped } `
                    -Verifiable

                Mock `
                    -CommandName New-Object `
                    -Verifiable

                $global:ServiceStarted = $false

                It 'Should not throw exception' {
                    {
                        Start-ServiceResource -Name $script:testServiceName -StartUpTimeout 30000
                    } | Should Not Throw
                }

                It 'Called start method' {
                    $global:ServiceStarted | Should Be $true
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName New-Object -Exactly 1
                }

                Remove-Variable -Name ServiceStarted -Scope Global
            }
        }

        Describe "$DSCResourceName\Stop-ServiceResource" {
            Context 'Service is already stopped' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-ServiceResource `
                    -MockWith { $script:testServiceMockStopped } `
                    -Verifiable

                # Mocks that should not be called
                Mock -CommandName New-Object

                It 'Should not throw exception' {
                    {
                        Stop-ServiceResource -Name $script:testServiceName -TerminateTimeout 30000
                    } | Should Not Throw
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName New-Object -Exactly 0
                }
            }

            Context 'Service is running' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-ServiceResource `
                    -MockWith { $script:testServiceMockRunning } `
                    -Verifiable

                Mock `
                    -CommandName New-Object `
                    -Verifiable

                $global:ServiceStopped = $false

                It 'Should not throw exception' {
                    {
                        Stop-ServiceResource -Name $script:testServiceName -TerminateTimeout 30000
                    } | Should Not Throw
                }

                It 'Called stop method' {
                    $global:ServiceStopped | Should Be $true
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Get-ServiceResource -Exactly 1
                    Assert-MockCalled -CommandName New-Object -Exactly 1
                }

                Remove-Variable -Name ServiceStopped -Scope Global
            }
        }

        Describe "$DSCResourceName\Resolve-UserName" {
            Context 'Username is NetworkService' {
                It 'Should return NT Authority\NetworkService' {
                    Resolve-UserName -Username 'NetworkService' | Should Be 'NT Authority\NetworkService'
                }
            }

            Context 'Username is LocalService' {
                It 'Should return NT Authority\LocalService' {
                    Resolve-UserName -Username 'LocalService' | Should Be 'NT Authority\LocalService'
                }
            }

            Context 'Username is LocalSystem' {
                It 'Should return .\LocalSystem' {
                    Resolve-UserName -Username 'LocalSystem' | Should Be '.\LocalSystem'
                }
            }

            Context 'Username is Domain\svcAccount' {
                It 'Should return Domain\svcAccount' {
                    Resolve-UserName -Username 'Domain\svcAccount' | Should Be 'Domain\svcAccount'
                }
            }

            Context 'Username is svcAccount' {
                It 'Should return .\svcAccount' {
                    Resolve-UserName -Username 'svcAccount' | Should Be '.\svcAccount'
                }
            }
        }

        Describe "$DSCResourceName\New-InvalidArgumentError" {
            Context 'Throws exception' {
                $errorRecord = Get-InvalidArgumentError `
                    -ErrorId 'ErrorId' `
                    -ErrorMessage 'ErrorMessage'

                It 'Throws exception' {
                    { New-InvalidArgumentError `
                        -ErrorId 'ErrorId' `
                        -ErrorMessage 'ErrorMessage'
                    } | Should Throw $errorRecord
                }
            }
        }

        Describe "$DSCResourceName\Test-ServiceExist" {
            Context 'Service exists' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-Service `
                    -ParameterFilter { $Name -eq $script:testServiceName } `
                    -MockWith { $script:testServiceMockRunning } `
                    -Verifiable

                It 'Should not throw an exception' {
                    {
                        $script:result = Test-ServiceExist -Name $script:testServiceName -Verbose
                    } | Should Not Throw
                }

                It 'Result is true' {
                    $script:Result | Should Be $true
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled `
                        -CommandName Get-Service `
                        -ParameterFilter { $Name -eq $script:testServiceName } `
                        -Exactly 1
                }
            }

            Context 'Service does not exist' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-Service `
                    -ParameterFilter { $Name -eq $script:testServiceName } `
                    -Verifiable

                It 'Should not throw an exception' {
                    {
                        $script:result = Test-ServiceExist -Name $script:testServiceName -Verbose
                    } | Should Not Throw
                }

                It 'Result is false' {
                    $script:Result | Should Be $false
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled `
                        -CommandName Get-Service `
                        -ParameterFilter { $Name -eq $script:testServiceName } `
                        -Exactly 1
                }
            }
        }

        Describe "$DSCResourceName\Compare-ServicePath" {
            Context 'Service exists, path matches' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-CimInstance `
                    -MockWith { $script:testWin32ServiceMockRunningLocalSystem } `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:result = Compare-ServicePath `
                        -Name $script:testServiceName `
                        -Path $script:testServiceExecutablePath `
                        -Verbose } | Should Not Throw
                }

                It 'Result is true' {
                    $script:Result | Should Be $true
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled `
                        -CommandName Get-CimInstance `
                        -Exactly 1
                }
            }

            Context 'Service exists, path does not match' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-CimInstance `
                    -MockWith { $script:testWin32ServiceMockRunningLocalSystem } `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:result = Compare-ServicePath `
                        -Name $script:testServiceName `
                        -Path 'c:\differentpath' `
                        -Verbose } | Should Not Throw
                }

                It 'Result is false' {
                    $script:Result | Should Be $false
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled `
                        -CommandName Get-CimInstance `
                        -Exactly 1
                }
            }

            Context 'Service does not exist' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-CimInstance `
                    -Verifiable

                It 'Should not throw an exception' {
                    { $script:result = Compare-ServicePath `
                        -Name $script:testServiceName `
                        -Path 'c:\differentpath' `
                        -Verbose } | Should Not Throw
                }

                It 'Result is false' {
                    $script:Result | Should Be $false
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled `
                        -CommandName Get-CimInstance `
                        -Exactly 1
                }
            }
        }

        Describe "$DSCResourceName\Get-ServiceResource" {
            Context 'Service exists' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-Service `
                    -ParameterFilter { $Name -eq $script:testServiceName } `
                    -MockWith { $script:testServiceMockRunning } `
                    -Verifiable

                It 'Should not throw an exception' {
                    {
                        $script:service = Get-ServiceResource -Name $script:testServiceName -Verbose
                    } | Should Not Throw
                }

                It 'Should return the correct hashtable properties' {
                    $script:service.Name               | Should Be $script:testServiceName
                    $script:service.ServiceName        | Should Be $script:testServiceName
                    $script:service.DisplayName        | Should Be $script:testServiceDisplayName
                    $script:service.StartType          | Should Be $script:testServiceStartupType
                    $script:service.Status             | Should Be $script:testServiceStatusRunning
                    $script:service.ServicesDependedOn | Should Be $script:testServiceDependsOnHash
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled `
                        -CommandName Get-Service `
                        -ParameterFilter { $Name -eq $script:testServiceName } `
                        -Exactly 1
                }
            }

            Context 'Service does not exist' {
                # Mocks that should be called
                Mock `
                    -CommandName Get-Service `
                    -ParameterFilter { $Name -eq $script:testServiceName } `
                    -Verifiable

                $errorRecord = Get-InvalidArgumentError `
                    -ErrorId 'ServiceNotFound' `
                    -ErrorMessage ($LocalizedData.ServiceNotFound -f $script:testServiceName)

                It 'Should throw a ServiceNotFound exception' {
                    {
                        $script:service = Get-ServiceResource -Name $script:testServiceName -Verbose
                    } | Should Throw $errorRecord
                }

                It 'Should call expected Mocks' {
                    Assert-VerifiableMocks
                    Assert-MockCalled `
                        -CommandName Get-Service `
                        -ParameterFilter { $Name -eq $script:testServiceName } `
                        -Exactly 1
                }
            }
        }
    }
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}
