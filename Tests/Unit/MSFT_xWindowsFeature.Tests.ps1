# These tests use a mock server module. They will fail on an actual server.
# All tests that require a credential will be skipped

Import-Module -Name (Join-Path -Path (Split-Path $PSScriptRoot -Parent) `
                               -ChildPath 'CommonTestHelper.psm1') `
                               -Force

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DSCResourceModuleName 'xPSDesiredStateConfiguration' `
    -DSCResourceName 'MSFT_xWindowsFeature' `
    -TestType Unit

try {
    InModuleScope 'MSFT_xWindowsFeature' {
        Describe 'xWindowsFeature Unit Tests' {
            Mock -CommandName ValidatePrerequisites -MockWith {}

            BeforeAll {
                Import-Module -Name (Join-Path -Path $PSScriptRoot `
                                               -ChildPath 'MSFT_xWindowsFeature.TestHelper.psm1') `
                                               -Force
                Import-Module -Name (Join-Path -Path $PSScriptRoot `
                                               -ChildPath '\MockServerManager') `
                                               -Force

                $script:getTargetResourceResultProperties = @('Name', 'DisplayName', 'Ensure', 'IncludeAllSubFeature')

                $script:testWindowsFeatureName = 'Test1'
                $script:skipCredentialTests = $true

                Remove-WindowsFeature $script:testWindowsFeatureName -ErrorAction Ignore
            }

            AfterEach {
                Remove-WindowsFeature $script:testWindowsFeatureName -ErrorAction Ignore
            }

            It 'Get-TargetResource without credential' {
                $getTargetResourceResult = Get-TargetResource -Name $script:testWindowsFeatureName
                Test-GetTargetResourceResult -GetTargetResourceResult $getTargetResourceResult `
                                             -GetTargetResourceResultProperties $script:getTargetResourceResultProperties
            }

            It 'Get-TargetResource with credential' -Skip:($script:skipCredentialTests) {
                $credential = $null

                $getTargetResourceResult = Get-TargetResource -Name $script:testWindowsFeatureName -Credential $credential
                Test-GetTargetResourceResult -GetTargetResourceResult $getTargetResourceResult `
                                             -GetTargetResourceResultProperties $script:getTargetResourceResultProperties
            }

            It 'Get-TargetResource subfeatures installed' {
                Add-WindowsFeature -Name $script:testWindowsFeatureName -IncludeAllSubFeature

                $getTargetResourceResult = Get-TargetResource $script:testWindowsFeatureName
                Test-GetTargetResourceResult -GetTargetResourceResult $getTargetResourceResult -GetTargetResourceResultProperties $script:getTargetResourceResultProperties

                $getTargetResourceResult['IncludeAllSubFeature'] | Should Be $true
            }

            It 'Get-TargetResource subfeatures not installed' {
                Add-WindowsFeature -Name $script:testWindowsFeatureName

                $getTargetResourceResult = Get-TargetResource $script:testWindowsFeatureName
                Test-GetTargetResourceResult -GetTargetResourceResult $getTargetResourceResult -GetTargetResourceResultProperties $script:getTargetResourceResultProperties

                $getTargetResourceResult['IncludeAllSubFeature'] | Should Be $false
            }

            It 'Set-TargetResource without credential and ensure present' {
                $ensureValue = 'Present'

                Set-TargetResource -Name $script:testWindowsFeatureName -Ensure $ensureValue

                $windowsFeature = Get-WindowsFeature -Name $script:testWindowsFeatureName

                $windowsFeature.Installed | Should Be $true
            }

            It 'Set-TargetResource with credential and ensure present' -Skip:($script:skipCredentialTests) {
                $ensureValue = 'Present'
                $credential = $null
            
                Set-TargetResource -Name $script:testWindowsFeatureName -Ensure $ensureValue -Credential $credential
         
                $windowsFeature = Get-WindowsFeature -Name $script:testWindowsFeatureName

                $windowsFeature.Installed | Should Be $true
            }

            It 'Set-TargetResource without credential and ensure absent' {
                $ensureValue = 'Absent'

                Set-TargetResource -Name $script:testWindowsFeatureName -Ensure $ensureValue

                $windowsFeature = Get-WindowsFeature -Name $script:testWindowsFeatureName

                $windowsFeature.Installed | Should Be $false
            }

            It 'Set-TargetResource with credential and ensure absent' -Skip:($script:skipCredentialTests) {
                $ensureValue = 'Absent'
                $credential = $null

                Set-TargetResource -Name $script:testWindowsFeatureName -Ensure $ensureValue -IncludeAllSubFeature $true -Credential $credential

                $windowsFeature = Get-WindowsFeature -Name $script:testWindowsFeatureName

                $windowsFeature.Installed | Should Be $false
            }

            It 'Set-TargetResource with default ensure value' {
                Set-TargetResource -Name $script:testWindowsFeatureName

                $windowsFeature = Get-WindowsFeature -Name $script:testWindowsFeatureName

                $windowsFeature.Installed | Should Be $true
            }

            It 'Set-TargetResource without credential and ensure present and subfeatures installed' {
                $ensureValue = 'Present'

                Set-TargetResource -Name $script:testWindowsFeatureName -Ensure $ensureValue -IncludeAllSubFeature $true
         
                $windowsFeature = Get-WindowsFeature -Name $script:testWindowsFeatureName

                $windowsFeature.Installed  | Should Be $true

                foreach ($subfeatureName in $windowsFeature.Subfeatures)
                {
                    $subfeature = Get-WindowsFeature -Name $subfeatureName
                    $subfeature.Installed | Should Be $true
                }
            }

            It 'Set-TargetResource without credential and ensure absent and subfeatures not installed' {
                $ensureValue = 'Absent'

                Set-TargetResource -Name $script:testWindowsFeatureName -Ensure $ensureValue
         
                $windowsFeature = Get-WindowsFeature -Name $script:testWindowsFeatureName

                $windowsFeature.Installed | Should Be $false

                foreach ($subfeatureName in $windowsFeature.Subfeatures)
                {
                    $subfeature = Get-WindowsFeature -Name $subfeatureName
                    $subfeature.Installed | Should Be $false
                }
            }

            It 'Set-TargetResource with credential and ensure present and subfeatures installed' -Skip:($script:skipCredentialTests) {
                $ensureValue = 'Present'
                $credential = $null

                Set-TargetResource -Name $script:testWindowsFeatureName -Ensure $ensureValue -Credential $credential -IncludeAllSubFeature $true
         
                $windowsFeature = Get-WindowsFeature -Name $script:testWindowsFeatureName

                $windowsFeature.Installed | Should Be $true

                foreach ($subfeatureName in $windowsFeature.Subfeatures)
                {
                    $subfeature = Get-WindowsFeature -Name $subfeatureName
                    $subfeature.Installed | Should Be $true
                }
            }

            It 'Set-TargetResource with credential and ensure absent and subfeatures not installed' -Skip:($script:skipCredentialTests) { 
                $ensureValue = 'Absent'
                $credential = $null

                Set-TargetResource -Name $script:testWindowsFeatureName -Ensure $ensureValue -Credential $credential -IncludeAllSubFeature $true
         
                $windowsFeature = Get-WindowsFeature -Name $script:testWindowsFeatureName

                $windowsFeature.Installed | Should Be $false

                foreach ($subfeatureName in $windowsFeature.Subfeatures)
                {
                    $subfeature = Get-WindowsFeature -Name $subfeatureName
                    $subfeature.Installed | Should Be $false
                }
            }

            It 'Test-TargetResource ensure present and feature installed and subfeatures installed' {
                Add-WindowsFeature $script:testWindowsFeatureName -IncludeAllSubFeature

                $testTargetResourceResult = Test-TargetResource -Name $script:testWindowsFeatureName -Ensure 'Present' -IncludeAllSubFeature $true

                $testTargetResourceResult | Should Be $true
            }

            It 'Test-TargetResource ensure present and feature installed and subfeatures not installed' {
                Add-WindowsFeature $script:testWindowsFeatureName
            
                $testTargetResourceResult = Test-TargetResource -Name $script:testWindowsFeatureName -Ensure 'Present'
            
                $testTargetResourceResult | Should Be $true
            }

            It 'Test-TargetResource ensure absent and feature installed' {
                Add-WindowsFeature $script:testWindowsFeatureName

                $testTargetResourceResult = Test-TargetResource -Name $script:testWindowsFeatureName -Ensure 'Absent'

                $testTargetResourceResult | Should Be $false
            }
        }
    }
}
finally
{
    Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
}
