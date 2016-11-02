Import-Module "$PSScriptRoot\..\..\DSCResource.Tests\TestHelper.psm1" -Force

$initializeTestEnvironmentParams = @{
    DSCModuleName = 'xPSDesiredStateConfiguration'
    DSCResourceName = 'MSFT_xGroupResource'
    TestType = 'Integration'
}
$null = Initialize-TestEnvironment @initializeTestEnvironmentParams

Describe 'xGroup Integration Tests'  {
    BeforeAll {
        Import-Module "$PSScriptRoot\..\Unit\MSFT_xGroupResource.TestHelper.psm1" -Force
        Import-Module "$PSScriptRoot\..\CommonTestHelper.psm1" -Force
        Import-Module "$PSScriptRoot\..\..\DSCResources\CommonResourceHelper.psm1" -Force
    }

    It 'Should create an empty group' {
        $configurationName = 'CreateEmptyGroup'
        $configurationPath = Join-Path -Path (Get-Location) -ChildPath $configurationName

        $resourceName = 'EmptyGroup'
        $groupName = 'Empty'

        try
        {
            Configuration $configurationName
            {
                param ()

                Import-DSCResource -ModuleName 'xPSDesiredStateConfiguration'

                xGroup $resourceName
                {
                    Ensure = 'Present'
                    GroupName = $groupName
                }
            }

            & $configurationName -OutputPath $configurationPath

            Start-DscConfiguration -Path $configurationPath -Wait -Verbose -Force

            if (Test-IsNanoServer)
            {
                $localGroup = Get-LocalGroup -Name $groupName -ErrorAction 'SilentlyContinue'
                $localGroup | Should Not Be $null
            }
            else
            {
                Test-GroupExists -GroupName $groupName | Should Be $true
            }
        }
        finally
        {
            Remove-Group -GroupName $groupName

            if (Test-Path $configurationPath)
            {
                Remove-Item -Path $configurationPath -Recurse -Force
            }
        }
    }

    It 'Should create an Administrators group with the built-in Administrator' {
        $configurationName = 'CreateAdministratorsGroup'
        $configurationPath = Join-Path -Path (Get-Location) -ChildPath $configurationName

        $resourceName = 'AdministratorsGroup'
        $groupName = 'Administrators'
        $builtInAdministratorUsername = 'Administrator'

        try
        {
            Configuration $configurationName
            {
                param ()

                Import-DSCResource -ModuleName 'xPSDesiredStateConfiguration'

                xGroup $resourceName
                {
                    GroupName = $groupName
                    MembersToInclude = $builtInAdministratorUsername
                }
            }

            & $configurationName -OutputPath $configurationPath

            Start-DscConfiguration -Path $configurationPath -Wait -Verbose -Force

            if (Test-IsNanoServer)
            {
                $localGroup = Get-LocalGroup -Name $groupName -ErrorAction 'SilentlyContinue'
                $localGroup | Should Not Be $null
            }
            else
            {
                Test-GroupExists -GroupName $groupName | Should Be $true
            }
        }
        finally
        {
            if (Test-Path $configurationPath)
            {
                Remove-Item -Path $configurationPath -Recurse -Force
            }
        }
    }
}
