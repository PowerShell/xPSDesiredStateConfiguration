[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
param ()

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName 'xPSDesiredStateConfiguration' `
    -DSCResourceName 'xGroupSet' `
    -TestType Integration

Describe "xGroupSet Integration Tests" {
    BeforeAll {
        Import-Module -Name (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'MSFT_xGroupResource.TestHelper.psm1')
        Import-Module "$PSScriptRoot\..\CommonTestHelper.psm1" -Force
        Import-Module "$PSScriptRoot\..\..\DSCResources\CommonResourceHelper.psm1" -Force
    }

    It "Create a xGroupSet" {
        $configurationName = "CreateTestGroup"
        $configurationPath = Join-Path -Path (Get-Location) -ChildPath $configurationName

        $testUserName1 = "LocalTestUser1"
        $testUserName2 = "LocalTestUser2"
        $testUserPassword = "StrongOne7."
        $testUserDescription = "Test users for creating an xGroupSet"

        $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force

        $testCredential1 = New-Object PSCredential ($testUserName1, $secureTestPassword)
        $testCredential2 = New-Object PSCredential ($testUserName2, $secureTestPassword)

        New-User -Credential $testCredential1 -Description $testUserDescription
        New-User -Credential $testCredential2 -Description $testUserDescription

        $membersToInclude = @($testUserName1, $testUserName2)
        $groupNames = @("TestGroupName123", "TestGroupName456")

        try
        {
            Configuration $configurationName
            {
                Import-DscResource -ModuleName xPSDesiredStateConfiguration

                xGroupSet GroupSet1
                {
                    GroupName = $groupNames
                    Ensure = "Present"
                    MembersToInclude = $membersToInclude
                }
            }

            & $configurationName -OutputPath $configurationPath

            Start-DscConfiguration -Path  $configurationPath -Wait -Force -Verbose

            if (Test-IsNanoServer)
            {
                foreach ($groupName in $groupNames)
                {
                    $localGroup = Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue
                    $localGroup | Should Not Be $null
                }
            }
            else
            {
                $groupEntries = [ADSI] "WinNT://$env:ComputerName"

                foreach ($groupName in $groupNames)
                {
                    $groupEntry = $groupEntries.Children | Where-Object Path -like "WinNT://*$env:ComputerName/$groupName"
                    $groupEntry | Should Not Be $null
                }
            }
        }
        finally
        {
            Remove-User $testUserName1

            Remove-User $testUserName2

            if (Test-Path $configurationPath)
            {
                Remove-Item -Path $configurationPath -Recurse -Force
            }
        }
    }

    It "Remove a xGroupSet" {
        $configurationName = "CreateTestGroup"
        $configurationPath = Join-Path -Path (Get-Location) -ChildPath $configurationName

        $testUserName1 = "LocalTestUser1"
        $testUserName2 = "LocalTestUser2"
        $testUserPassword = "StrongOne7."
        $testUserDescription = "Test users for removing an xGroupSet"

        $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force

        $testCredential1 = New-Object PSCredential ($testUserName1, $secureTestPassword)
        $testCredential2 = New-Object PSCredential ($testUserName2, $secureTestPassword)

        New-User -Credential $testCredential1 -Description $testUserDescription
        New-User -Credential $testCredential2 -Description $testUserDescription

        $membersToExclude = @($testUserName1, $testUserName2)
        $groupNames = @("TestGroupName123", "TestGroupName456")

        # Create test groups
        foreach($groupName in $groupNames)
        {
            New-Group -GroupName $groupName -Description $testUserDescription
        }

        try
        {
            Configuration $configurationName
            {
                Import-DscResource -ModuleName xPSDesiredStateConfiguration

                xGroupSet GroupSet1
                {
                    GroupName = $groupNames
                    Ensure = "Absent"
                    MembersToExclude = $membersToExclude
                }
            }

            & $configurationName -OutputPath $configurationPath
            Start-DscConfiguration -Path $configurationPath -Wait -Force -Verbose

            if (Test-IsNanoServer)
            {
                foreach ($groupName in $groupNames)
                {
                    $localGroup = Get-LocalGroup -Name $groupName -ErrorAction Ignore
                    $localGroup | Should Be $null
                }
            }
            else
            {
                $groupEntries = [ADSI] "WinNT://$env:ComputerName"
                foreach($groupName in $groupNames)
                {
                    $groupEntry = $groupEntries.Children | Where-Object Path -like "WinNT://*$env:ComputerName/$groupName"
                    $groupEntry | Should Be $null
                }
            }
        }
        finally
        {
            Remove-User $testUserName1

            Remove-User $testUserName2

            if (Test-Path $configurationPath)
            {
                Remove-Item -Path $configurationPath -Recurse -Force
            }
        }
    }
}
