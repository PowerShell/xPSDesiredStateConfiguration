[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
param ()

$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

# Import CommonTestHelper for Enter-DscResourceTestEnvironment, Exit-DscResourceTestEnvironment
$script:testsFolderFilePath = Split-Path $PSScriptRoot -Parent
$script:commonTestHelperFilePath = Join-Path -Path $testsFolderFilePath -ChildPath 'CommonTestHelper.psm1'
Import-Module -Name $commonTestHelperFilePath

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DscResourceModuleName 'xPSDesiredStateConfiguration' `
    -DscResourceName 'xGroupSet' `
    -TestType 'Integration'

try
{
    Describe "xGroupSet Integration Tests" {
        BeforeAll {
            # Import xGroup Test Helper for New-User, Remove-User
            $groupTestHelperFilePath = Join-Path -Path $script:testsFolderFilePath -ChildPath 'MSFT_xGroupResource.TestHelper.psm1'
            Import-Module -Name $groupTestHelperFilePath

            # Import CommonResourceHelper for Test-IsNanoServer
            $moduleRootFilePath = Split-Path -Path $script:testsFolderFilePath -Parent
            $dscResourcesFolderFilePath = Join-Path -Path $moduleRootFilePath -ChildPath 'DscResources'
            $commonResourceHelperFilePath = Join-Path -Path $dscResourcesFolderFilePath -ChildPath 'CommonResourceHelper.psm1'
            Import-Module $commonResourceHelperFilePath
        }

        It 'Should create a set of two empty groups' {

        }

        It 'Should create one group with one member and add the same member to the Administrators group' {

        }

        It 'Should remove two members from a set of three groups' {

        }

        It 'Should remove a set of groups' {

        }

        It "Create two new groups with the same two members" {
            $configurationName = "CreateTestGroup"
            $configurationPath = Join-Path -Path $TestDrive -ChildPath $configurationName

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

                    Node localhost
                    {
                        xGroupSet xGroupSet1
                        {
                            GroupName = $groupNames
                            Ensure = "Present"
                            MembersToInclude = $membersToInclude
                        }
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

                    xGroupSet xGroupSet1
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
}
finally
{
    Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
}
