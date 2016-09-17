[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

Import-Module "$PSScriptRoot\..\..\DSCResource.Tests\TestHelper.psm1" -Force

$initializeTestEnvironmentParams = @{
    DSCModuleName = 'xPSDesiredStateConfiguration'
    DSCResourceName = 'MSFT_xGroupResource'
    TestType = 'Unit'
}
$null = Initialize-TestEnvironment @initializeTestEnvironmentParams

InModuleScope 'MSFT_xGroupResource' {
    Describe 'xGroup Unit Tests'  {

        BeforeAll {
            Import-Module "$PSScriptRoot\MSFT_xGroupResource.TestHelper.psm1" -Force
            Import-Module "$PSScriptRoot\..\CommonTestHelper.psm1" -Force

            $script:skipTestsWithCredentials = $true
        }

        Context 'Get-TargetResource' {
            It 'Should return hashtable with correct values when group has members' {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription

                    $newGroupParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MemberUserNames = @( $testUserName1, $testUserName2 )
                    }
                    New-Group @newGroupParams

                    $getTargetResourceResult = Get-TargetResource -GroupName $testGroupName

                    $testGetTargetResourceResultParams = @{
                        GetTargetResourceResult = $getTargetResourceResult
                        GetTargetResourceResultProperties =
                            @( 'GroupName', 'Ensure', 'Description', 'Members' )
                    }
                    Test-GetTargetResourceResult @testGetTargetResourceResultParams

                    $getTargetResourceResult['GroupName']       | Should Be $testGroupName
                    $getTargetResourceResult['Ensure']          | Should Be 'Present'
                    $getTargetResourceResult['Description']     | Should Be $testDescription
                    $getTargetResourceResult['Members'].Count   | Should Be 2
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should return hashtable with correct values when group has no members' {
                $testGroupName = 'LocalTestGroup'
                $testDescription = 'Some Description'

                try
                {
                    New-Group -GroupName $testGroupName -Description $testDescription

                    $getTargetResourceResult = Get-TargetResource -GroupName $testGroupName

                    <#
                        NOTE:
                        Testing if the hashtable contains the property Members has been 
                        removed from the invocation of the generic hashtable test function 
                        "Test-GetTargetResourceResult". It would produce a test failure because  
                        the value of the Members property is an empty array.
                        
                        An alternative test has been added to ensure the hashtable contains
                        the Members property.
                    #>
                    $testGetTargetResourceResultParams = @{
                        GetTargetResourceResult = $getTargetResourceResult
                        GetTargetResourceResultProperties = 
                            @( 'GroupName', 'Ensure', 'Description' )
                    }
                    Test-GetTargetResourceResult @testGetTargetResourceResultParams

                    # Alternative test to ensure the hashtable contains the Members property.
                    $getTargetResourceResult.ContainsKey('Members') | Should Be $true

                    $getTargetResourceResult['GroupName']       | Should Be $testGroupName
                    $getTargetResourceResult['Ensure']          | Should Be 'Present'
                    $getTargetResourceResult['Description']     | Should Be $testDescription
                    $getTargetResourceResult['Members'].Count   | Should Be 0
                }
                finally
                {
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should return hashtable with correct values when group is absent' {
                $testGroupName = 'AbsentGroup'

                $getTargetResourceResult =
                    (Get-TargetResource -GroupName $testGroupName) -as [hashtable]

                $testGetTargetResourceResultParams = @{
                    GetTargetResourceResult = $getTargetResourceResult
                    GetTargetResourceResultProperties = @( 'GroupName', 'Ensure' )
                }
                Test-GetTargetResourceResult @testGetTargetResourceResultParams

                $getTargetResourceResult['GroupName']   | Should Be $testGroupName
                $getTargetResourceResult['Ensure']      | Should Be 'Absent'
            }
        }

        Context 'Set-TargetResource' {
            It 'Should create an empty group' {
                $testGroupName = 'LocalTestGroup'

                try
                {
                    $setTargetResourceResult =
                        Set-TargetResource -GroupName $testGroupName -Ensure 'Present'

                    Test-GroupExists -GroupName $testGroupName | Should Be $true

                    $getTargetResourceResult = Get-TargetResource -GroupName $testGroupName

                    $getTargetResourceResult['GroupName']       | Should Be $testGroupName
                    $getTargetResourceResult['Ensure']          | Should Be 'Present'
                    $getTargetResourceResult['Members'].Count   | Should Be 0
                }
                finally
                {
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should create a group with 2 users using Members' {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams  -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription

                    $setTargetResourceParams = @{
                        GroupName = $testGroupName
                        Ensure = 'Present'
                        Members = @( $testUserName1, $testUserName2 )
                        Description = $testDescription
                    }
                    $setTargetResourceResult = Set-TargetResource @setTargetResourceParams

                    Test-GroupExists -GroupName $testGroupName | Should Be $true

                    $getTargetResourceResult = Get-TargetResource -GroupName $testGroupName

                    $getTargetResourceResult['GroupName']       | Should Be $testGroupName
                    $getTargetResourceResult['Ensure']          | Should Be 'Present'
                    $getTargetResourceResult['Description']     | Should Be $testDescription
                    $getTargetResourceResult['Members'].Count   | Should Be 2
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should create a group with 2 users using MembersToInclude' {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription

                    $setTargetResourceParams = @{
                        GroupName = $testGroupName
                        Ensure = 'Present'
                        MembersToInclude = @( $testUserName1, $testUserName2 )
                        Description = $testDescription
                    }
                    $setTargetResourceResult = Set-TargetResource @setTargetResourceParams

                    Test-GroupExists -GroupName $testGroupName | Should Be $true

                    $getTargetResourceResult = Get-TargetResource -GroupName $testGroupName

                    $getTargetResourceResult['GroupName']       | Should Be $testGroupName
                    $getTargetResourceResult['Ensure']          | Should Be 'Present'
                    $getTargetResourceResult['Description']     | Should Be $testDescription
                    $getTargetResourceResult['Members'].Count   | Should Be 2
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should remove a member from a group with MembersToExclude' {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription

                    $newGroupParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MemberUserNames = @( $testUserName1, $testUserName2 )
                    }
                    New-Group @newGroupParams

                    $setTargetResourceParams = @{
                        GroupName = $testGroupName
                        Ensure = 'Present'
                        MembersToExclude = @( $testUserName2 )
                        Description = $testDescription
                    }
                    $setTargetResourceResult = Set-TargetResource @setTargetResourceParams

                    Test-GroupExists -GroupName $testGroupName | Should Be $true

                    $getTargetResourceResult = Get-TargetResource -GroupName $testGroupName

                    $getTargetResourceResult['GroupName']       | Should Be $testGroupName
                    $getTargetResourceResult['Ensure']          | Should Be 'Present'
                    $getTargetResourceResult['Description']     | Should Be $testDescription
                    $getTargetResourceResult['Members'].Count   | Should Be 1
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should not remove an existing group when Ensure is Present' {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription

                    $newGroupParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MemberUserNames = @( $testUserName1, $testUserName2 )
                    }
                    New-Group @newGroupParams

                    $setTargetResourceResult = Set-TargetResource $testGroupName -Ensure 'Present'

                    Test-GroupExists -GroupName $testGroupName | Should Be $true
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should not throw when only one member of the group specified in MembersToInclude' {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription

                    $newGroupParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MemberUserNames = @( $testUserName1, $testUserName2 )
                    }
                    New-Group @newGroupParams

                    {
                        $setTargetResourceParams = @{
                            GroupName = $testGroupName
                            Ensure = 'Present'
                            MembersToInclude = @( $testUserName1 )
                        }
                        Set-TargetResource  @setTargetResourceParams
                    } | Should Not Throw
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should remove an existing group when Ensure is Absent' {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription

                    $newGroupParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MemberUserNames = @( $testUserName1, $testUserName2 )
                    }
                    New-Group @newGroupParams

                    $setTargetResourceResult =
                        Set-TargetResource -GroupName $testGroupName -Ensure 'Absent'

                    Test-GroupExists -GroupName $testGroupName | Should Be $false
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-Group -GroupName $testGroupName
                }
            }

            <#
                Verify that test group can be created with a domain user and credential
                and that creating a group without a credential does not throw any errors
                when we have domain trust set up.
            #>
            $itName = 'Should correctly create a group with a domain user and credential'
            It $itName -Skip:$script:skipTestsWithCredentials {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription

                    $domainUserName = '?'
                    $domainUserPassword = '?'

                    $secureDomainUserPassword =
                        ConvertTo-SecureString $domainUserPassword -AsPlainText -Force
                    $newObjectParams = @{
                        TypeName = 'PSCredential'
                        ArgumentList = @( $domainUserName, $secureDomainUserPassword )
                    }
                    $domainCredential = New-Object @newObjectParams

                    $setTargetResourceParams = @{
                        GroupName = $testGroupName
                        MembersToInclude = @( $testUserName1, $testUserName2, $domainUserName )
                        Credential = $domainCredential
                        Description = $testDescription
                    }
                    Set-TargetResource @setTargetResourceParams

                    $testTargetResourceParams = @{
                        GroupName = $testGroupName
                        MembersToInclude = @( $testUserName1, $testUserName2, $domainUserName )
                        Credential = $domainCredential
                    }
                    Test-TargetResource  @testTargetResourceParams | Should Be $true

                    $getTargetResourceResult =
                        Get-TargetResource -GroupName $testGroupName -Credential $domainCredential
                    $testGetTargetResourceResultParams = @{
                        GetTargetResourceResult = $getTargetResourceResult
                        GetTargetResourceResultProperties =
                            @( 'GroupName', 'Ensure', 'Description', 'Members' )
                    }
                    Test-GetTargetResourceResult @testGetTargetResourceResultParams

                    $getTargetResourceResult['GroupName']       | Should Be $testGroupName
                    $getTargetResourceResult['Ensure']          | Should Be 'Present'
                    $getTargetResourceResult['Description']     | Should Be $testDescription
                    $getTargetResourceResult['Members'].Count   | Should Be 3
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-Group -GroupName $testGroupName
                }
            }

            <#
                Verify that a group can be created with a domain user and credential
                and that a user account from a trusted domain can be resolved and added.

                This test creates a group and adds the following users as domain\username:
                    - a domain local administrator user from a primary domain
                    - a domain user from the domain with a two-way trust

                The credential for the domain local administrator user is used to
                resolve all user accounts.
            #>
            $itName = 'Should create a new group with the trusted domain accounts and credential'
            It $itName -Skip:$script:skipTestsWithCredentials {
                $testGroupName = 'LocalTestGroup'
                $testDescription = 'Some Description'

                $primaryDomainAccount = '?'
                $twoWayTrustDomainAccount = '?'

                $membersToInclude = @( $primaryDomainAccount['DomainUserName'],
                    $twoWayTrustDomainAccount['DomainUserName'] )
                $primaryDomainAccountCredential = $primaryDomainAccount['Credential']

                try
                {
                    $setTargetResourceParams = @{
                        GroupName = $testGroupName
                        MembersToInclude = $membersToInclude
                        Credential = $primaryDomainAccountCredential
                        Description = $testDescription
                    }
                    Set-TargetResource @setTargetResourceParams

                    $testTargetResourceParams = @{
                        GroupName = $testGroupName
                        MembersToInclude = $membersToInclude
                        Credential = $primaryDomainAccountCredential
                    }
                    Test-TargetResource @testTargetResourceParams | Should Be $true

                    $getTargetResourceParams = @{
                        GroupName = $testGroupName
                        Credential = $primaryDomainAccountCredential
                    }
                    $getTargetResourceResult = Get-TargetResource @getTargetResourceParams

                    $testGetTargetResourceResultParams = @{
                        GetTargetResourceResult = $getTargetResourceResult
                        GetTargetResourceResultProperties =
                            @( 'GroupName', 'Ensure', 'Description', 'Members' )
                    }
                    Test-GetTargetResourceResult @testGetTargetResourceResultParams

                    $getTargetResourceResult['GroupName']       | Should Be $testGroupName
                    $getTargetResourceResult['Ensure']          | Should Be 'Present'
                    $getTargetResourceResult['Description']     | Should Be $testDescription
                    $getTargetResourceResult['Members'].Count   | Should Be $membersToInclude.Length
                }
                finally
                {
                    Remove-Group -GroupName $testGroupName
                }
            }

            <#
                Verify that a group can be created with domain user and credential and a user
                account can be added using the user's UPN name.

                This test creates a group and adds the following users using their UPN name:
                    - a domain local administrator user from a primary domain
                    - a domain user from the domain with a two-way trust

                The credential for the domain local administrator user is used to
                resolve all user accounts.
            #>
            $itName =
                'Should create a group with a domain user and credential and add a user by UPN name'
            It $itName -Skip:$script:skipTestsWithCredentials {
                $testGroupName = 'LocalTestGroup'
                $testDescription = 'Some Description'

                $primaryDomainAccount = '?'
                $twoWayTrustDomainAccount = '?'

                $membersToInclude = @( $primaryDomainAccount['UpnName'],
                    $twoWayTrustDomainAccount['UpnName'] )
                $primaryDomainAccountCredential = $primaryDomainAccount['Credential']

                try
                {
                    $setTargetResourceParams = @{
                        GroupName = $testGroupName
                        MembersToInclude = $membersToInclude
                        Credential = $primaryDomainAccountCredential
                        Description = $testDescription
                    }
                    Set-TargetResource @setTargetResourceParams

                    $testTargetResourceParams = @{
                        GroupName = $testGroupName
                        MembersToInclude = $membersToInclude
                        Credential = $primaryDomainAccountCredential
                    }
                    Test-TargetResource @testTargetResourceParams | Should Be $true

                    $getTargetResourceParams = @{
                        GroupName = $testGroupName
                        Credential = $primaryDomainAccountCredential
                    }
                    $getTargetResourceResult = Get-TargetResource @getTargetResourceParams

                    $testGetTargetResourceResultParams = @{
                        GetTargetResourceResult = $getTargetResourceResult
                        GetTargetResourceResultProperties =
                            @( 'GroupName', 'Ensure', 'Description', 'Members' )
                    }
                    Test-GetTargetResourceResult @testGetTargetResourceResultParams

                    $getTargetResourceResult['GroupName']       | Should Be $testGroupName
                    $getTargetResourceResult['Ensure']          | Should Be 'Present'
                    $getTargetResourceResult['Description']     | Should Be $testDescription
                    $getTargetResourceResult['Members'].Count   | Should Be $membersToInclude.Length
                }
                finally
                {
                    Remove-Group -GroupName $testGroupName
                }
            }

            $itName = 'Should not create a group with a credential and an invalid domain user'
            It $itName -Skip:$script:skipTestsWithCredentials {
                $testGroupName = 'LocalTestGroup'
                $testDescription = 'Some Description'

                $primaryDomainAccount = '?'
                $invalidDomainAccountUserName = 'invaliduser@' + $primaryAccount['DomainName']

                $membersToInclude =
                $primaryDomainAccountCredential = $primaryDomainAccount['Credential']

                {
                    $setTargetResourceParams = @{
                        GroupName = $testGroupName
                        MembersToInclude = @( $primaryDomainAccount['UpnName'],
                            $invalidDomainAccountUserName )
                        Credential = $primaryDomainAccountCredential
                        Description = $testDescription
                    }
                    Set-TargetResource @setTargetResourceParams
                } | Should Throw

                Test-GroupExists -GroupName $groupName | Should Be $false
            }

            <#
                Verify that a group can be created with domain user but no credential
                and a user account from a trusted domain can be resolved and added.

                This test creates a group and adds the following users as domain\username:
                    - a domain local administrator user from a primary domain
                    - a domain user from the domain with a two-way trust

                The domain trust is used to resolve all user accounts.
            #>
            $itName = 'Should create a group with a domain user but no credential'
            It $itName -Skip:$script:skipTestsWithCredentials {
                $testGroupName = 'LocalTestGroup'
                $testDescription = 'Some Description'

                $primaryDomainAccount = '?'
                $twoWayTrustDomainAccount = '?'

                $membersToInclude = @( $primaryDomainAccount['DomainUserName'],
                    $twoWayTrustDomainAccount['DomainUserName'] )

                try
                {
                    {
                        $setTargetResourceParams = @{
                            GroupName = $testGroupName
                            MembersToInclude = $membersToInclude
                            Description = $testDescription
                        }
                        Set-TargetResource @setTargetResourceParams
                    } | Should Not Throw

                    $testTargetResourceParams = @{
                        GroupName = $testGroupName
                        MembersToInclude = $membersToInclude
                    }
                    Test-TargetResource @testTargetResourceParams | Should Be $true

                    $getTargetResourceResult = Get-TargetResource -GroupName $testGroupName
                    $testGetTargetResourceResultParams = @{
                        GetTargetResourceResult = $getTargetResourceResult
                        GetTargetResourceResultProperties =
                            @( 'GroupName', 'Ensure', 'Description', 'Members' )
                    }
                    Test-GetTargetResourceResult @testGetTargetResourceResultParams

                    $getTargetResourceResult['GroupName']       | Should Be $testGroupName
                    $getTargetResourceResult['Ensure']          | Should Be 'Present'
                    $getTargetResourceResult['Description']     | Should Be $testDescription
                    $getTargetResourceResult['Members'].Count   | Should Be $membersToInclude.Length
                }
                finally
                {
                    Remove-Group -GroupName $testGroupName
                }
            }

            # Verify that test group cannot be created with an invalid credential
            $itName = 'Should not create a group with an invalid credential'
            It $itName -Skip:$script:skipTestsWithCredentials {
                $testGroupName = 'LocalTestGroup'
                $testDescription = 'Some Description'

                $testUserName1 = 'LocalTestUser1'
                $testUserPassword = 'StrongOne7.'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                    ArgumentList = @( $testUserName1, $secureTestPassword )
                }
                $testCredential1 = New-Object @newObjectParams

                # Domain user with invalid password
                $domainUserName = '?'
                $invalidDomainUserPassword = '?' + 'invalidstring'
                $secureInvalidDomainUserPassword =
                    ConvertTo-SecureString -String $invalidDomainUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'System.Management.Automation.PSCredential'
                    ArgumentList = @($domainUserName, $invalidDomainUserPassword)
                }
                $invalidDomainUserCredential = New-Object @newObjectParams

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription

                    {
                        $setTargetResourceParams = @{
                            GroupName = $testGroupName
                            MembersToInclude = @( $testUserName1, $domainUserName )
                            Credential = $invalidDomainUserCredential
                            Description = $testDescription
                        }
                        Set-TargetResource @setTargetResourceParams
                    } | Should Throw
                }
                finally
                {
                    Remove-Group -GroupName $testGroupName
                    Remove-User -UserName $testUserName1
                }
            }

            <#
                Verify that test group cannot be created with invalid user info
                (cannot resolve user) when using domain trust
            #>
            $itName = 'Should not create a group with an invalid domain user without a credential'
            It $itName -Skip:$script:skipTestsWithCredentials {
                $testGroupName = 'LocalTestGroup'
                $testDescription = 'Some Description'

                $testUserName1 = 'LocalTestUser1'
                $testUserPassword = 'StrongOne7.'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                    ArgumentList = @( $testUserName1, $secureTestPassword )
                }
                $testCredential1 = New-Object @newObjectParams

                # Domain user with invalid username
                $invalidDomainUserName = '?' + 'invalidstring'
                $invalidDomainUserPassword = '?' + 'invalidstring'
                $secureInvalidDomainUserPassword =
                    ConvertTo-SecureString -String $invalidDomainUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'System.Management.Automation.PSCredential'
                    ArgumentList = @( $invalidDomainUserName, $invalidDomainUserPassword )
                }
                $invalidDomainUserCredential = New-Object @newObjectParams

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription

                    {
                        $setTargetResourceParams = @{
                            GroupName = $testGroupName
                            Credential = $invalidDomainUserCredential
                            Description = $testDescription
                            MembersToInclude = @( $testUserName1,
                                $invalidDomainUserName )
                        }
                        Set-TargetResource @setTargetResourceParams
                    } | Should Throw
                }
                finally
                {
                    Remove-Group -GroupName $testGroupName
                    Remove-User -UserName $testUserName1
                }
            }
        }

        Context 'Test-TargetResource' {
            It 'Should return true for existing group with description' {
                $testGroupName = 'LocalTestGroup'
                $testDescription = 'Some Description'

                try
                {
                    New-Group -GroupName $testGroupName -Description $testDescription

                    $testTargetResourceParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                    }
                    Test-TargetResource @testTargetResourceParams | Should Be $true
                }
                finally
                {
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should return false for existing group with the wrong description' {
                $testGroupName = 'LocalTestGroup'
                $testDescription = 'Some Description'

                try
                {
                    New-Group -GroupName $testGroupName -Description $testDescription

                    $testTargetResourceParams = @{
                        GroupName = $testGroupName
                        Description = 'Wrong description'
                    }
                    Test-TargetResource @testTargetResourceParams | Should Be $false
                }
                finally
                {
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should return true for existing group with matching Members' {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription

                    $newGroupParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MemberUserNames = @( $testUserName1, $testUserName2 )
                    }
                    New-Group @newGroupParams

                    $testTargetResourceParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        Members = @( $testUserName1, $testUserName2 )
                    }
                    Test-TargetResource @testTargetResourceParams | Should Be $true
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should return false for existing group with mismatching Members' {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'
                $testUserName3 = 'LocalTestUser3'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )
                $testCredential3 = New-Object @newObjectParams -ArgumentList @( $testUserName3,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription
                    New-User -Credential $testCredential3 -Description $testDescription

                    $newGroupParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MemberUserNames = @( $testUserName1, $testUserName2 )
                    }
                    New-Group @newGroupParams

                    $testTargetResourceParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        Members = @( $testUserName1, $testUserName2, $testUserName3 )
                    }
                    Test-TargetResource @testTargetResourceParams | Should Be $false
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-User -UserName $testUserName3
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should return true for existing group with one matching MemberToInclude' {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription

                    $newGroupParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MemberUserNames = @( $testUserName1, $testUserName2 )
                    }
                    New-Group @newGroupParams

                    $testTargetResourceParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MembersToInclude = @( $testUserName1 )
                    }
                    Test-TargetResource @testTargetResourceParams | Should Be $true
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should return true for existing group with matching MembersToInclude' {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription

                    $newGroupParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MemberUserNames = @( $testUserName1, $testUserName2 )
                    }
                    New-Group @newGroupParams

                    $testTargetResourceParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MembersToInclude = @( $testUserName1, $testUserName2 )
                    }
                    Test-TargetResource @testTargetResourceParams | Should Be $true
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should return false for existing group with mismatching MembersToInclude' {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'
                $testUserName3 = 'LocalTestUser3'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )
                $testCredential3 = New-Object @newObjectParams -ArgumentList @( $testUserName3,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription
                    New-User -Credential $testCredential3 -Description $testDescription

                    $newGroupParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MemberUserNames = @( $testUserName1, $testUserName2 )
                    }
                    New-Group @newGroupParams

                    $testTargetResourceParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MembersToInclude = @( $testUserName1, $testUserName2, $testUserName3 )
                    }
                    Test-TargetResource @testTargetResourceParams | Should Be $false
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-User -UserName $testUserName3
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should return true for existing group without MembersToExclude' {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'
                $testUserName3 = 'LocalTestUser3'
                $testUserName4 = 'LocalTestUser4'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )
                $testCredential3 = New-Object @newObjectParams -ArgumentList @( $testUserName3,
                    $secureTestPassword )
                $testCredential4 = New-Object @newObjectParams -ArgumentList @( $testUserName4,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription
                    New-User -Credential $testCredential3 -Description $testDescription
                    New-User -Credential $testCredential4 -Description $testDescription

                    $newGroupParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MemberUserNames = @( $testUserName1, $testUserName2 )
                    }
                    New-Group @newGroupParams

                    $testTargetResourceParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MembersToExclude = @( $testUserName3, $testUserName4 )
                    }
                    Test-TargetResource @testTargetResourceParams | Should Be $true
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-User -UserName $testUserName3
                    Remove-User -UserName $testUserName4
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should return false for existing group with MembersToExclude' {
                $testUserName1 = 'LocalTestUser1'
                $testUserName2 = 'LocalTestUser2'
                $testUserName3 = 'LocalTestUser3'
                $testUserName4 = 'LocalTestUser4'

                $testDescription = 'Some Description'
                $testUserPassword = 'StrongOne7.'

                $testGroupName = 'LocalTestGroup'

                $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
                $newObjectParams = @{
                    TypeName = 'PSCredential'
                }
                $testCredential1 = New-Object @newObjectParams -ArgumentList @( $testUserName1,
                    $secureTestPassword )
                $testCredential2 = New-Object @newObjectParams -ArgumentList @( $testUserName2,
                    $secureTestPassword )
                $testCredential3 = New-Object @newObjectParams -ArgumentList @( $testUserName3,
                    $secureTestPassword )
                $testCredential4 = New-Object @newObjectParams -ArgumentList @( $testUserName4,
                    $secureTestPassword )

                try
                {
                    New-User -Credential $testCredential1 -Description $testDescription
                    New-User -Credential $testCredential2 -Description $testDescription
                    New-User -Credential $testCredential3 -Description $testDescription
                    New-User -Credential $testCredential4 -Description $testDescription

                    $newGroupParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MemberUserNames = @( $testUserName1, $testUserName2 )
                    }
                    New-Group @newGroupParams

                    $testTargetResourceParams = @{
                        GroupName = $testGroupName
                        Description = $testDescription
                        MembersToExclude = @( $testUserName1, $testUserName3, $testUserName4 )
                    }
                    Test-TargetResource @testTargetResourceParams | Should Be $false
                }
                finally
                {
                    Remove-User -UserName $testUserName1
                    Remove-User -UserName $testUserName2
                    Remove-User -UserName $testUserName3
                    Remove-User -UserName $testUserName4
                    Remove-Group -GroupName $testGroupName
                }
            }

            It 'Should return false for a nonexistent group' {
                $absentGroupName = 'AbsentGroupName'

                $testTargetResourceResult = Test-TargetResource -GroupName $absentGroupName
                $testTargetResourceResult | Should Be $false
            }
        }
    }
}
