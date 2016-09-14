#To run these tests, the currently logged on user must have rights to create a user
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

Import-Module "$PSScriptRoot\..\CommonTestHelper.psm1" -Force

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DSCResourceModuleName 'xPSDesiredStateConfiguration' `
    -DSCResourceName 'MSFT_xUserResource' `
    -TestType Unit

try {

    Import-Module "$PSScriptRoot\MSFT_xUserResource.TestHelper.psm1" -Force

    InModuleScope 'MSFT_xUserResource' {
        $testUserName = 'TestUserName12345'
        $testUserPassword = 'StrongOne7.'
        $testUserDescription = 'Some Description'

        $secureTestPassword = ConvertTo-SecureString $testUserPassword -AsPlainText -Force
        $testCredential = New-Object PSCredential ($testUserName, $secureTestPassword)

        New-User -Credential $testCredential -Description $testUserDescription
        
        try {

            Describe 'xUserResource/Get-TargetResource' {

                Context 'Tests on FullSKU' {
                    Mock -CommandName Test-IsNanoServer -MockWith { return $false }

                    It 'Should return the user as Present' {
                        $getTargetResourceResult = Get-TargetResource $testUserName

                        $getTargetResourceResult['UserName']                | Should Be $testUserName
                        $getTargetResourceResult['Ensure']                  | Should Be 'Present'
                        $getTargetResourceResult['Description']             | Should Be $testUserDescription
                        $getTargetResourceResult['PasswordChangeRequired']  | Should Be $null
                    }

                    It 'Should return the user as Absent' {
                        $getTargetResourceResult = Get-TargetResource 'NotAUserName'

                        $getTargetResourceResult['UserName']                | Should Be 'NotAUserName'
                        $getTargetResourceResult['Ensure']                  | Should Be 'Absent'
                    }
                }

                Context 'Tests on Nano Server' {
                    Mock -CommandName Test-IsNanoServer -MockWith { return $true }

                    It 'Should return the user as Present on Nano Server' -Skip {
                        $getTargetResourceResult = Get-TargetResource $testUserName

                        $getTargetResourceResult['UserName']                | Should Be $testUserName
                        $getTargetResourceResult['Ensure']                  | Should Be 'Present'
                        $getTargetResourceResult['Description']             | Should Be $testUserDescription
                        $getTargetResourceResult['PasswordChangeRequired']  | Should Be $null
                    }

                    It 'Should return the user as Absent' {
                        $getTargetResourceResult = Get-TargetResource 'NotAUserName'

                        $getTargetResourceResult['UserName']                | Should Be 'NotAUserName'
                        $getTargetResourceResult['Ensure']                  | Should Be 'Absent'
                    }
                }
            }

            Describe 'xUserResource/Set-TargetResource' {
                Context 'Tests on FullSKU' {
                    Mock -CommandName Test-IsNanoServer -MockWith { return $false }
                    
                    try
                    {
                        $newTestUserName = 'NewTestUserName12345'
                        $newTestUserPassword = 'NewStrongOne123.'
                        $newTestUserDescription = 'Some Description'

                        $newSecureTestPassword = ConvertTo-SecureString $newTestUserPassword -AsPlainText -Force
                        $newTestCredential = New-Object PSCredential ($newTestUserName, $newSecureTestPassword)
                        
                        $newUser = 'newUser1234'

                        New-User -Credential $newTestCredential -Description $newTestUserDescription
                    
                        It 'Should remove the user' {
                        
                            Test-User -UserName $newTestUserName | Should Be $true
                        
                            Set-TargetResource -UserName $newTestUserName -Ensure 'Absent'
                        
                            Test-User -UserName $newTestUserName | Should Be $false
                        
                        }
                    
                        It 'Should add the new user' {
                            $newPassword = 'ThisIsAStrongPassword543!'
                            $newSecurePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                            $newCredential = New-Object PSCredential ($newUser, $newSecurePassword)
                            
                            Set-TargetResource -UserName $newUser -Password $newCredential -Ensure 'Present'
                        
                            Test-User -UserName $newUser | Should Be $true
                        }
                        
                        It 'Should update the user' {
                            $newPassword = 'ThisIsAStrongPassword543!'
                            $newSecurePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                            $newCredential = New-Object PSCredential ($newUser, $newSecurePassword)
                            $newFullName = 'newFullName'
                            $newDescription = 'newDescription'
                            $disabled = $false
                            $passwordNeverExpires = $true
                            $passwordChangeRequired = $false
                            $passwordChangeNotAllowed = $true
                            
                            Set-TargetResource -UserName $newUser `
                                               -Password $newCredential `
                                               -Ensure 'Present' `
                                               -FullName $newFullName `
                                               -Description $newDescription `
                                               -Disabled $disabled `
                                               -PasswordNeverExpires $passwordNeverExpires `
                                               -PasswordChangeRequired $passwordChangeRequired `
                                               -PasswordChangeNotAllowed $passwordChangeNotAllowed
                        
                            Test-User -UserName $newUser | Should Be $true
                            $testTargetResourceResult = 
                                    Test-TargetResource -UserName $newUser `
                                                        -Password $newCredential `
                                                        -Ensure 'Present' `
                                                        -FullName $newFullName `
                                                        -Description $newDescription `
                                                        -Disabled $disabled `
                                                        -PasswordNeverExpires $passwordNeverExpires `
                                                        -PasswordChangeNotAllowed $passwordChangeNotAllowed
                            $testTargetResourceResult | Should Be $true
                            
                            #updating with different values
                            $disabled = $false
                            $passwordNeverExpires = $false
                            $passwordChangeRequired = $true
                            $passwordChangeNotAllowed = $false
                            
                            Set-TargetResource -UserName $newUser `
                                               -Password $newCredential `
                                               -Ensure 'Present' `
                                               -FullName $newFullName `
                                               -Description $newDescription `
                                               -Disabled $disabled `
                                               -PasswordNeverExpires $passwordNeverExpires `
                                               -PasswordChangeRequired $passwordChangeRequired `
                                               -PasswordChangeNotAllowed $passwordChangeNotAllowed
                        
                            Test-User -UserName $newUser | Should Be $true
                            $testTargetResourceResult = 
                                    Test-TargetResource -UserName $newUser `
                                                        -Password $newCredential `
                                                        -Ensure 'Present' `
                                                        -FullName $newFullName `
                                                        -Description $newDescription `
                                                        -Disabled $disabled `
                                                        -PasswordNeverExpires $passwordNeverExpires `
                                                        -PasswordChangeNotAllowed $passwordChangeNotAllowed
                            $testTargetResourceResult | Should Be $true
                        }
                    }
                    finally
                    {
                        Remove-User -UserName $newTestUserName
                        Remove-User -UserName $newUser
                    }
                }

                Context 'Tests on Nano Server' {
                    Mock -CommandName Test-IsNanoServer -MockWith { return $true }
                    Mock -CommandName Test-ValidCredentialsOnNanoServer { return $true }
                    
                    try
                    {
                        $newTestUserName = 'NewTestUserName12345'
                        $newTestUserPassword = 'NewStrongOne123.'
                        $newTestUserDescription = 'Some Description'

                        $newSecureTestPassword = ConvertTo-SecureString $newTestUserPassword -AsPlainText -Force
                        $newTestCredential = New-Object PSCredential ($newTestUserName, $newSecureTestPassword)
                        
                        $newUser = 'newUser1234'

                        New-User -Credential $newTestCredential -Description $newTestUserDescription
                    
                        It 'Should remove the user' {
                        
                            Test-User -UserName $newTestUserName | Should Be $true
                        
                            Set-TargetResource -UserName $newTestUserName -Ensure 'Absent'
                        
                            Test-User -UserName $newTestUserName | Should Be $false
                        
                        }
                    
                        It 'Should add the new user' {
                            $newPassword = 'ThisIsAStrongPassword543!'
                            $newSecurePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                            $newCredential = New-Object PSCredential ($newUser, $newSecurePassword)
                            
                            Set-TargetResource -UserName $newUser -Password $newCredential -Ensure 'Present'
                        
                            Test-User -UserName $newUser | Should Be $true
                        }
                        
                        It 'Should update the user' {
                            $newPassword = 'ThisIsAStrongPassword543!'
                            $newSecurePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                            $newCredential = New-Object PSCredential ($newUser, $newSecurePassword)
                            $newFullName = 'newFullName'
                            $newDescription = 'newDescription'
                            $disabled = $false
                            $passwordNeverExpires = $true
                            $passwordChangeRequired = $false
                            $passwordChangeNotAllowed = $true
                            
                            Set-TargetResource -UserName $newUser `
                                               -Password $newCredential `
                                               -Ensure 'Present' `
                                               -FullName $newFullName `
                                               -Description $newDescription `
                                               -Disabled $disabled `
                                               -PasswordNeverExpires $passwordNeverExpires `
                                               -PasswordChangeRequired $passwordChangeRequired `
                                               -PasswordChangeNotAllowed $passwordChangeNotAllowed
                        
                            Test-User -UserName $newUser | Should Be $true
                            $testTargetResourceResult = 
                                    Test-TargetResource -UserName $newUser `
                                                        -Password $newCredential `
                                                        -Ensure 'Present' `
                                                        -FullName $newFullName `
                                                        -Description $newDescription `
                                                        -Disabled $disabled `
                                                        -PasswordNeverExpires $passwordNeverExpires `
                                                        -PasswordChangeNotAllowed $passwordChangeNotAllowed
                            $testTargetResourceResult | Should Be $true
                            
                            #updating with different values
                            $disabled = $false
                            $passwordNeverExpires = $false
                            $passwordChangeRequired = $true
                            $passwordChangeNotAllowed = $false
                            
                            Set-TargetResource -UserName $newUser `
                                               -Password $newCredential `
                                               -Ensure 'Present' `
                                               -FullName $newFullName `
                                               -Description $newDescription `
                                               -Disabled $disabled `
                                               -PasswordNeverExpires $passwordNeverExpires `
                                               -PasswordChangeRequired $passwordChangeRequired `
                                               -PasswordChangeNotAllowed $passwordChangeNotAllowed
                        
                            Test-User -UserName $newUser | Should Be $true
                            $testTargetResourceResult = 
                                    Test-TargetResource -UserName $newUser `
                                                        -Password $newCredential `
                                                        -Ensure 'Present' `
                                                        -FullName $newFullName `
                                                        -Description $newDescription `
                                                        -Disabled $disabled `
                                                        -PasswordNeverExpires $passwordNeverExpires `
                                                        -PasswordChangeNotAllowed $passwordChangeNotAllowed
                            $testTargetResourceResult | Should Be $true
                        }
                    }
                    finally
                    {
                        Remove-User -UserName $newTestUserName
                        Remove-User -UserName $newUser
                    }
                }
            }

            Describe 'xUserResource/Test-TargetResource' {
                Context 'Tests on FullSKU' {
                    Mock -CommandName Test-IsNanoServer -MockWith { return $false }
                    $absentUserName = 'AbsentUserUserName123456789'
                    
                    It 'Should return true when user Present and correct values' {

                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -Description $testUserDescription `
                                                                        -Password $testCredential `
                                                                        -Disabled $false `
                                                                        -PasswordNeverExpires $false `
                                                                        -PasswordChangeNotAllowed $false
                        $testTargetResourceResult | Should Be $true
                    }
                    
                    It 'Should return true when user Absent and Ensure = Absent' {
                        $testTargetResourceResult = Test-TargetResource -UserName $absentUserName `
                                                                        -Ensure 'Absent'
                        $testTargetResourceResult | Should Be $true
                    }

                    It 'Should return false when user Absent and Ensure = Present' {
                        
                        $testTargetResourceResult = Test-TargetResource -UserName $absentUserName `
                                                                        -Ensure 'Present'
                        $testTargetResourceResult | Should Be $false
                    }
                    
                    It 'Should return false when user Present and Ensure = Absent' {
                        
                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -Ensure 'Absent'
                        $testTargetResourceResult | Should Be $false
                    }
                    
                    It 'Should return false when Password is wrong' {
                        $badPassword = 'WrongPassword'
                        $secureBadPassword = ConvertTo-SecureString $badPassword -AsPlainText -Force
                        $badTestCredential = New-Object PSCredential ($testUserName, $secureBadPassword)
                        
                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -Password $badTestCredential
                        $testTargetResourceResult | Should Be $false
                    }
                    
                    It 'Should return false when user Present and wrong Description' {

                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -Description 'Wrong description'
                        $testTargetResourceResult | Should Be $false
                    }

                    It 'Should return false when FullName is incorrect' {
                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -FullName 'Wrong FullName'
                        $testTargetResourceResult | Should Be $false 
                    }
                    
                    It 'Should return false when Disabled is incorrect' {
                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -Disabled $true
                        $testTargetResourceResult | Should Be $false 
                    }
                    
                    It 'Should return false when PasswordNeverExpires is incorrect' {
                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -PasswordNeverExpires $true
                        $testTargetResourceResult | Should Be $false 
                    }
                    
                    It 'Should return false when PasswordChangeNotAllowed is incorrect' {
                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -PasswordChangeNotAllowed $true
                        $testTargetResourceResult | Should Be $false 
                    }
                }
                
                Context 'Tests on Nano Server' {
                    Mock -CommandName Test-IsNanoServer -MockWith { return $true }
                    
                    $absentUserName = 'AbsentUserUserName123456789'
                    
                    It 'Should return true when user Present and correct values' {
                        Mock -CommandName Test-ValidCredentialsOnNanoServer { return $true }
                        
                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -Description $testUserDescription `
                                                                        -Password $testCredential `
                                                                        -Disabled $false `
                                                                        -PasswordNeverExpires $false `
                                                                        -PasswordChangeNotAllowed $false
                        $testTargetResourceResult | Should Be $true
                    }
                    
                    It 'Should return true when user Absent and Ensure = Absent' {
                        $testTargetResourceResult = Test-TargetResource -UserName $absentUserName `
                                                                        -Ensure 'Absent'
                        $testTargetResourceResult | Should Be $true
                    }

                    It 'Should return false when user Absent and Ensure = Present' {
                        
                        $testTargetResourceResult = Test-TargetResource -UserName $absentUserName `
                                                                        -Ensure 'Present'
                        $testTargetResourceResult | Should Be $false
                    }
                    
                    It 'Should return false when user Present and Ensure = Absent' {
                        
                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -Ensure 'Absent'
                        $testTargetResourceResult | Should Be $false
                    }
                    
                    It 'Should return false when Password is wrong' {
                        Mock -CommandName Test-ValidCredentialsOnNanoServer { return $false }
                        
                        $badPassword = 'WrongPassword'
                        $secureBadPassword = ConvertTo-SecureString $badPassword -AsPlainText -Force
                        $badTestCredential = New-Object PSCredential ($testUserName, $secureBadPassword)
                        
                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -Password $badTestCredential
                        $testTargetResourceResult | Should Be $false
                    }
                    
                    It 'Should return false when user Present and wrong Description' {

                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -Description 'Wrong description'
                        $testTargetResourceResult | Should Be $false
                    }

                    It 'Should return false when FullName is incorrect' {
                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -FullName 'Wrong FullName'
                        $testTargetResourceResult | Should Be $false 
                    }
                    
                    It 'Should return false when Disabled is incorrect' {
                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -Disabled $true
                        $testTargetResourceResult | Should Be $false 
                    }
                    
                    It 'Should return false when PasswordNeverExpires is incorrect' {
                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -PasswordNeverExpires $true
                        $testTargetResourceResult | Should Be $false 
                    }
                    
                    It 'Should return false when PasswordChangeNotAllowed is incorrect' {
                        $testTargetResourceResult = Test-TargetResource -UserName $testUserName `
                                                                        -PasswordChangeNotAllowed $true
                        $testTargetResourceResult | Should Be $false 
                    }
                }
            }
            
            Describe 'xUserResource/Assert-UserNameValid' {
                It 'Should not throw when username contains all valid chars' {
                    { Assert-UserNameValid -UserName 'abc123456!f_t-l098s' } | Should Not Throw
                }
                
                It 'Should throw InvalidArgumentError when username contains only whitespace and dots' {
                    $invalidName = ' . .. .     '
                    $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidArgument
                    $errorId = 'UserNameHasOnlyWhiteSpacesAndDots'
                    $errorMessage = "The name $invalidName cannot be used."
                    $exception = New-Object System.ArgumentException $errorMessage;
                    $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $errorCategory, $null
                    { Assert-UserNameValid -UserName $invalidName } | Should Throw $errorRecord
                }
                
                It 'Should throw InvalidArgumentError when username contains an invalid char' {
                    $invalidName = 'user|name'
                    $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidArgument
                    $errorId = 'UserNameHasInvalidCharachter'
                    $errorMessage = "The name $invalidName cannot be used."
                    $exception = New-Object System.ArgumentException $errorMessage;
                    $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $errorCategory, $null
                    { Assert-UserNameValid -UserName $invalidName } | Should Throw $errorRecord
                }
            }
            
            
        }
        finally
        {
            Remove-User -UserName $testUserName
        }
    }
}
finally
{
    Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
}



