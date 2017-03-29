[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

<#
    Cache the AppVeyor Administrator credential so that we do not reset the password multiple times
    if retrieved the credential is requested multiple times.
#>
$script:appVeyorAdministratorCredential = $null

data testStrings
        {
            ConvertFrom-StringData -StringData @'
Convert-ProductIdToIdentifyingNumber = convert the product ID to the identifying number
Get-ProductEntry = retrieve the product entry
Get-ProductEntryInfo = retrieve the product entry info
Test-TargetResource = check to see if the resource is already in the desired state
Assert-PathExtensionValid = assert that the specified path extension is valid
Convert-PathToUri = convert the path to a URI
Test-Path = test that the path at '{0}' exists
Remove-Item = remove '{0}'
New-Item = create a new {0}
New-PSDrive = create a new PS Drive
New-Object = create a new object of type {0}
Assert-FileValid = assert that the file is valid
Get-MsiProductCode = retrieve the MSI product code
Invoke-PInvoke = attempt to install/uninstall the MSI package with PInvoke
Invoke-Process = attempt to install/uninstall the MSI package under the process
Invoke-CimMethod = attempt to invoke a cim method to check if reboot is required
Close-Stream = close the stream
Copy-WebResponseToFileStream = copy the web response to the file stream
Get-ItemProperty = retrieve the registry data
'@
        }

<#
    .SYNOPSIS
        Retrieves the name of the test for asserting that the given function is called.

    .PARAMETER IsCalled
        Indicates whether the function should be called or not.

    .PARAMETER Custom
        An optional string to include in the test name to make the name more descriptive.
#>
function Get-TestName
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Command,

        [Boolean]
        $IsCalled = $true,

        [String]
        $Custom = ''
    )

    $testName = ''

    if (-not [String]::IsNullOrEmpty($Custom))
    {
        $testName = ($testStrings.$Command -f $Custom)
    }
    else
    {
        $testName = $testStrings.$Command
    }

    if ($IsCalled)
    {
        return 'Should ' + $testName
    }
    else
    {
        return 'Should not ' + $testName
    }
}

<#
    .SYNOPSIS
        Tests that each mock in MocksCalled is called the expected number of times.

    .PARAMETER MocksCalled
        An array of the mocked commands that should be called.
        Each item in the array is a hashtable that contains the name of the command
        being mocked and the number of times it is called (can be 0).
#>
function Invoke-ExpectedMocksAreCalledTest
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Hashtable[]]
        $MocksCalled
    )

    foreach ($mock in $MocksCalled)
    {
        $testName = Get-TestName -Command $mock.Command -IsCalled $mock.Times

        if ($mock.Keys -contains 'Custom')
        {
            $testName = Get-TestName -Command $mock.Command -IsCalled $mock.Times -Custom $mock.Custom
        }

        It $testName {
            Assert-MockCalled -CommandName $mock.Command -Exactly $mock.Times -Scope 'Context'
        }
    }
}

<#
    .SYNOPSIS
        Performs generic tests for Get-TargetResource, including checking that the
        function does not throw, checking that all mocks are called the expected
        number of times, and checking that the correct result is returned. If the function
        is expected to throw, then this function should not be used.

    .PARAMETER GetTargetResourceParameters
        The parameters that should be passed to Get-TargetResource for this test.

    .PARAMETER MocksCalled
        An array of the mocked commands that should be called for this test.
        Each item in the array is a hashtable that contains the name of the command
        being mocked and the number of times it is called (can be 0).

    .PARAMETER ExpectedReturnValue
        The expected hashtable that Get-TargetResource should return for this test.
#>
function Invoke-GetTargetResourceTest
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Hashtable]
        $GetTargetResourceParameters,

        [Parameter(Mandatory = $true)]
        [Hashtable[]]
        $MocksCalled,

        [Parameter(Mandatory = $true)]
        [Hashtable]
        $ExpectedReturnValue
    )

    It 'Should not throw' {
        { $null = Get-TargetResource @GetTargetResourceParameters } | Should Not Throw
    }

    Invoke-ExpectedMocksAreCalledTest -MocksCalled $MocksCalled

    $getTargetResourceResult = Get-TargetResource @GetTargetResourceParameters

    It 'Should return a Hashtable' {
        $getTargetResourceResult -is [Hashtable] | Should Be $true
    }

    It "Should return a Hashtable with $($ExpectedReturnValue.Keys.Count) properties" {
        $getTargetResourceResult.Keys.Count | Should Be $ExpectedReturnValue.Keys.Count
    }

    foreach ($key in $ExpectedReturnValue.Keys)
    {
        It "Should return a Hashtable with the $key property as $($ExpectedReturnValue.$key)" {
           $getTargetResourceResult.$key | Should Be $ExpectedReturnValue.$key
        }
    }
}

<#
    .SYNOPSIS
        Performs generic tests for Set-TargetResource, including checking that the
        function does not throw and checking that all mocks are called the expected
        number of times.

    .PARAMETER SetTargetResourceParameters
        The parameters that should be passed to Set-TargetResource for this test.

    .PARAMETER MocksCalled
        An array of the mocked commands that should be called for this test.
        Each item in the array is a hashtable that contains the name of the command
        being mocked, the number of times it is called (can be 0) and, optionally,
        an extra custom string to make the test name more descriptive.

    .PARAMETER ShouldThrow
        Indicates whether the function should throw or not. If this is set to True
        then ErrorMessage and ErrorTestName should also be passed.

    .PARAMETER ErrorMessage
        The error message that should be thrown if the function is supposed to throw.

    .PARAMETER ErrorTestName
        The string that should be used to create the name of the test that checks for
        the correct error being thrown.
#>
function Invoke-SetTargetResourceTest {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Hashtable]
        $SetTargetResourceParameters,

        [Parameter(Mandatory = $true)]
        [Hashtable[]]
        $MocksCalled,

        [Boolean]
        $ShouldThrow = $false,

        [String]
        $ErrorMessage = '',

        [String]
        $ErrorTestName = ''
    )

    if ($ShouldThrow)
    {
        It "Should throw an error for $ErrorTestName" {
            { $null = Set-TargetResource @SetTargetResourceParameters } | Should Throw $ErrorMessage
        }
    }
    else
    {
        It 'Should not throw' {
            { $null = Set-TargetResource @SetTargetResourceParameters } | Should Not Throw
        }
    }

    Invoke-ExpectedMocksAreCalledTest -MocksCalled $MocksCalled
}

<#
    .SYNOPSIS
        Performs generic tests for Test-TargetResource, including checking that the
        function does not throw, checking that all mocks are called the expected
        number of times, and checking that the correct result is returned. If the function
        is expected to throw, then this function should not be used.

    .PARAMETER TestTargetResourceParameters
        The parameters that should be passed to Test-TargetResource for this test.

    .PARAMETER MocksCalled
        An array of the mocked commands that should be called for this test.
        Each item in the array is a hashtable that contains the name of the command
        being mocked and the number of times it is called (can be 0).

    .PARAMETER ExpectedReturnValue
        The expected boolean value that should be returned
#>
function Invoke-TestTargetResourceTest
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Hashtable]
        $TestTargetResourceParameters,

        [Parameter(Mandatory = $true)]
        [Hashtable[]]
        $MocksCalled,

        [Parameter(Mandatory = $true)]
        [Boolean]
        $ExpectedReturnValue
    )

    It 'Should not throw' {
        { $null = Test-TargetResource @TestTargetResourceParameters } | Should Not Throw
    }

    Invoke-ExpectedMocksAreCalledTest -MocksCalled $MocksCalled

    $testTargetResourceResult = Test-TargetResource @TestTargetResourceParameters

    It "Should return $ExpectedReturnValue" {
        $testTargetResourceResult | Should Be $ExpectedReturnValue
    }
}



<#
    .SYNOPSIS
        Tests that the Get-TargetResource method of a DSC Resource is not null, can be converted to a hashtable, and has the correct properties.
        Uses Pester.

    .PARAMETER GetTargetResourceResult
        The result of the Get-TargetResource method.

    .PARAMETER GetTargetResourceResultProperties
        The properties that the result of Get-TargetResource should have.
#>
function Test-GetTargetResourceResult
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Hashtable]
        $GetTargetResourceResult,

        [String[]]
        $GetTargetResourceResultProperties
    )

    foreach ($property in $GetTargetResourceResultProperties)
    {
        $GetTargetResourceResult[$property] | Should Not Be $null
    }
}

<#
    .SYNOPSIS
        Tests if a scope represents the current machine.

    .PARAMETER Scope
        The scope to test.
#>
function Test-IsLocalMachine
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Scope
    )

    if ($scope -eq '.')
    {
        return $true
    }

    if ($scope -eq $env:COMPUTERNAME)
    {
        return $true
    }

    if ($scope -eq 'localhost')
    {
        return $true
    }

    if ($scope.Contains('.'))
    {
        if ($scope -eq '127.0.0.1')
        {
            return $true
        }

        <#
            Determine if we have an ip address that matches an ip address on one of the network adapters.
            NOTE: This is likely overkill; consider removing it.
        #>
        $networkAdapters = @(Get-CimInstance Win32_NetworkAdapterConfiguration)
        foreach ($networkAdapter in $networkAdapters)
        {
            if ($null -ne $networkAdapter.IPAddress)
            {
                foreach ($address in $networkAdapter.IPAddress)
                {
                    if ($address -eq $scope)
                    {
                        return $true
                    }
                }
            }
        }
    }

    return $false
}

<#
    .SYNOPSIS
        Waits a certain amount of time for a script block to return true.
        Return $true if completed successfully in the given amount of time, $false otherwise.

    .PARAMETER ScriptBlock
        The ScriptBlock to wait for.

    .PARAMETER TimeoutSeconds
        The number of seconds to wait for the ScriptBlock to return $true.
        Default value is 5.
#>
function Wait-ScriptBlockReturnTrue
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Int]
        $TimeoutSeconds = 5
    )

    $startTime = [DateTime]::Now

    $invokeScriptBlockResult = $false
    while (-not $invokeScriptBlockResult -and (([DateTime]::Now - $startTime).TotalSeconds -lt $TimeoutSeconds))
    {
        $invokeScriptBlockResult = $ScriptBlock.Invoke()
        Start-Sleep -Seconds 1
    }

    return $invokeScriptBlockResult
}

<#
    .SYNOPSIS
        Tests if a file is currently locked.

    .PARAMETER Path
        The path to the file to test.
#>
function Test-IsFileLocked
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )

    if (-not (Test-Path $Path))
    {
        return $false
    }

    try
    {
        $content = Get-Content -Path $Path
        return $false
    }
    catch
    {
        return $true
    }
}

<#
    .SYNOPSIS
        Tests that calling the Set-TargetResource cmdlet with the WhatIf parameter specified
        produces output that contains all the given expected output.
        Uses Pester.

    .PARAMETER Parameters
        The parameters to pass to Set-TargetResource.
        These parameters do not need to contain the WhatIf parameter, but if they do, this function
        will run Set-TargetResource with WhatIf = $true no matter what is in the Parameters Hashtable.

    .PARAMETER ExpectedOutput
        The output expected to be in the output from running WhatIf with the Set-TargetResource cmdlet.
        If this parameter is empty or null, this cmdlet will check that there was no output from
        Set-TargetResource with WhatIf specified.    
#>
function Test-SetTargetResourceWithWhatIf
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Hashtable]
        $Parameters,
     
        [String[]]
        $ExpectedOutput
    )

    $transcriptPath = Join-Path -Path (Get-Location) -ChildPath 'WhatIfTestTranscript.txt'
    if (Test-Path -Path $transcriptPath)
    {
        Wait-ScriptBlockReturnTrue -ScriptBlock {-not (Test-IsFileLocked -Path $transcriptPath)} -TimeoutSeconds 10
        Remove-Item -Path $transcriptPath -Force
    }

    $Parameters['WhatIf'] = $true

    try
    {
        Wait-ScriptBlockReturnTrue -ScriptBlock {-not (Test-IsFileLocked -Path $transcriptPath)}

        Start-Transcript -Path $transcriptPath
        Set-TargetResource @Parameters
        Stop-Transcript

        Wait-ScriptBlockReturnTrue -ScriptBlock {-not (Test-IsFileLocked -Path $transcriptPath)}

        $transcriptContent = Get-Content -Path $transcriptPath -Raw
        $transcriptContent | Should Not Be $null

        $regexString = '\*+[^\*]*\*+'

        # Removing transcript diagnostic logging at top and bottom of file
        $selectedString = Select-String -InputObject $transcriptContent `
                                        -Pattern $regexString `
                                        -AllMatches

        foreach ($match in $selectedString.Matches)
        {
            $transcriptContent = $transcriptContent.Replace($match.Captures, '')
        }

        $transcriptContent = $transcriptContent.Replace("`r`n", '').Replace("`n", '')

        if ($null -eq $ExpectedOutput -or $ExpectedOutput.Count -eq 0)
        {
            [String]::IsNullOrEmpty($transcriptContent) | Should Be $true
        }
        else
        {
            foreach ($expectedOutputPiece in $ExpectedOutput)
            {
                $transcriptContent.Contains($expectedOutputPiece) | Should Be $true
            }
        }
    }
    finally
    {
        if (Test-Path -Path $transcriptPath)
        {
            Wait-ScriptBlockReturnTrue -ScriptBlock {-not (Test-IsFileLocked -Path $transcriptPath)} `
                                       -TimeoutSeconds 10
            Remove-Item -Path $transcriptPath -Force
        }
    }
}

<#
    .SYNOPSIS
        Retrieves the administrator credential on an AppVeyor machine.
        The password will be reset so that we know what the password is.

    .NOTES
        The AppVeyor credential will be cached after the first call to this function so that the
        password is not reset if this function is called again.
#>
function Get-AppVeyorAdministratorCredential
{
    [OutputType([System.Management.Automation.PSCredential])]
    [CmdletBinding()]
    param ()

    if ($null -eq $script:appVeyorAdministratorCredential)
    {
        $password = ''

        $randomGenerator = New-Object -TypeName 'System.Random'

        $passwordLength = Get-Random -Minimum 15 -Maximum 126

        while ($password.Length -lt $passwordLength)
        {
            $password = $password + [Char]$randomGenerator.Next(45, 126)
        }

        # Change password
        $appVeyorAdministratorUsername = 'appveyor'

        $appVeyorAdministratorUser = [ADSI]("WinNT://$($env:computerName)/$appVeyorAdministratorUsername")

        $null = $appVeyorAdministratorUser.SetPassword($password)
        [Microsoft.Win32.Registry]::SetValue('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 'DefaultPassword', $password)

        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force

        $script:appVeyorAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @( "$($env:computerName)\$appVeyorAdministratorUsername", $securePassword )
    }

    return $script:appVeyorAdministratorCredential
}

<#
    .SYNOPSIS
        Enters a DSC Resource test environment.

    .PARAMETER DscResourceModuleName
        The name of the module that contains the DSC Resource to test.

    .PARAMETER DscResourceName
        The name of the DSC resource to test.

    .PARAMETER TestType
        Specifies whether the test environment will run a Unit test or an Integration test.
#>
function Enter-DscResourceTestEnvironment
{
    [OutputType([Hashtable])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DscResourceModuleName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DscResourceName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Unit', 'Integration')]
        [String]
        $TestType
    )

    $moduleRootPath = Split-Path -Path $PSScriptRoot -Parent
    $dscResourceTestsPath = Join-Path -Path $moduleRootPath -ChildPath 'DSCResource.Tests'
    $testHelperFilePath = Join-Path -Path $dscResourceTestsPath -ChildPath 'TestHelper.psm1'

    if (-not (Test-Path -Path $dscResourceTestsPath))
    {
        Push-Location $moduleRootPath
        git clone 'https://github.com/PowerShell/DscResource.Tests' --quiet
        Pop-Location
    }
    else
    {
        $gitInstalled = $null -ne (Get-Command -Name 'git' -ErrorAction 'SilentlyContinue')

        if ($gitInstalled)
        {
            Push-Location $dscResourceTestsPath
            git pull origin dev --quiet
            Pop-Location
        }
        else
        {
            Write-Verbose -Message 'Git not installed. Leaving current DSCResource.Tests as is.'
        }
    }

    Import-Module -Name $testHelperFilePath

    return Initialize-TestEnvironment `
        -DSCModuleName $DscResourceModuleName `
        -DSCResourceName $DscResourceName `
        -TestType $TestType
}

<#
    .SYNOPSIS
        Exits the specified DSC Resource test environment.

    .PARAMETER TestEnvironment
        The test environment to exit.
#>
function Exit-DscResourceTestEnvironment
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $TestEnvironment
    )

    $moduleRootPath = Split-Path -Path $PSScriptRoot -Parent
    $dscResourceTestsPath = Join-Path -Path $moduleRootPath -ChildPath 'DSCResource.Tests'
    $testHelperFilePath = Join-Path -Path $dscResourceTestsPath -ChildPath 'TestHelper.psm1'

    Import-Module -Name $testHelperFilePath

    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}

Export-ModuleMember -Function @(
    'Test-GetTargetResourceResult', `
    'Wait-ScriptBlockReturnTrue', `
    'Test-IsFileLocked', `
    'Test-SetTargetResourceWithWhatIf', `
    'Get-AppVeyorAdministratorCredential', `
    'Enter-DscResourceTestEnvironment', `
    'Exit-DscResourceTestEnvironment', `
    'Invoke-GetTargetResourceTest', `
    'Invoke-SetTargetResourceTest', `
    'Invoke-TestTargetResourceTest'
)
