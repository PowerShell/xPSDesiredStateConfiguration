[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
param ()

$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

<#
    Cache the AppVeyor Administrator credential so that we do not reset the password multiple times
    if retrieved the credential is requested multiple times.
#>
$script:appVeyorAdministratorCredential = $null

<#
    String data for unit test names to be used with the generic test functions.
    Maps command names to the appropriate test names to insert when checking that
    the correct mocks are called.
    In the future we will move this data out of the commonTestHelper file and into the
    corresponding test file or its own file. For now, it is much easier to access this
    way rather than passing it around.
#>
data testStrings
{
    ConvertFrom-StringData -StringData @'
Assert-FileHashValid = assert that the file hash is valid
Assert-FileSignatureValid = assert that the file signature is valid
Assert-FileValid = assert that the file is valid
Assert-PathExtensionValid = assert that the specified path extension is valid
Close-Stream = close the stream
Convert-PathToUri = convert the path to a URI
Convert-ProductIdToIdentifyingNumber = convert the product ID to the identifying number
Copy-ResponseStreamToFileStream = copy the response to the outstream
Get-ItemProperty = retrieve {0}
Get-MsiProductCode = retrieve the MSI product code
Get-ProductEntry = retrieve the product entry
Get-ProductEntryInfo = retrieve the product entry info
Get-ProductEntryValue = retrieve the value of the product entry property
Get-ScriptBlock = retrieve the script block
Get-WebRequest = retrieve the WebRequest object
Get-WebRequestResponse = retrieve the web request response
Get-WebRequestResponseStream = retrieve the WebRequest response stream
Invoke-CimMethod = attempt to invoke a cim method to check if reboot is required
Invoke-PInvoke = attempt to {0} the MSI package under the user
Invoke-Process = attempt to {0} the MSI package under the process
New-Item = create a new {0}
New-LogFile = create a new log file
New-Object = create a new {0}
New-PSDrive = create a new PS Drive
Remove-Item = remove {0}
Remove-PSDrive = remove the PS drive
Start-MsiProcess = start the MSI process
Test-Path = test that the path {0} exists
'@
}

<#
    .SYNOPSIS
        Retrieves the name of the test for asserting that the given function is called.

    .PARAMETER IsCalled
        Indicates whether the function should be called or not.

    .PARAMETER Custom
        An optional string to include in the test name to make the name more descriptive.
        Can only be used by commands that have a variable in their string data name.
#>
function Get-TestName
{
    [OutputType([System.String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Command,

        [System.Boolean]
        $IsCalled = $true,

        [System.String]
        $Custom = ''
    )

    $testName = ''

    if (-not [System.String]::IsNullOrEmpty($Custom))
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
        An array of the mocked commands that should be called or not called.
        Each item in the array is a hashtable that contains the name of the command
        being mocked and the number of times it is called (can be 0).
#>
function Invoke-ExpectedMocksAreCalledTest
{
    [CmdletBinding()]
    param
    (
        [System.Collections.Hashtable[]]
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
        Performs generic tests for the given function, including checking that the
        function does not throw and checking that all mocks are called the expected
        number of times.

    .PARAMETER Function
        The function to be called. Must be in format:
        { Param($hashTableOfParamsToPass) Function-Name @hashTableOfParamsToPass }
        For example:
        { Param($testLogPath) New-LogFile $script:testPath }
        or
        { Param($startMsiProcessParameters) Start-MsiProcess @startMsiProcessParameters }

    .PARAMETER FunctionParameters
        The parameters that should be passed to the function for this test. Should match
        what is passed in the Function parameter.

    .PARAMETER MocksCalled
        An array of the mocked commands that should be called for this test.
        Each item in the array is a hashtable that contains the name of the command
        being mocked, the number of times it is called (can be 0) and, optionally,
        an extra custom string to make the test name more descriptive. The custom
        string will only work if the command has a corresponding variable in the
        string data name.

    .PARAMETER ShouldThrow
        Indicates whether the function should throw or not. If this is set to True
        then ErrorMessage and ErrorTestName should also be passed.

    .PARAMETER ErrorMessage
        The error message that should be thrown if the function is supposed to throw.

    .PARAMETER ErrorTestName
        The string that should be used to create the name of the test that checks for
        the correct error being thrown.
#>
function Invoke-GenericUnitTest {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ScriptBlock]
        $Function,

        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $FunctionParameters,

        [System.Collections.Hashtable[]]
        $MocksCalled,

        [System.Boolean]
        $ShouldThrow = $false,

        [System.String]
        $ErrorMessage = '',

        [System.String]
        $ErrorTestName = ''
    )

    if ($ShouldThrow)
    {
        It "Should throw an error for $ErrorTestName" {
            { $null = $($Function.Invoke($FunctionParameters)) } | Should -Throw -ExpectedMessage $ErrorMessage
        }
    }
    else
    {
        It 'Should not throw' {
            { $null = $($Function.Invoke($FunctionParameters)) } | Should -Not -Throw
        }
    }

    Invoke-ExpectedMocksAreCalledTest -MocksCalled $MocksCalled
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
        being mocked, the number of times it is called (can be 0) and, optionally,
        an extra custom string to make the test name more descriptive. The custom
        string will only work if the command has a corresponding variable in the
        string data name.

    .PARAMETER ExpectedReturnValue
        The expected hashtable that Get-TargetResource should return for this test.
#>
function Invoke-GetTargetResourceUnitTest
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $GetTargetResourceParameters,

        [System.Collections.Hashtable[]]
        $MocksCalled,

        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $ExpectedReturnValue
    )

    It 'Should not throw' {
        { $null = Get-TargetResource @GetTargetResourceParameters } | Should -Not -Throw
    }

    Invoke-ExpectedMocksAreCalledTest -MocksCalled $MocksCalled

    $getTargetResourceResult = Get-TargetResource @GetTargetResourceParameters

    It 'Should return a Hashtable' {
        $getTargetResourceResult -is [System.Collections.Hashtable] | Should -Be $true
    }

    It "Should return a Hashtable with $($ExpectedReturnValue.Keys.Count) properties" {
        $getTargetResourceResult.Keys.Count | Should -Be $ExpectedReturnValue.Keys.Count
    }

    foreach ($key in $ExpectedReturnValue.Keys)
    {
        It "Should return a Hashtable with the $key property as $($ExpectedReturnValue.$key)" {
           $getTargetResourceResult.$key | Should -Be $ExpectedReturnValue.$key
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
        an extra custom string to make the test name more descriptive. The custom
        string will only work if the command has a corresponding variable in the
        string data name.

    .PARAMETER ShouldThrow
        Indicates whether Set-TargetResource should throw or not. If this is set to True
        then ErrorMessage and ErrorTestName should also be passed.

    .PARAMETER ErrorMessage
        The error message that should be thrown if Set-TargetResource is supposed to throw.

    .PARAMETER ErrorTestName
        The string that should be used to create the name of the test that checks for
        the correct error being thrown.
#>
function Invoke-SetTargetResourceUnitTest {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $SetTargetResourceParameters,

        [System.Collections.Hashtable[]]
        $MocksCalled,

        [System.Boolean]
        $ShouldThrow = $false,

        [System.String]
        $ErrorMessage = '',

        [System.String]
        $ErrorTestName = ''
    )

    if ($ShouldThrow)
    {
        It "Should throw an error for $ErrorTestName" {
            { $null = Set-TargetResource @SetTargetResourceParameters } | Should -Throw -ExpectedMessage $ErrorMessage
        }
    }
    else
    {
        It 'Should not throw' {
            { $null = Set-TargetResource @SetTargetResourceParameters } | Should -Not -Throw
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
        being mocked, the number of times it is called (can be 0) and, optionally,
        an extra custom string to make the test name more descriptive. The custom
        string will only work if the command has a corresponding variable in the
        string data name.

    .PARAMETER ExpectedReturnValue
        The expected boolean value that should be returned
#>
function Invoke-TestTargetResourceUnitTest
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $TestTargetResourceParameters,

        [System.Collections.Hashtable[]]
        $MocksCalled,

        [Parameter(Mandatory = $true)]
        [System.Boolean]
        $ExpectedReturnValue
    )

    It 'Should not throw' {
        { $null = Test-TargetResource @TestTargetResourceParameters } | Should -Not -Throw
    }

    Invoke-ExpectedMocksAreCalledTest -MocksCalled $MocksCalled

    $testTargetResourceResult = Test-TargetResource @TestTargetResourceParameters

    It "Should return $ExpectedReturnValue" {
        $testTargetResourceResult | Should -Be $ExpectedReturnValue
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
        [System.Collections.Hashtable]
        $GetTargetResourceResult,

        [System.String[]]
        $GetTargetResourceResultProperties
    )

    foreach ($property in $GetTargetResourceResultProperties)
    {
        $GetTargetResourceResult[$property] | Should -Not -Be $null
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
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
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
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [System.Int32]
        $TimeoutSeconds = 5
    )

    $startTime = [System.DateTime]::Now

    $invokeScriptBlockResult = $false
    while (-not $invokeScriptBlockResult -and (([System.DateTime]::Now - $startTime).TotalSeconds -lt $TimeoutSeconds))
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
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path
    )

    if (-not (Test-Path $Path))
    {
        return $false
    }

    try
    {
        Get-Content -Path $Path | Out-Null
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
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $Parameters,

        [System.String[]]
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
        $transcriptContent | Should -Not -Be $null

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
            [System.String]::IsNullOrEmpty($transcriptContent) | Should -Be $true
        }
        else
        {
            foreach ($expectedOutputPiece in $ExpectedOutput)
            {
                $transcriptContent.Contains($expectedOutputPiece) | Should -Be $true
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
            $password = $password + [System.Char] $randomGenerator.Next(45, 126)
        }

        # Change password
        $appVeyorAdministratorUsername = 'appveyor'

        $appVeyorAdministratorUser = [System.DirectoryServices.DirectoryEntry] ("WinNT://$($env:computerName)/$appVeyorAdministratorUsername")

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
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DscResourceModuleName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DscResourceName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Unit', 'Integration')]
        [System.String]
        $TestType
    )

    $moduleRootPath = Split-Path -Path $PSScriptRoot -Parent
    $dscResourceTestsPath = Join-Path -Path $moduleRootPath -ChildPath 'DSCResource.Tests'
    $testHelperFilePath = Join-Path -Path $dscResourceTestsPath -ChildPath 'TestHelper.psm1'

    if (Test-DscResourceTestsNeedsInstallOrUpdate)
    {
        Install-DscResourceTests
    }

    Import-Module -Name $testHelperFilePath

    return Initialize-TestEnvironment `
        -DSCModuleName $DscResourceModuleName `
        -DSCResourceName $DscResourceName `
        -TestType $TestType
}

<#
    .SYNOPSIS
        Tests to see if DSCResource.Tests needs to be downloaded
        or updated.

    .DESCRIPTION
        This function returns true if the DSCResource.Tests
        content needs to be downloaded or updated.

        A magic file in the .Git folder of DSCResource.Tests
        is used to determine if the repository needs to be
        updated.

        If the last write time of the magic file is over 60
        minutes old then this will cause the function to
        return true.

        The magic file is called DSC_LAST_FETCH.
#>
function Test-DscResourceTestsNeedsInstallOrUpdate
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
    )

    $moduleRootPath = Split-Path -Path $PSScriptRoot -Parent
    $dscResourceTestsPath = Join-Path -Path $moduleRootPath -ChildPath 'DSCResource.Tests'

    if (Test-Path -Path $dscResourceTestsPath)
    {
        $magicFilePath = Join-Path -Path $dscResourceTestsPath -ChildPath '.git\DSC_LAST_FETCH'

        if (Test-Path -Path $magicFilePath)
        {
            $magicFileLastWriteTime = (Get-Item -Path $magicFilePath).LastWriteTime
            $timeWhenUpdateRequired = (Get-Date) + [timespan]::FromMinutes(60)

            if ($magicFileLastWriteTime -and $magicFileLastWriteTime -lt $timeWhenUpdateRequired)
            {
                Write-Verbose -Message ('DSCResource.Tests was last updated at {0}. Update not required.' -f $magicFileLastWriteTime) -Verbose
                return $false
            }
            else
            {
                Write-Verbose -Message ('DSCResource.Tests was last updated at {0}. Update is required.' -f $magicFileLastWriteTime) -Verbose
            }
        }
    }

    Write-Verbose -Message 'DSCResource.Tests needs to be updated.' -Verbose
    return $true
}

<#
    .SYNOPSIS
        Installs the DSCResource.Tests content.

    .DESCRIPTION
        This function uses Git to install or update the
        DSCResource.Tests repository.

        It will then create or update the magic file in
        the .git folder in the DSCResource.Tests folder.

        The magic file is called DSC_LAST_FETCH.

        If Git is not installed and the DSCResource.Tests
        folder is not available then an exception will
        be thrown.

        If the DSCResource.Tests folder does exist but
        Git is not installed then a warning will be
        displayed and the repository will not be pulled.
#>
function Install-DscResourceTests
{
    [CmdletBinding()]
    param
    (
    )

    $moduleRootPath = Split-Path -Path $PSScriptRoot -Parent
    $dscResourceTestsPath = Join-Path -Path $moduleRootPath -ChildPath 'DSCResource.Tests'
    $gitInstalled = $null -ne (Get-Command -Name 'git' -ErrorAction 'SilentlyContinue')
    $writeMagicFile = $false

    if (Test-Path -Path $dscResourceTestsPath)
    {
        if ($gitInstalled)
        {
            Push-Location -Path $dscResourceTestsPath
            Write-Verbose -Message 'Updating DSCResource.Tests.' -Verbose
            git pull origin dev --quiet
            $writeMagicFile = $true
            Pop-Location
        }
        else
        {
            Write-Warning -Message 'Git not installed. DSCResource.Tests will not be updated.'
        }
    }
    else
    {
        if (-not $gitInstalled)
        {
            throw 'Git not installed. Can not pull DSCResource.Tests.'
        }

        Push-Location -Path $moduleRootPath
        Write-Verbose -Message 'Cloning DSCResource.Tests.' -Verbose
        git clone 'https://github.com/PowerShell/DscResource.Tests' --quiet
        $writeMagicFile = $true
        Pop-Location
    }

    if ($writeMagicFile)
    {
        # Write the magic file
        $magicFilePath = Join-Path -Path $dscResourceTestsPath -ChildPath '.git\DSC_LAST_FETCH'
        $null = Set-Content -Path $magicFilePath -Value (Get-Date) -Force
    }
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
        [System.Collections.Hashtable]
        $TestEnvironment
    )

    $moduleRootPath = Split-Path -Path $PSScriptRoot -Parent
    $dscResourceTestsPath = Join-Path -Path $moduleRootPath -ChildPath 'DSCResource.Tests'
    $testHelperFilePath = Join-Path -Path $dscResourceTestsPath -ChildPath 'TestHelper.psm1'

    Import-Module -Name $testHelperFilePath

    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}

<#
    .SYNOPSIS
        Returns $true if the the environment variable APPVEYOR is set to $true,
        and the environment variable CONFIGURATION is set to the value passed
        in the parameter Type.

    .PARAMETER Name
        Name of the test script that is called. Defaults to the name of the
        calling script.

    .PARAMETER Type
        Type of tests in the test file. Can be set to Unit or Integration.
#>
function Test-SkipContinuousIntegrationTask
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name = $MyInvocation.PSCommandPath.Split('\')[-1],

        [Parameter(Mandatory = $true)]
        [ValidateSet('Unit', 'Integration')]
        [System.String]
        $Type
    )

    $result = $false

    if ($env:APPVEYOR -eq $true -and $env:CONFIGURATION -ne $Type)
    {
        Write-Verbose -Message ('{1} tests in {0} will be skipped unless $env:CONFIGURATION is set to ''{1}''.' -f $Name, $Type) -Verbose
        $result = $true
    }

    return $result
}

<#
    .SYNOPSIS
        Verifies that the specified Windows Feature exists and is installed
        on the local machine.

    .PARAMETER Name
        The name of the Windows Feature to verify installation of.
#>
function Install-WindowsFeatureAndVerify
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name
    )

    $featureInstalled = $true

    $targetFeature = Get-WindowsFeature -Name $Name -ErrorAction SilentlyContinue

    if ($null -eq $targetFeature)
    {
        Write-Warning -Message "Unable to find Windows Feature '$Name'."
        $featureInstalled = $false
    }
    elseif (!$targetFeature.Installed)
    {
        $installResult = Install-WindowsFeature -Name $Name

        if (!$installResult.Success)
        {
            Write-Error -Message "Failed to install Windows Feature '$Name'."
            $featureInstalled = $false
        }
    }

    return $featureInstalled
}

Export-ModuleMember -Function @(
    'Test-GetTargetResourceResult', `
    'Wait-ScriptBlockReturnTrue', `
    'Test-IsFileLocked', `
    'Test-SetTargetResourceWithWhatIf', `
    'Get-AppVeyorAdministratorCredential', `
    'Enter-DscResourceTestEnvironment', `
    'Exit-DscResourceTestEnvironment', `
    'Invoke-GetTargetResourceUnitTest', `
    'Invoke-SetTargetResourceUnitTest', `
    'Invoke-TestTargetResourceUnitTest', `
    'Invoke-ExpectedMocksAreCalledTest', `
    'Invoke-GenericUnitTest',
    'Test-SkipContinuousIntegrationTask',
    'Install-WindowsFeatureAndVerify'
)
