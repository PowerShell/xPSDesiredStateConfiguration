data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData @'
FileNotFound = File not found in the environment path.
AbsolutePathOrFileName = Absolute path or file name expected.
InvalidArgument = Invalid argument: '{0}' with value: '{1}'.
InvalidArgumentAndMessage = {0} {1}
ProcessStarted = Process matching path '{0}' started
ProcessesStopped = Proceses matching path '{0}' with Ids '({1})' stopped.
ProcessAlreadyStarted = Process matching path '{0}' found running and no action required.
ProcessAlreadyStopped = Process matching path '{0}' not found running and no action required.
ErrorStopping = Failure stopping processes matching path '{0}' with IDs '({1})'. Message: {2}.
ErrorStarting = Failure starting process matching path '{0}'. Message: {1}.
StartingProcessWhatif = Start-Process
StoppingProcessWhatIf = Stop-Process
ProcessNotFound = Process matching path '{0}' not found
PathShouldBeAbsolute = The path should be absolute
PathShouldExist = The path should exist
ParameterShouldNotBeSpecified = Parameter {0} should not be specified.
FailureWaitingForProcessesToStart = Failed to wait for processes to start
FailureWaitingForProcessesToStop = Failed to wait for processes to stop
ErrorParametersNotSupportedWithCredential = Can't specify StandardOutputPath, StandardInputPath or WorkingDirectory when trying to run a process under a user context.
VerboseInProcessHandle = In process handle {0}
ErrorRunAsCredentialParameterNotSupported = The PsDscRunAsCredential parameter is not supported by the Process resource. To start the process with user '{0}', add the Credential parameter.
ErrorCredentialParameterNotSupportedWithRunAsCredential = The PsDscRunAsCredential parameter is not supported by the Process resource, and cannot be used with the Credential parameter. To start the process with user '{0}', use only the Credential parameter, not the PsDscRunAsCredential parameter.
GetTargetResourceStartMessage = Begin executing Get functionality for the process {0}.
GetTargetResourceEndMessage = End executing Get functionality for the process {0}.
SetTargetResourceStartMessage = Begin executing Set functionality for the process {0}.
SetTargetResourceEndMessage = End executing Set functionality for the process {0}.
TestTargetResourceStartMessage = Begin executing Test functionality for the process {0}.
TestTargetResourceEndMessage = End executing Test functionality for the process {0}.
'@
}

# Commented out until more languages are supported
# Import-LocalizedData  LocalizedData -filename MSFT_xProcessResource.strings.psd1

Import-Module "$PSScriptRoot\..\CommonResourceHelper.psm1"

<#
    .SYNOPSIS
        Tests if the current user is from the local system.
#>
function Test-IsRunFromLocalSystemUser
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param ()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity

    return $principal.Identity.IsSystem
}

<#
    .SYNOPSIS
        Splits a credential into a username and domain wihtout calling GetNetworkCredential.
        Calls to GetNetworkCredential expose the password as plain text in memory.

    .PARAMETER Credential
        The credential to pull the username and domain out of.

    .NOTES
        Supported formats: DOMAIN\username, username@domain
#>
function Split-Credential
{
    [OutputType([Hashtable])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    $wrongFormat = $false

    if ($Credential.UserName.Contains('\'))
    {
        $credentialSegments = $Credential.UserName.Split('\')

        if ($credentialSegments.Length -gt 2)
        {
            # i.e. domain\user\foo
            $wrongFormat = $true
        }
        else
        {
            $domain = $credentialSegments[0]
            $userName = $credentialSegments[1]
        }
    }
    elseif ($Credential.UserName.Contains('@'))
    {
        $credentialSegments = $Credential.UserName.Split('@')

        if ($credentialSegments.Length -gt 2)
        {
            # i.e. user@domain@foo
            $wrongFormat = $true
        }
        else
        {
            $UserName = $credentialSegments[0]
            $Domain = $credentialSegments[1]
        }
    }
    else
    {
        # support for default domain (localhost)
        $domain = $env:computerName
        $userName = $Credential.UserName
    }

    if ($wrongFormat)
    {
        $message = $LocalizedData.ErrorInvalidUserName -f $Credential.UserName

        Write-Verbose -Message $message

        New-InvalidArgumentException -ArgumentName 'Credential' -Message $message
    }

    return @{
        Domain = $domain
        UserName = $userName
    }
}

<#
    .SYNOPSIS
        Gets the state of the managed process.

    .PARAMETER Path
        The path to the process executable. If this is the file name of the executable
        (not the fully qualified path), the DSC resource will search the environment Path variable
        ($env:Path) to find the executable file. If the value of this property is a fully qualified
        path, DSC will not use the Path environment variable to find the file, and will throw an
        error if the path does not exist. Relative paths are not allowed.

    .PARAMETER Arguments
        Indicates a string of arguments to pass to the process as-is. If you need to pass several
        arguments, put them all in this string.

    .PARAMETER Credential
        Indicates the credentials for starting the process.
#>
function Get-TargetResource
{
    [OutputType([Hashtable])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]
        $Arguments,

        [ValidateNotNullOrEmpty()]
        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    Write-Verbose ($LocalizedData.GetTargetResourceStartMessage -f $Path)

    $Path = Expand-Path -Path $Path

    $getWin32ProcessArguments = @{
        Path = $Path
        Arguments = $Arguments
    }

    if ($null -ne $Credential)
    {
        $getWin32ProcessArguments['Credential'] = $Credential
    }

    $win32Processes = @( Get-Win32Process @getWin32ProcessArguments )

    if ($win32Processes.Count -eq 0)
    {
        return @{
            Path = $Path
            Arguments = $Arguments
            Ensure ='Absent'
        }
    }

    foreach ($win32Process in $win32Processes)
    {
        $getProcessResult = Get-Process -ID $win32Process.ProcessId -ErrorAction 'Ignore'

        return @{
            Path = $win32Process.Path
            Arguments = (Get-ArgumentsFromCommandLineInput -CommandLineInput $win32Process.CommandLine)
            PagedMemorySize = $getProcessResult.PagedMemorySize64
            NonPagedMemorySize = $getProcessResult.NonpagedSystemMemorySize64
            VirtualMemorySize = $getProcessResult.VirtualMemorySize64
            HandleCount = $getProcessResult.HandleCount
            Ensure = 'Present'
            ProcessId = $win32Process.ProcessId
        }
    }

    Write-Verbose ($LocalizedData.GetTargetResourceEndMessage -f $Path)
}

<#
    .SYNOPSIS
        Ensures the managed process executable is Present or Absent.

    .PARAMETER Path
        The path to the process executable. If this is the file name of the executable
        (not the fully qualified path), the DSC resource will search the environment Path variable
        ($env:Path) to find the executable file. If the value of this property is a fully qualified
        path, DSC will not use the Path environment variable to find the file, and will throw an
        error if the path does not exist. Relative paths are not allowed.

    .PARAMETER Arguments
        Indicates a string of arguments to pass to the process as-is. If you need to pass several
        arguments, put them all in this string.

    .PARAMETER Credential
        Indicates the credentials for starting the process.

    .PARAMETER Ensure
        Indicates if the process exists. Set this property to "Present" to ensure that the process
        exists. Otherwise, set it to "Absent". The default is "Present".

    .PARAMETER StandardOutputPath
        Indicates the location to write the standard output. Any existing file there will be
        overwritten.

    .PARAMETER StandardErrorPath
        Indicates the directory path to write the standard error. Any existing file there will be
        overwritten.

    .PARAMETER StandardInputPath
        Indicates the standard input location.

    .PARAMETER WorkingDirectory
        Indicates the location that will be used as the current working directory for the process.
#>
function Set-TargetResource
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]
        $Arguments,

        [ValidateNotNullOrEmpty()]
        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure = 'Present',

        [String]
        $StandardOutputPath,

        [String]
        $StandardErrorPath,

        [String]
        $StandardInputPath,

        [String]
        $WorkingDirectory
    )

    Write-Verbose ($LocalizedData.SetTargetResourceStartMessage -f $Path)

    if ($null -ne $PsDscContext.RunAsUser)
    {
        $newInvalidArgumentExceptionParams = @{
            ArgumentName = 'PsDscRunAsCredential'
            Message =
                ($LocalizedData.ErrorRunAsCredentialParameterNotSupported -f $PsDscContext.RunAsUser)
        }
        New-InvalidArgumentException @newInvalidArgumentExceptionParams
    }

    $Path = Expand-Path -Path $Path

    $getWin32ProcessArguments = @{
        Path = $Path
        Arguments = $Arguments
    }

    if ($null -ne $Credential)
    {
        $getWin32ProcessArguments['Credential'] = $Credential
    }

    $win32Processes = @( Get-Win32Process @getWin32ProcessArguments )

    if ($Ensure -eq 'Absent')
    {
        $assertHashtableParams = @{
            Hashtable = $PSBoundParameters
            Key = @( 'StandardOutputPath', 'StandardErrorPath', 'StandardInputPath',
                'WorkingDirectory' )
        }
        Assert-HashtableDoesNotContainKey @assertHashtableParams

        $whatIfShouldProcess = $PSCmdlet.ShouldProcess($Path, $LocalizedData.StoppingProcessWhatif)
        if ($win32Processes.Count -gt 0 -and $whatIfShouldProcess)
        {
            $processIds = $win32Processes.ProcessId

            $stopProcessError = Stop-Process -Id $processIds -Force 2>&1

            if ($null -eq $stopProcessError)
            {
                $message = ($LocalizedData.ProcessesStopped -f $Path, ($processIds -join ','))
                Write-Verbose -Message $message
            }
            else
            {
                $message = ($LocalizedData.ErrorStopping -f $Path, ($processIds -join ','),
                    ($stopProcessError | Out-String))
                Write-Verbose -Message $message
                throw $stopProcessError
           }

           # Before returning from Set-TargetResource we have to ensure a subsequent
           # Test-TargetResource is going to work
           if (-not (Wait-ProcessCount -ProcessSettings $getWin32ProcessArguments -ProcessCount 0))
           {
                $message = $LocalizedData.ErrorStopping -f $Path, ($processIds -join ','),
                    $LocalizedData.FailureWaitingForProcessesToStop

                Write-Verbose -Message $message

                New-InvalidOperationException -Message $message
           }
        }
        else
        {
            Write-Verbose -Message ($LocalizedData.ProcessAlreadyStopped -f $Path)
        }
    }
    else
    {
        $shouldBeRootedPathArguments = @( 'StandardInputPath', 'WorkingDirectory',
            'StandardOutputPath', 'StandardErrorPath' )

        foreach ($shouldBeRootedPathArgument in $shouldBeRootedPathArguments)
        {
            if (-not [String]::IsNullOrEmpty($PSBoundParameters[$shouldBeRootedPathArgument]))
            {
                $assertPathArgumentRootedParams = @{
                    PathArgumentName = $shouldBeRootedPathArgument
                    PathArgument = $PSBoundParameters[$shouldBeRootedPathArgument]
                }
                Assert-PathArgumentRooted @assertPathArgumentRootedParams
            }
        }

        $shouldExistPathArguments = @( 'StandardInputPath', 'WorkingDirectory' )

        foreach ($shouldExistPathArgument in $shouldExistPathArguments)
        {
            if (-not [String]::IsNullOrEmpty($PSBoundParameters[$shouldExistPathArgument]))
            {
                $assertPathArgumentValidParams = @{
                    PathArgumentName = $shouldExistPathArgument
                    PathArgument = $PSBoundParameters[$shouldExistPathArgument]
                }
                Assert-PathArgumentValid @assertPathArgumentValidParams
            }
        }

        if ($win32Processes.Count -eq 0)
        {
            $startProcessArguments = @{
                FilePath = $Path
            }

            $startProcessOptionalArgumentMap = @{
                Credential = 'Credential'
                RedirectStandardOutput = 'StandardOutputPath'
                RedirectStandardError = 'StandardErrorPath'
                RedirectStandardInput = 'StandardInputPath'
                WorkingDirectory = 'WorkingDirectory'
            }

            foreach ($startProcessOptionalArgumentName in $startProcessOptionalArgumentMap.Keys)
            {
                $parameterKey = $startProcessOptionalArgumentMap[$startProcessOptionalArgumentName]
                $parameterValue = $PSBoundParameters[$parameterKey]
                if (-not [String]::IsNullOrEmpty($parameterValue))
                {
                    $startProcessArguments[$startProcessOptionalArgumentName] = $parameterValue
                }
            }

            if (-not [String]::IsNullOrEmpty($Arguments))
            {
                $startProcessArguments['ArgumentList'] = $Arguments
            }

            if ($PSCmdlet.ShouldProcess($Path, $LocalizedData.StartingProcessWhatif))
            {
                <#
                    Start-Process calls .net Process.Start()
                    If -Credential is present Process.Start() uses win32 api CreateProcessWithLogonW
                    http://msdn.microsoft.com/en-us/library/0w4h05yb(v=vs.110).aspx
                    CreateProcessWithLogonW cannot be called as LocalSystem user.
                    Details http://msdn.microsoft.com/en-us/library/windows/desktop/ms682431(v=vs.85).aspx
                    (section Remarks/Windows XP with SP2 and Windows Server 2003)

                    In this case we call another api.
                #>
                if ($PSBoundParameters.ContainsKey('Credential') -and (Test-IsRunFromLocalSystemUser))
                {
                    foreach ($key in @('StandardOutputPath','StandardInputPath','WorkingDirectory'))
                    {
                        $newInvalidArgumentExceptionParams = {
                            ArgumentName = $key
                            Message = $LocalizedData.ErrorParametersNotSupportedWithCredential
                        }
                        New-InvalidArgumentException @newInvalidArgumentExceptionParams
                    }

                    $splitCredentialResult = Split-Credential $Credential
                    try
                    {
                        <#
                            Internally we use win32 api LogonUser() with
                            dwLogonType == LOGON32_LOGON_NETWORK_CLEARTEXT.

                            It grants process ability for second-hop.
                        #>
                        Import-DscNativeMethods

                        [PSDesiredStateConfiguration.NativeMethods]::CreateProcessAsUser( "$Path $Arguments", $domain, $userName, $Credential.Password, $false, [Ref]$null )
                    }
                    catch
                    {
                        throw (New-Object -TypeName 'System.Management.Automation.ErrorRecord' -ArgumentList @( $_.Exception, 'Win32Exception', 'OperationStopped', $null ))
                    }
                }
                else
                {
                    $startProcessError = Start-Process @startProcessArguments 2>&1
                }

                if ($null -eq $startProcessError)
                {
                    Write-Verbose -Message ($LocalizedData.ProcessStarted -f $Path)
                }
                else
                {
                    Write-Verbose -Message ($LocalizedData.ErrorStarting -f $Path,
                        ($startProcessError | Out-String))
                    throw $startProcessError
                }

                # Before returning from Set-TargetResource we have to ensure a subsequent Test-TargetResource is going to work
                if (-not (Wait-ProcessCount -ProcessSettings $getWin32ProcessArguments -ProcessCount 1))
                {
                    $message = $LocalizedData.ErrorStarting -f $Path,
                        $LocalizedData.FailureWaitingForProcessesToStart

                    Write-Verbose -Message $message

                    New-InvalidOperationException -Message $message
                }
            }
        }
        else
        {
            Write-Verbose -Message ($LocalizedData.ProcessAlreadyStarted -f $Path)
        }
    }

    Write-Verbose ($LocalizedData.SetTargetResourceEndMessage -f $Path)
}

<#
    .SYNOPSIS
        Tests if the managed process is Present or Absent.

    .PARAMETER Path
        The path to the process executable. If this is the file name of the executable
        (not the fully qualified path), the DSC resource will search the environment Path variable
        ($env:Path) to find the executable file. If the value of this property is a fully qualified
        path, DSC will not use the Path environment variable to find the file, and will throw an
        error if the path does not exist. Relative paths are not allowed.

    .PARAMETER Arguments
        Indicates a string of arguments to pass to the process as-is. If you need to pass several
        arguments, put them all in this string.

    .PARAMETER Credential
        Indicates the credentials for starting the process.

    .PARAMETER Ensure
        Indicates if the process exists. Set this property to "Present" to return true
        if the process that the process exists. Otherwise, set it to "Absent" to return true if
        the process does not exist. The default is "Present".

    .PARAMETER StandardOutputPath
        Indicates the location to write the standard output.

        Note: The value provided to this parameter is not being used inside the function
        because we only test if the managed process is Present or Absent.

    .PARAMETER StandardErrorPath
        Indicates the directory path to write the standard error.

        Note: The value provided to this parameter is not being used inside the function
        because we only test if the managed process is Present or Absent.

    .PARAMETER StandardInputPath
        Indicates the standard input location.

        Note: The value provided to this parameter is not being used inside the function
        because we only test if the managed process is Present or Absent.

    .PARAMETER WorkingDirectory
        Indicates the location that will be used as the current working directory for the process.

        Note: The value provided to this parameter is not being used inside the function
        because we only test if the managed process is Present or Absent.
#>
function Test-TargetResource
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]
        $Arguments,

        [ValidateNotNullOrEmpty()]
        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure = 'Present',

        [String]
        $StandardOutputPath,

        [String]
        $StandardErrorPath,

        [String]
        $StandardInputPath,

        [String]
        $WorkingDirectory
    )

    Write-Verbose ($LocalizedData.TestTargetResourceStartMessage -f $Path)

    if ($null -ne $PsDscContext.RunAsUser)
    {
        $newInvalidArgumentExceptionParams = @{
            ArgumentName = 'PsDscRunAsCredential'
            Message =
                ($LocalizedData.ErrorRunAsCredentialParameterNotSupported -f $PsDscContext.RunAsUser)
        }
        New-InvalidArgumentException @newInvalidArgumentExceptionParams
    }

    $Path = Expand-Path -Path $Path

    $getWin32ProcessArguments = @{
        Path = $Path
        Arguments = $Arguments
    }

    if ($null -ne $Credential)
    {
        $getWin32ProcessArguments['Credential'] = $Credential
    }

    $win32Processes = @( Get-Win32Process @getWin32ProcessArguments )

    Write-Verbose ($LocalizedData.TestTargetResourceEndMessage -f $Path)
    if ($Ensure -eq 'Absent')
    {
        return ($win32Processes.Count -eq 0)
    }
    else
    {
        return ($win32Processes.Count -gt 0)
    }
}

<#
    .SYNOPSIS
        Retrieves the owner of a Win32_Process.

    .PARAMETER Process
        The Win32_Process to retrieve the owner of.

    .NOTES
        If the process was killed by the time this function is called, this function will throw a
        WMIMethodException with the message "Not found".
#>
function Get-Win32ProcessOwner
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $Process
    )

    $owner = Invoke-CimMethod -InputObject $Process -MethodName 'GetOwner' -ErrorAction 'SilentlyContinue'

    if ($null -ne $owner.Domain)
    {
        return $owner.Domain + '\' + $owner.User
    }
    else
    {
        return $owner.User
    }
}

<#
    .SYNOPSIS
        Waits for the given number of processes with the given settings to be running.

    .PARAMETER ProcessSettings
        The settings of the running process(s) to get the count of.

    .PARAMETER ProcessCount
        The number of processes running to wait for.
#>
function Wait-ProcessCount
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $ProcessSettings,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [Int]::MaxValue)]
        [Int]
        $ProcessCount
    )

    $startTime = [DateTime]::Now

    do
    {
        $actualProcessCount = @( Get-Win32Process @ProcessSettings ).Count
    } while ($actualProcessCount -ne $ProcessCount -and ([DateTime]::Now - $startTime).TotalMilliseconds -lt 2000)

    return $actualProcessCount -eq $ProcessCount
}

<#
    .SYNOPSIS
        Retrieves any Win32_Process objects that match the given path, arguments, and credential.

    .PARAMETER Path
        The path that should match the retrieved process.

    .PARAMETER Arguments
        The arguments that should match the retrieved process.

    .PARAMETER Credential
        The credential whose user name should match the owner of the process.

    .PARAMETER UseGetCimInstanceThreshold
        If the number of processes returned by the Get-Process method is greater than or equal to
        this value, this function will retrieve all processes at the executable path. This will
        help the function execute faster. Otherwise, this function will retrieve each Win32_Process
        objects with the product ids returned from Get-Process.
#>
function Get-Win32Process
{
    [OutputType([Object[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [String]
        $Arguments,

        [ValidateNotNullOrEmpty()]
        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [ValidateRange(0, [Int]::MaxValue)]
        [Int]
        $UseGetCimInstanceThreshold = 8
    )

    $processName = [IO.Path]::GetFileNameWithoutExtension($Path)

    $getProcessResult = @( Get-Process -Name $processName -ErrorAction 'SilentlyContinue' )

    $processes = @()

    if ($getProcessResult.Count -ge $UseGetCimInstanceThreshold)
    {

        $escapedPathForWqlFilter = ConvertTo-EscapedStringForWqlFilter -FilterString $Path
        $wqlFilter = "ExecutablePath = '$escapedPathForWqlFilter'"

        $processes = Get-CimInstance -ClassName 'Win32_Process' -Filter $wqlFilter
    }
    else
    {
        foreach ($process in $getProcessResult)
        {
            if ($process.Path -ieq $Path)
            {
                Write-Verbose -Message ($LocalizedData.VerboseInProcessHandle -f $process.Id)
                $getCimInstanceParams = @{
                    ClassName = 'Win32_Process'
                    Filter = "ProcessId = $($process.Id)"
                    ErrorAction = 'SilentlyContinue'
                }
                $processes += Get-CimInstance @getCimInstanceParams
            }
        }
    }

    if ($PSBoundParameters.ContainsKey('Credential'))
    {
        $splitCredentialResult = Split-Credenital -Credential $Credential

        $whereFilterScript = {
            $domain =  $splitCredentialResult.Domain
            $userName = $splitCredentialResult.UserName

            (Get-Win32ProcessOwner -Process $_) -eq "${domain}\${userName}"
        }
        $processes = Where-Object -InputObject $processes -FilterScript $whereFilterScript
    }

    if ($null -eq $Arguments)
    {
        $Arguments = [String]::Empty
    }

    $processesWithMatchingArguments = @()

    foreach ($process in $processes)
    {
        $commandLine = $process.CommandLine
        if ((Get-ArgumentsFromCommandLineInput -CommandLineInput $commandLine) -eq $Arguments)
        {
            $processesWithMatchingArguments += $process
        }
    }

    return $processesWithMatchingArguments
}

<#
    .SYNOPSIS
        Retrieves the 'arguments' part of command line input.

    .PARAMETER CommandLineInput
        The command line input to retrieve the arguments from.

    .EXAMPLE
        Get-ArgumentsFromCommandLineInput -CommandLineInput 'C:\temp\a.exe X Y Z'
        Returns 'X Y Z'.
#>
function Get-ArgumentsFromCommandLineInput
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [String]
        $CommandLineInput
    )

    if ([String]::IsNullOrWhitespace($CommandLineInput))
    {
        return [String]::Empty
    }

    $CommandLineInput = $CommandLineInput.Trim()

    if ($CommandLineInput.StartsWith('"'))
    {
        $endOfCommandChar = [Char]'"'
    }
    else
    {
        $endOfCommandChar = [Char]' '
    }

    $endofCommandIndex = $CommandLineInput.IndexOf($endOfCommandChar, 1)
    if ($endofCommandIndex -eq -1)
    {
        return [String]::Empty
    }

    return $CommandLineInput.Substring($endofCommandIndex + 1).Trim()
}

<#
    .SYNOPSIS
        Converts a string to an escaped string to be used in a WQL filter such as the one passed in
        the Filter parameter of Get-WmiObject.

    .PARAMETER FilterString
        The string to convert.
#>
function ConvertTo-EscapedStringForWqlFilter
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FilterString
    )

    return $FilterString.Replace("\","\\").Replace('"','\"').Replace("'","\'")
}

<#
    .SYNOPSIS
        Expands a shortened path into a full, rooted path.

    .PARAMETER Path
        The shortened path to expand.
#>
function Expand-Path
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )

    $Path = [Environment]::ExpandEnvironmentVariables($Path)

    if ([IO.Path]::IsPathRooted($Path))
    {
        if (-not (Test-Path -Path $Path -PathType 'Leaf'))
        {
            New-InvalidArgumentException -ArgumentName 'Path' -Message ($LocalizedData.InvalidArgumentAndMessage -f ($LocalizedData.InvalidArgument -f 'Path', $Path), $LocalizedData.FileNotFound)
        }

        return $Path
    }
    else
    {
        New-InvalidArgumentException -ArgumentName 'Path'
    }

    if ([String]::IsNullOrEmpty($env:Path))
    {
        New-InvalidArgumentException -ArgumentName 'Path' -Message ($LocalizedData.InvalidArgumentAndMessage -f ($LocalizedData.InvalidArgument -f 'Path', $Path), $LocalizedData.FileNotFound)
    }

    <#
        This will block relative paths. The statement is only true when $Path contains a plain file name.
        Checking a relative path against segments of $env:Path does not make sense.
    #>
    if ((Split-Path -Path $Path -Leaf) -ne $Path)
    {
        New-InvalidArgumentException -ArgumentName 'Path' -Message ($LocalizedData.InvalidArgumentAndMessage -f ($LocalizedData.InvalidArgument -f 'Path', $Path), $LocalizedData.AbsolutePathOrFileName)
    }

    foreach ($rawEnvPathSegment in $env:Path.Split(';'))
    {
        $envPathSegment = [Environment]::ExpandEnvironmentVariables($rawEnvPathSegment)

        <#
            If the whole path passed through [IO.Path]::IsPathRooted with no exceptions, it does not have
            invalid characters, so the segment has no invalid characters and will not throw as well.
        #>
        try
        {
            $envPathSegmentRooted = [IO.Path]::IsPathRooted($envPathSegment)
        }
        catch
        {
            # If an exception causes $envPathSegmentRooted not to be set, we will consider it $false
            $envPathSegmentRooted = $false
        }

        if ($envPathSegmentRooted)
        {
            $fullPathCandidate = Join-Path -Path $envPathSegment -ChildPath $Path

            if (Test-Path -Path $fullPathCandidate -PathType 'Leaf')
            {
                return $fullPathCandidate
            }
        }
    }

    New-InvalidArgumentException -ArgumentName 'Path' -Message ($LocalizedData.InvalidArgumentAndMessage -f ($LocalizedData.InvalidArgument -f 'Path', $Path), $LocalizedData.FileNotFound)
}

<#
    .SYNOPSIS
        Throws an error if the given path argument is not rooted.

    .PARAMETER PathArgumentName
        The name of the path argument that should be rooted.

    .PARAMETER PathArgument
        The path arguments that should be rooted.
#>
function Assert-PathArgumentRooted
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $PathArgumentName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $PathArgument
    )

    if (-not ([IO.Path]::IsPathRooted($PathArgument)))
    {
        New-InvalidArgumentException -ArgumentName $PathArgumentName -Message ($LocalizedData.InvalidArgumentAndMessage -f ($LocalizedData.InvalidArgument -f $PathArgumentName, $PathArgument), $LocalizedData.PathShouldBeAbsolute)
    }
}

<#
    .SYNOPSIS
        Throws an error if the given path argument does not exist.

    .PARAMETER PathArgumentName
        The name of the path argument that should exist.

    .PARAMETER PathArgument
        The path argument that should exist.
#>
function Assert-PathArgumentValid
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $PathArgumentName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $PathArgument
    )

    if (-not (Test-Path -Path $PathArgument))
    {
        New-InvalidArgumentException -ArgumentName $PathArgumentName -Message ($LocalizedData.InvalidArgumentAndMessage -f ($LocalizedData.InvalidArgument -f $PathArgumentName, $PathArgument), $LocalizedData.PathShouldExist)
    }
}

<#
    .SYNOPSIS
        Throws an exception if the given hashtable contains the given key(s).

    .PARAMETER Hashtable
        The hashtable to check the keys of.

    .PARAMETER Key
        The key(s) that should not be in the hashtable.
#>
function Assert-HashtableDoesNotContainKey
{
    [CmdletBinding()]
    param
    (
        [Hashtable]
        $Hashtable,

        [Parameter(Mandatory = $true)]
        [String[]]
        $Key
    )

    foreach ($keyName in $Key)
    {
        if ($Hashtable.ContainsKey($keyName))
        {
            New-InvalidArgumentException -ArgumentName $keyName -Message ($LocalizedData.ParameterShouldNotBeSpecified -f $keyName)
        }
    }
}

Export-ModuleMember -Function *-TargetResource
