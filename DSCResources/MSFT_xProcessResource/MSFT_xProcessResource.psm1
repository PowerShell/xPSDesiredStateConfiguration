Import-Module -Name (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) `
                               -ChildPath 'CommonResourceHelper.psm1')
$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_xProcessResource'

<#
    .SYNOPSIS
        Returns a hashtable of results about the managed process. If more than one process is
        

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
        Indicates the credential for starting the process.
#>
function Get-TargetResource
{
    [OutputType([Hashtable[]])]
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
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    Write-Verbose ($script:localizedData.GetTargetResourceStartMessage -f $Path)

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

    $processesToReturn = @()

    foreach ($win32Process in $win32Processes)
    {
        $getProcessResult = Get-Process -ID $win32Process.ProcessId -ErrorAction 'Ignore'

        $processesToReturn += @{
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

    Write-Verbose ($script:localizedData.GetTargetResourceEndMessage -f $Path)
    return $processesToReturn
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
        Indicates the credential for starting the process.

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
        [System.Management.Automation.PSCredential]
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

    Write-Verbose ($script:localizedData.SetTargetResourceStartMessage -f $Path)

    if ($null -ne $PsDscContext.RunAsUser)
    {
        $newInvalidArgumentExceptionParams = @{
            ArgumentName = 'PsDscRunAsCredential'
            Message = ($script:localizedData.ErrorRunAsCredentialParameterNotSupported -f $PsDscContext.RunAsUser)
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
            Key = @( 'StandardOutputPath',
                     'StandardErrorPath',
                     'StandardInputPath',
                     'WorkingDirectory' )
        }
        Assert-HashtableDoesNotContainKey @assertHashtableParams

        $whatIfShouldProcess = $PSCmdlet.ShouldProcess($Path, $script:localizedData.StoppingProcessWhatif)
        if ($win32Processes.Count -gt 0 -and $whatIfShouldProcess)
        {
            # If there are multiple process Ids, all will be included to be stopped
            $processIds = $win32Processes.ProcessId

            # Redirecting error output to standard output while we try to stop the processes
            $stopProcessError = Stop-Process -Id $processIds -Force 2>&1

            if ($null -eq $stopProcessError)
            {
                $message = ($script:localizedData.ProcessesStopped -f $Path, ($processIds -join ','))
                Write-Verbose -Message $message
            }
            else
            {
                $message = ($script:localizedData.ErrorStopping -f $Path,
                           ($processIds -join ','),
                           ($stopProcessError | Out-String))

                New-InvalidOperationException -Message $message
           }
           <#
               Before returning from Set-TargetResource we have to ensure a subsequent
               Test-TargetResource is going to work
           #>
           if (-not (Wait-ProcessCount -ProcessSettings $getWin32ProcessArguments -ProcessCount 0))
           {
                $message = $script:localizedData.ErrorStopping -f $Path, ($processIds -join ','),
                           $script:localizedData.FailureWaitingForProcessesToStop

                New-InvalidOperationException -Message $message
           }
        }
        else
        {
            Write-Verbose -Message ($script:localizedData.ProcessAlreadyStopped -f $Path)
        }
    }
    # Ensure = 'Present'
    else
    {
        $shouldBeRootedPathArguments = @( 'StandardInputPath',
                                          'WorkingDirectory',
                                          'StandardOutputPath',
                                          'StandardErrorPath' )

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

            if ($PSCmdlet.ShouldProcess($Path, $script:localizedData.StartingProcessWhatif))
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
                    # Throw an exception if any of the below parameters are included with Credential passed
                    foreach ($key in @('StandardOutputPath','StandardInputPath','WorkingDirectory'))
                    {
                        if ($PSBoundParameters.Keys -contains $key)
                        {
                            $newInvalidArgumentExceptionParams = @{
                                ArgumentName = $key
                                Message = $script:localizedData.ErrorParametersNotSupportedWithCredential
                            }
                            New-InvalidArgumentException @newInvalidArgumentExceptionParams
                        }
                    }
                    try
                    {
                        Start-ProcessAsLocalSystemUser -Path $Path -Arguments $Arguments -Credential $Credential
                    }
                    catch
                    {
                        throw (New-Object -TypeName 'System.Management.Automation.ErrorRecord' `
                                          -ArgumentList @( $_.Exception, 'Win32Exception', 'OperationStopped', $null ))
                    }
                }
                else
                {
                    $startProcessError = Start-Process @startProcessArguments 2>&1
                }

                if ($null -eq $startProcessError)
                {
                    Write-Verbose -Message ($script:localizedData.ProcessStarted -f $Path)
                }
                else
                {
                    Write-Verbose -Message ($script:localizedData.ErrorStarting -f $Path,
                                            ($startProcessError | Out-String))
                    throw $startProcessError
                }

                # Before returning from Set-TargetResource we have to ensure a subsequent Test-TargetResource is going to work
                if (-not (Wait-ProcessCount -ProcessSettings $getWin32ProcessArguments -ProcessCount 1))
                {
                    $message = $script:localizedData.ErrorStarting -f $Path,
                               $script:localizedData.FailureWaitingForProcessesToStart

                    New-InvalidOperationException -Message $message
                }
            }
        }
        else
        {
            Write-Verbose -Message ($script:localizedData.ProcessAlreadyStarted -f $Path)
        }
    }

    Write-Verbose ($script:localizedData.SetTargetResourceEndMessage -f $Path)
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
        Indicates the credential for starting the process.

    .PARAMETER Ensure
        Indicates if the process exists. Set this property to "Present" to return true
        if the process that is being tested exists. Otherwise, set it to "Absent" to return true if
        the process does not exist. The default is "Present".

    .PARAMETER StandardOutputPath
        Not used in Test-TargetResource.

    .PARAMETER StandardErrorPath
        Not used in Test-TargetResource.

    .PARAMETER StandardInputPath
        Not used in Test-TargetResource.

    .PARAMETER WorkingDirectory
        Not used in Test-TargetResource.
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

    Write-Verbose ($script:localizedData.TestTargetResourceStartMessage -f $Path)

    if ($null -ne $PsDscContext.RunAsUser)
    {
        $newInvalidArgumentExceptionParams = @{
            ArgumentName = 'PsDscRunAsCredential'
            Message = ($script:localizedData.ErrorRunAsCredentialParameterNotSupported -f $PsDscContext.RunAsUser)
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

    Write-Verbose ($script:localizedData.TestTargetResourceEndMessage -f $Path)

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

    $fileNotFoundMessage = $script:localizedData.InvalidArgumentAndMessage -f ($script:localizedData.InvalidArgument -f 'Path', $Path), 
                                                                               $script:localizedData.FileNotFound

    if ([IO.Path]::IsPathRooted($Path))
    {
        if (-not (Test-Path -Path $Path -PathType 'Leaf'))
        {
            New-InvalidArgumentException -ArgumentName 'Path' -Message $fileNotFoundMessage
        }

        return $Path
    }
    else
    {
        New-InvalidArgumentException -ArgumentName 'Path' `
                                     -Message $script:localizedData.InvalidArgument -f 'Path', $Path
    }

    if ([String]::IsNullOrEmpty($env:Path))
    {
        New-InvalidArgumentException -ArgumentName 'Path' -Message $fileNotFoundMessage
    }

    <#
        This will block relative paths. The statement is only true when $Path contains a plain file name.
        Checking a relative path against segments of $env:Path does not make sense.
    #>
    if ((Split-Path -Path $Path -Leaf) -ne $Path)
    {
        $message = $script:localizedData.InvalidArgumentAndMessage -f ($script:localizedData.InvalidArgument -f 'Path', $Path),
                                                                      $script:localizedData.AbsolutePathOrFileName
        New-InvalidArgumentException -ArgumentName 'Path' -Message $message
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

    New-InvalidArgumentException -ArgumentName 'Path' -Message $fileNotFoundMessage
}

<#
    .SYNOPSIS
        Retrieves any Win32_Process objects that match the given path, arguments, and credential.

    .PARAMETER Path
        The path that should match the retrieved process.

    .PARAMETER Arguments
        The arguments that should match the retrieved process.

    .PARAMETER Credential
        The credential whose username should match the owner of the process.

    .PARAMETER UseGetCimInstanceThreshold
        If the number of processes returned by the Get-Process method is greater than or equal to
        this value, this function will retrieve all processes at the executable path. This will
        help the function execute faster. Otherwise, this function will retrieve each Win32_Process
        object with the product IDs returned from Get-Process.
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
        [System.Management.Automation.PSCredential]
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
                Write-Verbose -Message ($script:localizedData.VerboseInProcessHandle -f $process.Id)
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
        if ((Get-ArgumentsFromCommandLineInput -CommandLineInput $process.CommandLine) -eq $Arguments)
        {
            $processesWithMatchingArguments += $process
        }
    }

    return $processesWithMatchingArguments
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
        [Object]
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
            New-InvalidArgumentException -ArgumentName $keyName `
                                         -Message ($script:localizedData.ParameterShouldNotBeSpecified -f $keyName)
        }
    }
}

<#
    .SYNOPSIS
        Waits for the given number of processes with the given settings to be running.

    .PARAMETER ProcessSettings
        The settings of the running process(es) to get the count of.

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
        $message = $script:localizedData.InvalidArgumentAndMessage -f `
                  ($script:localizedData.InvalidArgument -f $PathArgumentName, $PathArgument),
                   $script:localizedData.PathShouldBeAbsolute
        New-InvalidArgumentException -ArgumentName $PathArgumentName `
                                     -Message $message
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
        $message = $script:localizedData.InvalidArgumentAndMessage -f `
                  ($script:localizedData.InvalidArgument -f $PathArgumentName, $PathArgument),
                   $script:localizedData.PathShouldExist
        New-InvalidArgumentException -ArgumentName $PathArgumentName `
                                     -Message $message
    }
}

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
        Starts the process with the given credential when the user is a local system user.

    .PARAMETER Path
        The path to the process executable.

    .PARAMETER Arguments
        Indicates a string of arguments to pass to the process as-is.

    .PARAMETER Credential
        Indicates the credential for starting the process.
#>
function Start-ProcessAsLocalSystemUser
{
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

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    $splitCredentialResult = Split-Credential -Credential $Credential
    <#
        Internally we use win32 api LogonUser() with
        dwLogonType == LOGON32_LOGON_NETWORK_CLEARTEXT.

        It grants the process ability for second-hop.
    #>
    Import-DscNativeMethods

    [PSDesiredStateConfiguration.NativeMethods]::CreateProcessAsUser( "$Path $Arguments", $splitCredentialResult.Domain,
                                                                      $splitCredentialResult.UserName, $Credential.Password,
                                                                      $false, [Ref]$null )
}

<#
    .SYNOPSIS
        Splits a credential into a username and domain without calling GetNetworkCredential.
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
        [System.Management.Automation.PSCredential]
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
        $message = $script:localizedData.ErrorInvalidUserName -f $Credential.UserName

        New-InvalidArgumentException -ArgumentName 'Credential' -Message $message
    }

    return @{
        Domain = $domain
        UserName = $userName
    }
}

Export-ModuleMember -Function *-TargetResource
