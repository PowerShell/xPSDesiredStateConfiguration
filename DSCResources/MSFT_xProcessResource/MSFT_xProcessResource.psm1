Set-StrictMode -Version 'Latest'

Import-Module -Name (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) `
                               -ChildPath 'CommonResourceHelper.psm1')

# Localized messages for verbose and error statements in this resource
$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_xProcessResource'

<#
    .SYNOPSIS
        Returns a hashtable of results about the managed process. If more than one process is
        found, only the first will be returned

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
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    Write-Verbose -Message ($script:localizedData.GetTargetResourceStartMessage -f $Path)

    $Path = Expand-Path -Path $Path

    $getProcessCimInstanceArguments = @{
        Path = $Path
        Arguments = $Arguments
    }

    if ($null -ne $Credential)
    {
        $getProcessCimInstanceArguments['Credential'] = $Credential
    }

    $processCimInstance = @( Get-ProcessCimInstance @getProcessCimInstanceArguments )

    if ($processCimInstance.Count -eq 0)
    {
        return @{
            Path = $Path
            Arguments = $Arguments
            Ensure ='Absent'
        }
    }

    $getProcessResult = Get-Process -ID $processCimInstance[0].ProcessId -ErrorAction 'Ignore'

    $processToReturn = @{
        Path = $processCimInstance[0].Path
        Arguments = (Get-ArgumentsFromCommandLineInput -CommandLineInput $processCimInstance[0].CommandLine)
        PagedMemorySize = $getProcessResult.PagedMemorySize64
        NonPagedMemorySize = $getProcessResult.NonpagedSystemMemorySize64
        VirtualMemorySize = $getProcessResult.VirtualMemorySize64
        HandleCount = $getProcessResult.HandleCount
        Ensure = 'Present'
        ProcessId = $processCimInstance[0].ProcessId
        ProcessCount = $processCimInstance.Count
    }

    Write-Verbose -Message ($script:localizedData.GetTargetResourceEndMessage -f $Path)
    return $processToReturn
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
    Write-Verbose -Message ($script:localizedData.SetTargetResourceStartMessage -f $Path)

    Assert-PsDscContextNotRunAsUser

    $Path = Expand-Path -Path $Path

    $getProcessCimInstanceArguments = @{
        Path = $Path
        Arguments = $Arguments
    }

    if ($null -ne $Credential)
    {
        $getProcessCimInstanceArguments['Credential'] = $Credential
    }

    $processCimInstance = @( Get-ProcessCimInstance @getProcessCimInstanceArguments )

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
        if ($processCimInstance.Count -gt 0 -and $whatIfShouldProcess)
        {
            # If there are multiple process Ids, all will be included to be stopped
            $processIds = $processCimInstance.ProcessId

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
           if (-not (Wait-ProcessCount -ProcessSettings $getProcessCimInstanceArguments -ProcessCount 0))
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

        if ($processCimInstance.Count -eq 0)
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
                if (($PSBoundParameters.ContainsKey('Credential')) -and (Test-IsRunFromLocalSystemUser))
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
                # Credential not passed in
                else
                {
                    try
                    {
                        Start-Process @startProcessArguments
                    }
                    catch [System.Exception]
                    {
                        $message = ($script:localizedData.ErrorStarting -f $Path, $_.Exception.Message)
                        
                        New-InvalidOperationException -Message $message
                    }
                }

                Write-Verbose -Message ($script:localizedData.ProcessesStarted -f $Path)

                # Before returning from Set-TargetResource we have to ensure a subsequent Test-TargetResource is going to work
                if (-not (Wait-ProcessCount -ProcessSettings $getProcessCimInstanceArguments -ProcessCount 1))
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

    Write-Verbose -Message ($script:localizedData.SetTargetResourceEndMessage -f $Path)
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

    Write-Verbose -Message ($script:localizedData.TestTargetResourceStartMessage -f $Path)

    Assert-PsDscContextNotRunAsUser

    $Path = Expand-Path -Path $Path

    $getProcessArguments = @{
        Path = $Path
        Arguments = $Arguments
    }

    if ($null -ne $Credential)
    {
        $getProcessArguments['Credential'] = $Credential
    }

    $processCimInstances = @( Get-ProcessCimInstance @getProcessArguments )

    Write-Verbose -Message ($script:localizedData.TestTargetResourceEndMessage -f $Path)

    if ($Ensure -eq 'Absent')
    {
        return ($processCimInstances.Count -eq 0)
    }
    else
    {
        return ($processCimInstances.Count -gt 0)
    }
}

<#
    .SYNOPSIS
        Expands a relative leaf path into a full, rooted path. Throws an invalid argument exception
        if any there are any issues with the path.

    .PARAMETER Path
        The relative leaf path to expand.
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

    # Check to see if the path is rooted. If so, return it as is.
    if ([IO.Path]::IsPathRooted($Path))
    {
        if (-not (Test-Path -Path $Path -PathType 'Leaf'))
        {
            New-InvalidArgumentException -ArgumentName 'Path' -Message $fileNotFoundMessage
        }

        return $Path
    }

    # Check to see if the path to the file exists in the current location. If so, return the full rooted path.
    $rootedPath = [System.IO.Path]::GetFullPath($Path)
    if ([System.IO.File]::Exists($rootedPath))
    {
        return $rootedPath
    }
    
    # If the path is not found, throw an exception
    New-InvalidArgumentException -ArgumentName 'Path' -Message $fileNotFoundMessage
}

<#
    .SYNOPSIS
        Retrieves any process cim instance objects that match the given path, arguments, and credential.

    .PARAMETER Path
        The path that should match the retrieved process.

    .PARAMETER Arguments
        The arguments that should match the retrieved process.

    .PARAMETER Credential
        The credential whose username should match the owner of the process.

    .PARAMETER UseGetCimInstanceThreshold
        If the number of processes returned by the Get-Process method is greater than or equal to
        this value, this function will retrieve all processes at the executable path. This will
        help the function execute faster. Otherwise, this function will retrieve each Process cim
        instance object with the product IDs returned from Get-Process.
#>
function Get-ProcessCimInstance
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
        $splitCredentialResult = Split-Credential -Credential $Credential
        $domain =  $splitCredentialResult.Domain
        $userName = $splitCredentialResult.UserName
        $processesWithCredential = @()

        foreach ($process in $processes)
        {
            if ((Get-ProcessOwner -Process $process) -eq "$domain\$userName")
            {
                $processesWithCredential += $process
            }
        }
        $processes = $processesWithCredential
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
        Retrieves the owner of a Process.

    .PARAMETER Process
        The Process to retrieve the owner of.

    .NOTES
        If the process was killed by the time this function is called, this function will throw a
        WMIMethodException with the message "Not found".
#>
function Get-ProcessOwner
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

    $owner = Get-ProcessOwnerCimInstance -Process $Process

    if ($null -ne $owner.Domain)
    {
        return ($owner.Domain + '\' + $owner.User)
    }
    else
    {
        # return the default domain
        return ($env:computerName + '\' + $owner.User)
    }
}

<#
    .SYNOPSIS
        Wrapper function to retrieve the cim instance of the owner of a process

    .PARAMETER Process
        The process to retrieve the cim instance of the owner of.

    .NOTES
        If the process was killed by the time this function is called, this function will throw a
        WMIMethodException with the message "Not found".
#>
function Get-ProcessOwnerCimInstance
{
    [OutputType([Object])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Object]
        $Process
    )

    return Invoke-CimMethod -InputObject $Process -MethodName 'GetOwner' -ErrorAction 'SilentlyContinue'
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
        Waits for the given amount of time for the given number of processes with the given settings
        to be running. If not all processes are running by 'WaitTime', the function returns
        false, otherwise it returns true.

    .PARAMETER ProcessSettings
        The settings for the running process(es) that we're getting the count of.

    .PARAMETER ProcessCount
        The number of processes running to wait for.

    .PARAMETER WaitTime
        The amount of milliseconds to wait for all processes to be running.
        Default is 2000.
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
        $ProcessCount,

        [Int]
        $WaitTime = 200000
    )

    $startTime = [DateTime]::Now

    do
    {
        $actualProcessCount = @( Get-ProcessCimInstance @ProcessSettings ).Count
    } while ($actualProcessCount -ne $ProcessCount -and ([DateTime]::Now - $startTime).TotalMilliseconds -lt $WaitTime)

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

<#
    .SYNOPSIS
        Asserts that the PsDscContext is not run as user. If so, it will throw 
        an invalid argument exception.

    .NOTES
        Strict mode is turned off for this function since it does not recognize $PsDscContext
#>
function Assert-PsDscContextNotRunAsUser
{
    [CmdletBinding()]
    param 
    ()

    Set-StrictMode -Off

    if ($null -ne $PsDscContext.RunAsUser)
    {
        $newInvalidArgumentExceptionParams = @{
            ArgumentName = 'PsDscRunAsCredential'
            Message = ($script:localizedData.ErrorRunAsCredentialParameterNotSupported -f $PsDscContext.RunAsUser)
        }
        New-InvalidArgumentException @newInvalidArgumentExceptionParams
    }
}

<#
    .SYNOPSIS
        Imports the DSC native methods so that a process can be started with a credential
        on a local system. Currently Start-Process, which is the command used when no credential
        is passed in, does not have this functionality.
#>
function Import-DscNativeMethods  
{  
$script:ProgramSource = @"  
  
using System;  
using System.Collections.Generic;  
using System.Text;  
using System.Security;  
using System.Runtime.InteropServices;  
using System.Diagnostics;  
using System.Security.Principal;  
#if !CORECLR  
using System.ComponentModel;  
#endif  
using System.IO;  
  
namespace PSDesiredStateConfiguration  
{  
#if !CORECLR  
    [SuppressUnmanagedCodeSecurity]  
#endif  
    public static class NativeMethods  
    {  
        //The following structs and enums are used by the various Win32 API's that are used in the code below  
  
        [StructLayout(LayoutKind.Sequential)]  
        public struct STARTUPINFO  
        {  
            public Int32 cb;  
            public string lpReserved;  
            public string lpDesktop;  
            public string lpTitle;  
            public Int32 dwX;  
            public Int32 dwY;  
            public Int32 dwXSize;  
            public Int32 dwXCountChars;  
            public Int32 dwYCountChars;  
            public Int32 dwFillAttribute;  
            public Int32 dwFlags;  
            public Int16 wShowWindow;  
            public Int16 cbReserved2;  
            public IntPtr lpReserved2;  
            public IntPtr hStdInput;  
            public IntPtr hStdOutput;  
            public IntPtr hStdError;  
        }  
  
        [StructLayout(LayoutKind.Sequential)]  
        public struct PROCESS_INFORMATION  
        {  
            public IntPtr hProcess;  
            public IntPtr hThread;  
            public Int32 dwProcessID;  
            public Int32 dwThreadID;  
        }  
  
        [Flags]  
        public enum LogonType  
        {  
            LOGON32_LOGON_INTERACTIVE = 2,  
            LOGON32_LOGON_NETWORK = 3,  
            LOGON32_LOGON_BATCH = 4,  
            LOGON32_LOGON_SERVICE = 5,  
            LOGON32_LOGON_UNLOCK = 7,  
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8,  
            LOGON32_LOGON_NEW_CREDENTIALS = 9  
        }  
  
        [Flags]  
        public enum LogonProvider  
        {  
            LOGON32_PROVIDER_DEFAULT = 0,  
            LOGON32_PROVIDER_WINNT35,  
            LOGON32_PROVIDER_WINNT40,  
            LOGON32_PROVIDER_WINNT50  
        }  
        [StructLayout(LayoutKind.Sequential)]  
        public struct SECURITY_ATTRIBUTES  
        {  
            public Int32 Length;  
            public IntPtr lpSecurityDescriptor;  
            public bool bInheritHandle;  
        }  
  
        public enum SECURITY_IMPERSONATION_LEVEL  
        {  
            SecurityAnonymous,  
            SecurityIdentification,  
            SecurityImpersonation,  
            SecurityDelegation  
        }  
  
        public enum TOKEN_TYPE  
        {  
            TokenPrimary = 1,  
            TokenImpersonation  
        }  
  
        [StructLayout(LayoutKind.Sequential, Pack = 1)]  
        internal struct TokPriv1Luid  
        {  
            public int Count;  
            public long Luid;  
            public int Attr;  
        }  
  
        public const int GENERIC_ALL_ACCESS = 0x10000000;  
        public const int CREATE_NO_WINDOW = 0x08000000;  
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;  
        internal const int TOKEN_QUERY = 0x00000008;  
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;  
        internal const string SE_INCRASE_QUOTA = "SeIncreaseQuotaPrivilege";  
  
#if CORECLR  
        [DllImport("api-ms-win-core-handle-l1-1-0.dll",  
#else  
        [DllImport("kernel32.dll",  
#endif  
              EntryPoint = "CloseHandle", SetLastError = true,  
              CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]  
        public static extern bool CloseHandle(IntPtr handle);  
  
#if CORECLR  
        [DllImport("api-ms-win-core-processthreads-l1-1-2.dll",  
#else  
        [DllImport("advapi32.dll",  
#endif  
              EntryPoint = "CreateProcessAsUser", SetLastError = true,  
              CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]  
        public static extern bool CreateProcessAsUser(  
            IntPtr hToken,  
            string lpApplicationName,  
            string lpCommandLine,  
            ref SECURITY_ATTRIBUTES lpProcessAttributes,  
            ref SECURITY_ATTRIBUTES lpThreadAttributes,  
            bool bInheritHandle,  
            Int32 dwCreationFlags,  
            IntPtr lpEnvrionment,  
            string lpCurrentDirectory,  
            ref STARTUPINFO lpStartupInfo,  
            ref PROCESS_INFORMATION lpProcessInformation  
            );  
  
#if CORECLR  
        [DllImport("api-ms-win-security-base-l1-1-0.dll", EntryPoint = "DuplicateTokenEx")]  
#else  
        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]  
#endif  
        public static extern bool DuplicateTokenEx(  
            IntPtr hExistingToken,  
            Int32 dwDesiredAccess,  
            ref SECURITY_ATTRIBUTES lpThreadAttributes,  
            Int32 ImpersonationLevel,  
            Int32 dwTokenType,  
            ref IntPtr phNewToken  
            );  
  
#if CORECLR  
        [DllImport("api-ms-win-security-logon-l1-1-1.dll", CharSet = CharSet.Unicode, SetLastError = true)]  
#else  
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]  
#endif  
        public static extern Boolean LogonUser(  
            String lpszUserName,  
            String lpszDomain,  
            IntPtr lpszPassword,  
            LogonType dwLogonType,  
            LogonProvider dwLogonProvider,  
            out IntPtr phToken  
            );  
  
#if CORECLR  
        [DllImport("api-ms-win-security-base-l1-1-0.dll", ExactSpelling = true, SetLastError = true)]  
#else  
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]  
#endif  
        internal static extern bool AdjustTokenPrivileges(  
            IntPtr htok,  
            bool disall,  
            ref TokPriv1Luid newst,  
            int len,  
            IntPtr prev,  
            IntPtr relen  
            );  
  
#if CORECLR  
        [DllImport("api-ms-win-downlevel-kernel32-l1-1-0.dll", ExactSpelling = true)]  
#else  
        [DllImport("kernel32.dll", ExactSpelling = true)]  
#endif  
        internal static extern IntPtr GetCurrentProcess();  
  
#if CORECLR  
        [DllImport("api-ms-win-downlevel-advapi32-l1-1-1.dll", ExactSpelling = true, SetLastError = true)]  
#else  
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]  
#endif  
        internal static extern bool OpenProcessToken(  
            IntPtr h,  
            int acc,  
            ref IntPtr phtok  
            );  
  
#if CORECLR  
        [DllImport("api-ms-win-downlevel-kernel32-l1-1-0.dll", ExactSpelling = true)]  
#else  
        [DllImport("kernel32.dll", ExactSpelling = true)]  
#endif  
        internal static extern int WaitForSingleObject(  
            IntPtr h,   
            int milliseconds  
            );  
  
#if CORECLR  
        [DllImport("api-ms-win-downlevel-kernel32-l1-1-0.dll", ExactSpelling = true)]  
#else  
        [DllImport("kernel32.dll", ExactSpelling = true)]  
#endif  
        internal static extern bool GetExitCodeProcess(  
            IntPtr h,   
            out int exitcode  
            );  
  
#if CORECLR  
        [DllImport("api-ms-win-downlevel-advapi32-l4-1-0.dll", SetLastError = true)]  
#else  
        [DllImport("advapi32.dll", SetLastError = true)]  
#endif  
        internal static extern bool LookupPrivilegeValue(  
            string host,  
            string name,  
            ref long pluid  
            );  
  
        internal static void ThrowException(  
            string message  
            )  
        {  
#if CORECLR  
            throw new Exception(message);  
#else  
            throw new Win32Exception(message);  
#endif  
        }  
  
        public static void CreateProcessAsUser(string strCommand, string strDomain, string strName, SecureString secureStringPassword, bool waitForExit, ref int ExitCode)  
        {  
            var hToken = IntPtr.Zero;  
            var hDupedToken = IntPtr.Zero;  
            TokPriv1Luid tp;  
            var pi = new PROCESS_INFORMATION();  
            var sa = new SECURITY_ATTRIBUTES();  
            sa.Length = Marshal.SizeOf(sa);  
            Boolean bResult = false;  
            try  
            {  
                IntPtr unmanagedPassword = IntPtr.Zero;  
                try  
                {  
#if CORECLR  
                    unmanagedPassword = SecureStringMarshal.SecureStringToCoTaskMemUnicode(secureStringPassword);  
#else  
                    unmanagedPassword = Marshal.SecureStringToGlobalAllocUnicode(secureStringPassword);  
#endif  
                    bResult = LogonUser(  
                        strName,  
                        strDomain,  
                        unmanagedPassword,  
                        LogonType.LOGON32_LOGON_NETWORK_CLEARTEXT,  
                        LogonProvider.LOGON32_PROVIDER_DEFAULT,  
                        out hToken  
                        );  
                }  
                finally  
                {  
                    Marshal.ZeroFreeGlobalAllocUnicode(unmanagedPassword);  
                }  
                if (!bResult)  
                {  
                    ThrowException("$($script:localizedData.UserCouldNotBeLoggedError)" + Marshal.GetLastWin32Error().ToString());  
                }  
                IntPtr hproc = GetCurrentProcess();  
                IntPtr htok = IntPtr.Zero;  
                bResult = OpenProcessToken(  
                        hproc,  
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,  
                        ref htok  
                    );  
                if (!bResult)  
                {  
                    ThrowException("$($script:localizedData.OpenProcessTokenError)" + Marshal.GetLastWin32Error().ToString());  
                }  
                tp.Count = 1;  
                tp.Luid = 0;  
                tp.Attr = SE_PRIVILEGE_ENABLED;  
                bResult = LookupPrivilegeValue(  
                    null,  
                    SE_INCRASE_QUOTA,  
                    ref tp.Luid  
                    );  
                if (!bResult)  
                {  
                    ThrowException("$($script:localizedData.PrivilegeLookingUpError)" + Marshal.GetLastWin32Error().ToString());  
                }  
                bResult = AdjustTokenPrivileges(  
                    htok,  
                    false,  
                    ref tp,  
                    0,  
                    IntPtr.Zero,  
                    IntPtr.Zero  
                    );  
                if (!bResult)  
                {  
                    ThrowException("$($script:localizedData.TokenElevationError)" + Marshal.GetLastWin32Error().ToString());  
                }  
  
                bResult = DuplicateTokenEx(  
                    hToken,  
                    GENERIC_ALL_ACCESS,  
                    ref sa,  
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,  
                    (int)TOKEN_TYPE.TokenPrimary,  
                    ref hDupedToken  
                    );  
                if (!bResult)  
                {  
                    ThrowException("$($script:localizedData.DuplicateTokenError)" + Marshal.GetLastWin32Error().ToString());  
                }  
                var si = new STARTUPINFO();  
                si.cb = Marshal.SizeOf(si);  
                si.lpDesktop = "";  
                bResult = CreateProcessAsUser(  
                    hDupedToken,  
                    null,  
                    strCommand,  
                    ref sa,  
                    ref sa,  
                    false,  
                    0,  
                    IntPtr.Zero,  
                    null,  
                    ref si,  
                    ref pi  
                    );  
                if (!bResult)  
                {  
                    ThrowException("$($script:localizedData.CouldNotCreateProcessError)" + Marshal.GetLastWin32Error().ToString());  
                }  
                if (waitForExit) {  
                    int status = WaitForSingleObject(pi.hProcess, -1);  
                    if(status == -1)  
                    {  
                        ThrowException("$($script:localizedData.WaitFailedError)" + Marshal.GetLastWin32Error().ToString());  
                    }  
  
                    bResult = GetExitCodeProcess(pi.hProcess, out ExitCode);  
                    if(!bResult)  
                    {  
                        ThrowException("$($script:localizedData.RetriveStatusError)" + Marshal.GetLastWin32Error().ToString());  
                    }  
                }  
            }  
            finally  
            {  
                if (pi.hThread != IntPtr.Zero)  
                {  
                    CloseHandle(pi.hThread);  
                }  
                if (pi.hProcess != IntPtr.Zero)  
                {  
                    CloseHandle(pi.hProcess);  
                }  
                if (hDupedToken != IntPtr.Zero)  
                {  
                    CloseHandle(hDupedToken);  
                }  
            }  
        }  
    }  
}  
  
"@
    # if not on Nano:
    Add-Type -TypeDefinition $ProgramSource -ReferencedAssemblies 'System.ServiceProcess'
} 

Export-ModuleMember -Function *-TargetResource
