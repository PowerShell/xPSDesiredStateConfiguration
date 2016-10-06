# Suppressed as per PSSA Rule Severity guidelines for unit/integration tests:
# https://github.com/PowerShell/DscResources/blob/master/PSSARuleSeverities.md
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
param ()

Import-Module -Name (Join-Path -Path (Split-Path $PSScriptRoot -Parent) `
-ChildPath 'CommonResourceHelper.psm1')

# Localized messages for Write-Verbose statements in this resource
$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_xServiceResource'

<#
    .SYNOPSIS
        Get the current status of a service.

    .PARAMETER Name
        Indicates the service name to retrieve. Note that sometimes this is different from the
        display name.
        You can get a list of the services and their current state with the Get-Service cmdlet.
#>
function Get-TargetResource
{
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )

    if (Test-ServiceExists -Name $Name -ErrorAction SilentlyContinue)
    {
        Write-Verbose -Message 'Service exists - getting service'
        $service = Get-ServiceResource -Name $Name
        $serviceWmi = Get-Win32ServiceObject -Name $Name

        $builtInAccount = $null

        if ($serviceWmi.StartName -ieq 'LocalSystem')
        {
            $builtInAccount ='LocalSystem'
        }
        elseif ($serviceWmi.StartName -ieq 'NT Authority\NetworkService')
        {
            $builtInAccount = 'NetworkService'
        }
        elseif ($serviceWmi.StartName -ieq 'NT Authority\LocalService')
        {
            $builtInAccount = 'LocalService'
        }

        $dependencies = @()

        foreach ($serviceDependedOn in $service.ServicesDependedOn)
        {
            $dependencies += $serviceDependedOn.Name.ToString()
        }
        
        return @{
            Name            = $service.Name
            StartupType     = ConvertTo-StartupTypeString -StartMode $serviceWmi.StartMode
            BuiltInAccount  = $builtInAccount
            State           = $service.Status.ToString()
            Path            = $serviceWmi.PathName
            DisplayName     = $service.DisplayName
            Description     = $serviceWmi.Description
            DesktopInteract = $serviceWmi.DesktopInteract
            Dependencies    = $dependencies
            Ensure          = 'Present'
        }
    }
    else
    {
        Write-Verbose -Message 'Service with given name does not exist'
        return @{
            Name            = $service.Name
            Ensure          = 'Absent'
        }
    }
    
} # function Get-TargetResource

<#
    .SYNOPSIS
        Creates, updates or removes a service.

    .PARAMETER Name
        Indicates the name of the service to create, update, or remove.
        Note that sometimes this is different from the display name.
        You can get a list of the services and their current state with the Get-Service cmdlet.

    .PARAMETER Ensure
        Specifies whether the service should exist or not. Optional. Defaults to Present.

    .PARAMETER Path
        The path to the service executable file. Optional.

    .PARAMETER StartupType
        Indicates the startup type for the service. Optional.

    .PARAMETER BuiltInAccount
        Indicates the sign-in account to use for the service. Optional.

    .PARAMETER Credential
        The credential to run the service under. Optional.

    .PARAMETER DesktopInteract
        Indicates whether the service can create or communicate with a window on the desktop.
        Must be false for services not running as LocalSystem. Optional. Defaults to false.

    .PARAMETER State
        Indicates the state the service should be in. Optional. Defaults to Running.

    .PARAMETER DisplayName
        The display name of the service. Optional.

    .PARAMETER Description
        The description of the service. Optional.

    .PARAMETER Dependencies
        An array of strings indicating the names of the dependencies of the service. Optional.

    .PARAMETER StartupTimeout
        The time to wait for the service to start in milliseconds. Optional. Default is 3000.

    .PARAMETER TerminateTimeout
        The time to wait for the service to stop in milliseconds. Optional. Default is 3000.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure = 'Present',

        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [ValidateSet('Automatic', 'Manual', 'Disabled')]
        [String]
        $StartupType,

        [ValidateSet('LocalSystem', 'LocalService', 'NetworkService')]
        [String]
        $BuiltInAccount,

        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Boolean]
        $DesktopInteract,

        [ValidateSet('Running', 'Stopped')]
        [String]
        $State = 'Running',

        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,

        [ValidateNotNull()]
        [String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Dependencies,

        [uint32]
        $StartupTimeout = 30000,

        [uint32]
        $TerminateTimeout = 30000
    )

    if ($PSBoundParameters.ContainsKey('StartupType'))
    {
        # Throw an exception if the requested StartupType will conflict with the current state
        Test-StartupType -Name $Name -StartupType $StartupType -State $State
    }

    $serviceExists = Test-ServiceExists -Name $Name -ErrorAction SilentlyContinue

    if (($Ensure -eq 'Absent') -and $serviceExists)
    {
        # The service exists but needs to be deleted
        Stop-ServiceResource -Name $Name -TerminateTimeout $TerminateTimeout
        Remove-Service -Name $Name -TerminateTimeout $TerminateTimeout
        return
    }

    if ($PSBoundParameters.ContainsKey('Path') -and $serviceExists)
    {
        if (-not (Compare-ServicePath -Name $Name -Path $Path))
        {
            # Update the path - this is not yet supported, but could be
            Write-Verbose -Message ($LocalizedData.ServiceExecutablePathChangeNotSupported)
        }
    }
    elseif ($PSBoundParameters.ContainsKey('Path') -and -not $serviceExists)
    {
        $argumentsToNewService = @{}
        $argumentsToNewService.Add('Name', $Name)
        $argumentsToNewService.Add('BinaryPathName', $Path)

        try
        {
            New-Service @argumentsToNewService
        }
        catch
        {
            Write-Verbose -Message ($LocalizedData.TestStartupTypeMismatch `
            -f $argumentsToNewService['Name'], $_.Exception.Message)
            throw $_
        }
    }
    elseif (-not $PSBoundParameters.ContainsKey('Path') -and -not $serviceExists)
    {
        New-InvalidArgumentException `
            -Message ($LocalizedData.ServiceDoesNotExistPathMissingError -f $Name) `
            -ArgumentName 'Path'
    }

    # Update the parameters of the service
    $writeWritePropertiesArguments = @{
        Name = $Name
    }

    if ($PSBoundParameters.ContainsKey('Path'))
    {
        $writeWritePropertiesArguments['Path'] = $Path
    }

    if ($PSBoundParameters.ContainsKey('StartupType'))
    {
        $writeWritePropertiesArguments['StartupType'] = $StartupType
    }

    if ($PSBoundParameters.ContainsKey('BuiltInAccount'))
    {
        $writeWritePropertiesArguments['BuiltInAccount'] = $BuiltInAccount
    }

    if ($PSBoundParameters.ContainsKey('Credential'))
    {
        $writeWritePropertiesArguments['Credential'] = $Credential
    }

    if ($PSBoundParameters.ContainsKey('DesktopInteract'))
    {
        $writeWritePropertiesArguments['DesktopInteract'] = $DesktopInteract
    }

    if ($PSBoundParameters.ContainsKey('DisplayName'))
    {
        $writeWritePropertiesArguments['DisplayName'] = $DisplayName
    }

    if ($PSBoundParameters.ContainsKey('Description'))
    {
        $writeWritePropertiesArguments['Description'] = $Description
    }

    if ($PSBoundParameters.ContainsKey('Dependencies'))
    {
        $writeWritePropertiesArguments['Dependencies'] = $Dependencies
    }

    $requiresRestart = Write-WriteProperty @writeWritePropertiesArguments

    if ($State -eq 'Stopped')
    {
        # Ensure service is stopped
        Stop-ServiceResource -Name $Name -TerminateTimeout $TerminateTimeout
    }
    elseif ($State -eq 'Running')
    {
        # if the service needs to be restarted then go stop it first
        if ($requiresRestart)
        {
            Write-Verbose -Message ($LocalizedData.ServiceNeedsRestartMessage -f $Name)
            Stop-ServiceResource -Name $Name -TerminateTimeout $TerminateTimeout
        }

        Start-ServiceResource -Name $Name -StartupTimeout $StartupTimeout
    }
} # function Set-TargetResource


<#
    .SYNOPSIS
        Tests if a service is in the desired state.

    .PARAMETER Name
        The name of the service to be tested.
        Note that sometimes this is different from the display name.
        You can get a list of the services and their current state with the Get-Service cmdlet.

    .PARAMETER Ensure
        Specifies whether the service should exist or not. Optional. Defaults to Present.
        If set to Absent, the existence of the service is the only thing that will be checked.

    .PARAMETER Path
        Indicates what the path to the service executable file should be. Optional.

    .PARAMETER StartupType
        Indicates what the startup type for the service should be. Optional.

    .PARAMETER BuiltInAccount
        Indicates what the sign-in account to use for the service should be. Optional.

    .PARAMETER Credential
        Indicates the credential that the service should run under. Optional.

    .PARAMETER DesktopInteract
        Indicates if the service should be able to create or communicate with a window on the desktop.
        Must be false for services not running as LocalSystem. Optional.

    .PARAMETER State
        Indicates the state that the service should be in. Optional. Defaults to Running.

    .PARAMETER DisplayName
        The display name that the service should have. Optional.

    .PARAMETER Description
        The description that the service should have. Optional.

    .PARAMETER Dependencies
        An array of strings indicating the names of the dependencies that the service should have.
        Optional.

    .PARAMETER StartupTimeout
        Indicates what the time to wait for the service to start should be in milliseconds.
        Optional. Default is 3000.

    .PARAMETER TerminateTimeout
        Indicates what the time to wait for the service to stop should be in milliseconds.
        Optional. Default is 3000.
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
        $Name,
      
        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure = 'Present',

        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [ValidateSet('Automatic', 'Manual', 'Disabled')]
        [String]
        $StartupType,

        [ValidateSet('LocalSystem', 'LocalService', 'NetworkService')]
        [String]
        $BuiltInAccount,

        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Boolean]
        $DesktopInteract,

        [ValidateSet('Running', 'Stopped')]
        [String]
        $State = 'Running',

        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,

        [ValidateNotNull()]
        [String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Dependencies,

        [uint32]
        $StartupTimeout = 30000,

        [uint32]
        $TerminateTimeout = 30000
    )

    if ($PSBoundParameters.ContainsKey('StartupType'))
    {
        # Throw an exception if the requested StartupType will conflict with the current state
        Test-StartupType -Name $Name -StartupType $StartupType -State $State
    }

    $serviceExists = Test-ServiceExists -Name $Name -ErrorAction SilentlyContinue

    if ($Ensure -eq 'Absent')
    {
        Write-Verbose -Message 'Not checking other values since Ensure is set to Absent'
        return -not $serviceExists
    }

    if (-not $serviceExists)
    {
        Write-Verbose -Message 'Service does not exist'
        return $false
    }

    $service = Get-ServiceResource -Name $Name
    $serviceWmi = Get-Win32ServiceObject -Name $Name

    # Check the binary path
    if ($PSBoundParameters.ContainsKey('Path') -and `
        (-not (Compare-ServicePath -Name $Name -Path $Path)))
    {
        Write-Verbose -Message ($LocalizedData.TestBinaryPathMismatch `
            -f $serviceWmi.Name, $serviceWmi.PathName, $Path)
        return $false
    }

    # Check the optional parameters
    if ($PSBoundParameters.ContainsKey('DisplayName') -and `
        ($DisplayName -ne $serviceWmi.DisplayName))
    {
        Write-Verbose -Message ($LocalizedData.ParameterMismatch `
            -f 'DisplayName', $serviceWmi.DisplayName, $DisplayName)
        return $false
    }

    if ($PSBoundParameters.ContainsKey('Description') -and `
        ($Description -ne $serviceWmi.Description))
    {
        Write-Verbose -Message ($LocalizedData.ParameterMismatch `
            -f 'Description', $serviceWmi.Description, $Description)
        return $false
    }

    if ($PSBoundParameters.ContainsKey('Dependencies'))
    {
        $mismatchedDependencies = @(Compare-Object `
                                      -ReferenceObject $service.ServicesDependedOn `
                                      -DifferenceObject $Dependencies `
                                   )

        if ($mismatchedDependencies.Count -gt 0)
        {
            Write-Verbose -Message ($LocalizedData.ParameterMismatch `
                -f 'Dependencies', ($service.ServicesDependedOn -join ','), ($Dependencies -join ','))
            return $false
        }
    }

    if ($PSBoundParameters.ContainsKey('StartupType') -or `
        $PSBoundParameters.ContainsKey('BuiltInAccount') -or `
        $PSBoundParameters.ContainsKey('Credential') -or `
        $PSBoundParameters.ContainsKey('DesktopInteract'))
    {
        $getUserNameAndPasswordArgs = @{}

        if ($PSBoundParameters.ContainsKey('BuiltInAccount'))
        {
            $null = $getUserNameAndPasswordArgs.Add('BuiltInAccount', $BuiltInAccount)
        }

        if ($PSBoundParameters.ContainsKey('Credential'))
        {
            $null = $getUserNameAndPasswordArgs.Add('Credential', $Credential)
        }

        $userName, $password = Get-UserNameAndPassword @getUserNameAndPasswordArgs
        if ($null -ne $userName  -and `
            -not (Test-UserName -ServiceWmi $serviceWmi -Username $userName))
        {
            Write-Verbose -Message ($LocalizedData.TestUserNameMismatch `
                -f $serviceWmi.Name, $serviceWmi.StartName, $userName)
            return $false
        }

        if ($PSBoundParameters.ContainsKey('DesktopInteract') -and `
            ($serviceWmi.DesktopInteract -ne $DesktopInteract))
        {
            Write-Verbose -Message ($LocalizedData.TestDesktopInteractMismatch `
                -f $serviceWmi.Name, $serviceWmi.DesktopInteract, $DesktopInteract)
            return $false
        }

        if ($PSBoundParameters.ContainsKey('StartupType') -and `
            $serviceWmi.StartMode -ine (ConvertTo-StartModeString -StartupType $StartupType))
        {
            Write-Verbose -Message ($LocalizedData.TestStartupTypeMismatch `
                -f $serviceWmi.Name, $serviceWmi.StartMode, $StartupType)
            return $false
        }
    }

    if ($State -ne $service.Status)
    {
        Write-Verbose -Message ($LocalizedData.TestStateMismatch `
            -f $serviceWmi.Name, $service.Status, $State)
        return $false
    }

    return $true
} # function Test-TargetResource


<#
    .SYNOPSIS
        Tests if the given StartupType is valid with the given State parameter for the service with the given name.

    .PARAMETER Name
        The name of the service for which to check the StartupType and State
        (For error message only)

    .PARAMETER StartupType
        The StartupType to test.

    .PARAMETER State
        The State to test against. Default state is 'Running'
#>
function Test-StartupType
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Automatic', 'Manual', 'Disabled')]
        [String]
        $StartupType,

        [ValidateSet('Running', 'Stopped')]
        [String]
        $State = 'Running'
    )

    if ($State -eq 'Stopped')
    {
        if ($StartupType -eq 'Automatic')
        {
            # State = Stopped conflicts with Automatic or Delayed
            New-InvalidArgumentException `
                -Message ($LocalizedData.CannotStopServiceSetToStartAutomatically -f $Name) `
                -ArgumentName 'State'
        }
    }
    else
    {
        if ($StartupType -eq 'Disabled')
        {
            # State = Running conflicts with Disabled
            New-InvalidArgumentException `
                -Message ($LocalizedData.CannotStartAndDisable -f $Name) `
                -ArgumentName 'State'
        }
    }
} # function Test-StartupType

<#
    .SYNOPSIS
        Converts the StartupType String to the correct StartMode String returned
        in the Win32 service object.

    .PARAMETER StartupType
        The StartupType to convert.
#>
function ConvertTo-StartModeString
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Automatic', 'Manual', 'Disabled')]
        [String] $StartupType
    )

    if ($StartupType -eq 'Automatic')
    {
        return 'Auto'
    }

    return $StartupType
} # function ConvertTo-StartModeString

<#
    .SYNOPSIS
        Converts the StartMode string returned in a Win32_Service object to the format
        expected by this resource.

    .PARAMETER StartMode
        The StartMode string to convert.
#>
function ConvertTo-StartupTypeString
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Auto', 'Manual', 'Disabled')]
        $StartMode
    )

    if ($StartMode -eq 'Auto')
    {
        return 'Automatic'
    }

    return $StartMode
} # function ConvertTo-StartupTypeString

<#
    .SYNOPSIS
        Retrieves the Win32_Service object for the service with the given name.

    .PARAMETER Name
        The name of the service for which to get the Win32_Service object
#>
function Get-Win32ServiceObject
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        $Name
    )

    return Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'"
} # function Get-Win32ServiceObject

<#
    .SYNOPSIS
        Sets the StartupType property of the given service to the given value.

    .PARAMETER Win32ServiceObject
        The Win32_Service object to set the StartupType to.

    .PARAMETER StartupType
        The StartupType to set
#>
function Set-ServiceStartMode
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $Win32ServiceObject,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Automatic', 'Manual', 'Disabled')]
        [String]
        $StartupType
    )

    if ((ConvertTo-StartupTypeString -StartMode $Win32ServiceObject.StartMode) -ine $StartupType `
        -and $PSCmdlet.ShouldProcess($Win32ServiceObject.Name, $LocalizedData.SetStartupTypeWhatIf))
    {
        $changeServiceArguments = @{ StartMode = $StartupType }

        $changeResult = Invoke-CimMethod `
            -InputObject $Win32ServiceObject `
            -MethodName 'Change' `
            -Arguments $changeServiceArguments

        if ($changeResult.ReturnValue -ne 0)
        {
            $innerMessage = ($LocalizedData.MethodFailed `
                -f 'Change', 'Win32_Service', $changeResult.ReturnValue)
            $errorMessage = ($LocalizedData.ErrorChangingProperty `
                -f 'StartupType', $innerMessage)
            New-InvalidArgumentException `
                -Message $errorMessage `
                -ArgumentName 'StartupType'
        }
    }
} # function Set-ServiceStartMode

<#
    .SYNOPSIS
        Writes all write properties if not already correctly set.
        Logs errors and respects whatif

    .PARAMETER Name
        The name of the service to be updated.
        Note that sometimes this is different from the display name.
        You can get a list of the services and their current state with the Get-Service cmdlet.

    .PARAMETER Path
        The path to the service executable file. Optional.

    .PARAMETER StartupType
        Indicates the startup type for the service. Optional.

    .PARAMETER BuiltInAccount
        Indicates the sign-in account to use for the service. Optional.

    .PARAMETER Credential
        The credential to run the service under. Optional.

    .PARAMETER DesktopInteract
        The service can create or communicate with a window on the desktop.

    .PARAMETER DisplayName
        The display name of the service. Optional.

    .PARAMETER Description
        The description of the service. Optional.

    .PARAMETER Dependencies
        An array of strings indicating the names of the dependencies of the service. Optional.
#>
function Write-WriteProperty
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $Name,

        [System.String]
        [ValidateNotNullOrEmpty()]
        $Path,

        [System.String]
        [ValidateSet('Automatic', 'Manual', 'Disabled')]
        $StartupType,

        [System.String]
        [ValidateSet('LocalSystem', 'LocalService', 'NetworkService')]
        $BuiltInAccount,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        [ValidateNotNull()]
        $Credential,

        [Boolean]
        $DesktopInteract,

        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,

        [ValidateNotNull()]
        [String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Dependencies
    )

    $service = Get-Service -Name $Name
    $serviceWmi = Get-Win32ServiceObject -Name $Name
    $requiresRestart = $false

    # update binary path
    if ($PSBoundParameters.ContainsKey('Path'))
    {
        $writeBinaryArguments = @{
            ServiceWmi = $serviceWmi
            Path = $Path
        }

        $requiresRestart = ($requiresRestart -or (Write-BinaryProperty @writeBinaryArguments))
    }

    # update misc service properties
    $serviceprops = @{}

    if ($PSBoundParameters.ContainsKey('DisplayName') -and `
        ($DisplayName -ne $serviceWmi.DisplayName))
    {
        $serviceprops += @{ DisplayName = $DisplayName }
    }

    if ($PSBoundParameters.ContainsKey('Description') -and `
        ($Description -ne $serviceWmi.Description))
    {
        $serviceprops += @{ Description = $Description }
    }

    if ($serviceprops.count -gt 0)
    {
        $null = Set-Service -Name $Name @ServiceProps
    }

    # update the service dependencies if required
    if ($PSBoundParameters.ContainsKey('Dependencies'))
    {
        $mismatchedDependencies = @(Compare-Object `
                                    -ReferenceObject $service.ServicesDependedOn `
                                    -DifferenceObject $Dependencies)

        if ($mismatchedDependencies.Count -gt 0)
        {
            $changeServiceArguments = @{ ServiceDependencies = $Dependencies }

            $changeResult = Invoke-CimMethod `
                -InputObject $serviceWmi `
                -MethodName 'Change' `
                -Arguments $changeServiceArguments

            if ($changeResult.ReturnValue -ne 0)
            {
                $innerMessage = ($LocalizedData.MethodFailed `
                    -f 'Change', 'Win32_Service', $changeResult.ReturnValue)
                $errorMessage = ($LocalizedData.ErrorChangingProperty `
                    -f 'Dependencies', $innerMessage)

                New-InvalidArgumentException `
                    -Message $errorMessage `
                    -ArgumentName 'Dependencies'
            }
        }
    }

    # update credentials
    if ($PSBoundParameters.ContainsKey('BuiltInAccount') -or `
        $PSBoundParameters.ContainsKey('Credential') -or `
        $PSBoundParameters.ContainsKey('DesktopInteract'))
    {
        $writeCredentialPropertiesArguments = @{ 'ServiceWmi' = $serviceWmi }

        if ($PSBoundParameters.ContainsKey('BuiltInAccount'))
        {
            $null = $writeCredentialPropertiesArguments.Add('BuiltInAccount', $BuiltInAccount)
        }

        if ($PSBoundParameters.ContainsKey('Credential'))
        {
            $null = $writeCredentialPropertiesArguments.Add('Credential', $Credential)
        }

        if ($PSBoundParameters.ContainsKey('DesktopInteract'))
        {
            $null = $writeCredentialPropertiesArguments.Add('DesktopInteract', $DesktopInteract)
        }

        Write-CredentialProperty @writeCredentialPropertiesArguments
    }

    # Update startup type
    if ($PSBoundParameters.ContainsKey('StartupType'))
    {
        Set-ServiceStartMode -Win32ServiceObject $serviceWmi -StartupType $StartupType
    }

    # Return restart status
    return $requiresRestart

} # function Write-WriteProperty

<#
    .SYNOPSIS
        Writes credential properties if not already correctly set.
        Logs errors and respects whatif

    .PARAMETER ServiceWmi
        The WMI service of which to set the credentials.

    .PARAMETER BuiltInAccount
        Indicates the sign-in account to use for the service. Optional.

    .PARAMETER Credential
        The credential to update. Optional.

    .PARAMETER DesktopInteract
        Indicates whether the service can create or communicate with a window on the desktop.
        Must be false for services not running as LocalSystem. Optional.
#>
function Write-CredentialProperty
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $ServiceWmi,

        [System.String]
        [ValidateSet('LocalSystem', 'LocalService', 'NetworkService')]
        $BuiltInAccount,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Boolean]
        $DesktopInteract
    )

    if (-not $PSBoundParameters.ContainsKey('Credential') -and `
        -not $PSBoundParameters.ContainsKey('BuiltInAccount') -and `
        -not $PSBoundParameters.ContainsKey('DesktopInteract'))
    {
        # No change parameters actually passed - nothing to change
        return
    }

    # These are the arguments to chnage on the service
    $changeArgs = @{}

    # Get the Username and Password to change to (if applicable)
    $getUserNameAndPasswordArgs = @{}

    if ($PSBoundParameters.ContainsKey('BuiltInAccount'))
    {
        $null = $getUserNameAndPasswordArgs.Add('BuiltInAccount',$BuiltInAccount)
    }

    if ($PSBoundParameters.ContainsKey('Credential'))
    {
        $null = $getUserNameAndPasswordArgs.Add('Credential',$Credential)
    }

    if ($getUserNameAndPasswordArgs.Count -gt 1)
    {
        # Both Credentials and BuiltInAccount were set - throw
        New-InvalidArgumentException `
            -Message ($LocalizedData.OnlyOneParameterCanBeSpecified `
                -f 'Credential', 'BuiltInAccount') `
            -ArgumentName 'BuiltInAccount'
    }

    $userName, $password = Get-UserNameAndPassword @getUserNameAndPasswordArgs

    # If the user account needs to be changed add it to the arguments
    if (($null -ne $userName) -and `
        -not (Test-UserName -ServiceWmi $ServiceWmi -Username $userName))
    {
        # A specific user account was passed so set log on as a service policy
        if ($PSBoundParameters.ContainsKey('Credential'))
        {
            Set-LogOnAsServicePolicy -Username $userName
        }

        $changeArgs += @{
            StartName = $userName
            StartPassword = $password
        }
    }

    # The desktop interact flag was passed to set that value
    if ($PSBoundParameters.ContainsKey('DesktopInteract') -and `
        ($DesktopInteract -ne $ServiceWmi.DesktopInteract))
    {
        $changeArgs.DesktopInteract = $DesktopInteract
    }

    if ($changeArgs.Count -gt 0)
    {
        $ret = Invoke-CimMethod `
            -InputObject $ServiceWmi `
            -MethodName 'Change' `
            -Arguments $changeArgs

        if ($ret.ReturnValue -ne 0)
        {
            $innerMessage = ($LocalizedData.MethodFailed `
                -f 'Change', 'Win32_Service',$ret.ReturnValue)
            $errorMessage = ($LocalizedData.ErrorChangingProperty `
                -f 'Credential', $innerMessage)

            New-InvalidArgumentException `
                -Message $errorMessage `
                -ArgumentName 'Credential'
        }
    }
} # function Write-CredentialProperty

<#
    .SYNOPSIS
        Writes binary path if not already correctly set. Logs errors.
        returns false if the path is already set and true if it was not set.

    .PARAMETER ServiceWmi
        The WMI service of which to set the path

    .PARAMETER Path
        The Path to set for the service. Optional.
        
#>
function Write-BinaryProperty
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $ServiceWmi,

        [System.String]
        [ValidateNotNullOrEmpty()]
        $Path
    )

    if ($ServiceWmi.PathName -eq $Path)
    {
        return $false
    }

    $changeServiceArguments = @{ PathName = $Path }

    $changeResult = Invoke-CimMethod `
        -InputObject $serviceWmi `
        -MethodName 'Change' `
        -Arguments $changeServiceArguments

    if ($changeResult.ReturnValue -ne 0)
    {
        $innerMessage = ($LocalizedData.MethodFailed `
            -f 'Change', 'Win32_Service', $changeResult.ReturnValue)
        $errorMessage = ($LocalizedData.ErrorChangingProperty `
            -f 'Binary Path', $innerMessage)

        New-InvalidArgumentException `
            -Message $errorMessage `
            -ArgumentName 'Path'
    }

    return $true
} # function Write-BinaryProperty

<#
    .SYNOPSIS
        Returns true if the service's StartName matches $UserName

    .PARAMETER ServiceWmi
        The WMI service of which to check the username.

    .PARAMETER UserName
        The username of the user to compare the one in the WMI object with.
#>
function Test-UserName
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $ServiceWmi,

        [String]
        $UserName
    )

    return  ((Resolve-UserName -UserName $ServiceWmi.StartName) -ieq $UserName)
} # function Test-UserName

<#
    .SYNOPSIS
        If BuiltInAccount is provided, this will return the resolved username from that.
        If Credential is provided, this will return the resolved username and password from that.
        If nothing is provided, this will return null for both username and password.

    .PARAMETER BuiltInAccount
        The built in account to extract the username from. Optional

    .PARAMETER Credential
        The Credential to extract the username and password from. Optional.

    .OUTPUTS
        A tuple containing: [String] Username, [String] Password.
#>
function Get-UserNameAndPassword
{
    [CmdletBinding()]
    param
    (
        [System.String]
        [ValidateSet('LocalSystem', 'LocalService', 'NetworkService')]
        $BuiltInAccount,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    if ($PSBoundParameters.ContainsKey('BuiltInAccount'))
    {
        return (Resolve-UserName -UserName $BuiltInAccount.ToString()), $null
    }

    if ($PSBoundParameters.ContainsKey('Credential'))
    {
        return (Resolve-UserName -UserName $Credential.UserName), `
                $Credential.GetNetworkCredential().Password
    }

    return $null, $null
} # function Get-UserNameAndPassword

<#
    .SYNOPSIS
        Deletes a service

    .PARAMETER Name
        The name of the service to delete.

    .PARAMETER TerminateTimeout
        The number of milliseconds to wait for the service to be removed.
        Optional. Default value is 3000.
#>
function Remove-Service
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $Name,

        [ValidateNotNullOrEmpty()]
        [Int]
        $TerminateTimeout = 30000
    )

    # Delete the service
    & 'sc.exe' 'delete' "$Name"

    # Wait for the service to be deleted
    $serviceDeletedSuccessfully = $false
    $start = [DateTime]::Now

    while (-not $serviceDeletedSuccessfully -and `
          ([DateTime]::Now - $start).TotalMilliseconds -lt $TerminateTimeout)
    {
        if (-not (Test-ServiceExists -Name $Name))
        {
            $serviceDeletedSuccessfully = $true
            break
        }

        # The service was not deleted so wait a second and try again (unless TerminateTimeout is hit)
        Start-Sleep -Seconds 1
        Write-Verbose -Message ($LocalizedData.TryDeleteAgain)
    }

    if ($serviceDeletedSuccessfully)
    {
        Write-Verbose -Message ($LocalizedData.ServiceDeletedSuccessfully -f $Name)
    }
    else
    {
        # Service was not deleted
        New-InvalidOperationException `
            -Message ($LocalizedData.ErrorDeletingService -f $Name)
    }
} # function Remove-Service

<#
    .SYNOPSIS
        Starts a service if it is not already running.

    .PARAMETER Name
        The name of the service to start.

    .PARAMETER StartupTimeout
        The amount of time to wait for the service to start.
#>
function Start-ServiceResource
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [uint32]
        $StartupTimeout
    )

    $service = Get-ServiceResource -Name $Name

    if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running)
    {
        Write-Verbose -Message ($LocalizedData.ServiceAlreadyStarted -f $service.Name)
        return
    }

    if ($PSCmdlet.ShouldProcess($Name, $LocalizedData.StartServiceWhatIf))
    {
        try
        {
            $service.Start()
            $waitTimeSpan = New-Object `
                -TypeName TimeSpan `
                -ArgumentList ($StartupTimeout * 10000)
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, `
                                    $waitTimeSpan)
        }
        catch
        {
            $servicePath = (Get-CimInstance -Class win32_service |
                Where-Object { $_.Name -eq $Name }).PathName
            $errorMessage = ($LocalizedData.ErrorStartingService `
                -f $service.Name, $servicePath, $_.Exception.Message)
            New-InvalidOperationException -Message $errorMessage
        }

        Write-Verbose -Message ($LocalizedData.ServiceStarted -f $service.Name)
    }
} # function Start-ServiceResource

<#
    .SYNOPSIS
        Stops a service if it is not already stopped.

    .PARAMETER Name
        The name of the service to stop.

    .PARAMETER TerminateTimeout
        The amount of time to wait for the service to stop.
#>
function Stop-ServiceResource
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [uint32]
        $TerminateTimeout
    )

    $service = Get-ServiceResource -Name $Name

    if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped)
    {
        Write-Verbose -Message ($LocalizedData.ServiceAlreadyStopped -f $service.Name)
        return
    }

    if ($PSCmdlet.ShouldProcess($Name, $LocalizedData.StopServiceWhatIf))
    {
        try
        {
            $service.Stop()
            $waitTimeSpan = New-Object `
                -TypeName TimeSpan `
                -ArgumentList ($TerminateTimeout * 10000)
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, `
                                    $waitTimeSpan)
        }
        catch
        {
            Write-Verbose -Message ($LocalizedData.ErrorStoppingService `
                -f $service.Name, $_.Exception.Message)
            throw $_
        }

        Write-Verbose -Message ($LocalizedData.ServiceStopped -f $service.Name)
    }
} # function Stop-ServiceResource

<#
    .SYNOPSIS
        Converts the username returned from a Win32_service object to the format
        expected by this resource.

    .PARAMETER UserName
        The Username to convert.
#>

function Resolve-UserName
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $UserName
    )

    switch ($Username)
    {
        'NetworkService'
        {
            return 'NT Authority\NetworkService'
        }
        'LocalService'
        {
            return 'NT Authority\LocalService'
        }
        'LocalSystem'
        {
            return '.\LocalSystem'
        }
        default
        {
            if ($UserName.IndexOf('\') -eq -1)
            {
                return '.\' + $UserName
            }
        }
    }

    return $UserName
} # function Resolve-UserName

<#
    .SYNOPSIS
        Tests if a service with the given name exists

    .PARAMETER Name
        The name of the service to test for.
#>
function Test-ServiceExists
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    return ($null -ne $service)

} # function Test-ServiceExists

<#
    .SYNOPSIS
        Compares a path to the existing service path.
        Returns true when the given path is the same as the existing service path, false otherwise.

    .PARAMETER Name
        The name of the existing service for which to check the path.

    .PARAMETER Path
        The path to check against.
#>
function Compare-ServicePath
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )

    $existingServicePath = (Get-CimInstance -Class win32_service |
        Where-Object { $_.Name -eq $Name }).PathName
    $stringCompareResult = [String]::Compare($Path, $existingServicePath, `
                            [System.Globalization.CultureInfo]::CurrentUICulture)

    return ($stringCompareResult -eq 0)
} # function Compare-ServicePath

<#
    .SYNOPSIS
        Retrieves the service with the given name.

    .PARAMETER Name
        The name of the service to retrieve
#>
function Get-ServiceResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name
    )

    $service = Get-Service -Name $Name -ErrorAction Ignore
    if ($null -eq $service)
    {
        New-InvalidArgumentException `
            -Message ($LocalizedData.ServiceNotFound -f $Name) `
            -ArgumentName 'Name'
    }

    return $service

} # function Get-ServiceResource

<#
    .SYNOPSIS
        Grants log on as service right to the given user

    .PARAMETER UserName
        The name of the user to grant log on as a service right to
#>
function Set-LogOnAsServicePolicy
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserName
    )

    $logOnAsServiceText = @"
        namespace LogOnAsServiceHelper
        {
            using Microsoft.Win32.SafeHandles;
            using System;
            using System.Runtime.ConstrainedExecution;
            using System.Runtime.InteropServices;
            using System.Security;

            public class NativeMethods
            {
                #region constants
                // from ntlsa.h
                private const int POLICY_LOOKUP_NAMES = 0x00000800;
                private const int POLICY_CREATE_ACCOUNT = 0x00000010;
                private const uint ACCOUNT_ADJUST_SYSTEM_ACCESS = 0x00000008;
                private const uint ACCOUNT_VIEW = 0x00000001;
                private const uint SECURITY_ACCESS_SERVICE_LOGON = 0x00000010;

                // from LsaUtils.h
                private const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;

                // from lmcons.h
                private const int UNLEN = 256;
                private const int DNLEN = 15;

                // Extra characteres for "\","@" etc.
                private const int EXTRA_LENGTH = 3;
                #endregion constants

                #region interop structures
                /// <summary>
                /// Used to open a policy, but not containing anything meaqningful
                /// </summary>
                [StructLayout(LayoutKind.Sequential)]
                private struct LSA_OBJECT_ATTRIBUTES
                {
                    public UInt32 Length;
                    public IntPtr RootDirectory;
                    public IntPtr ObjectName;
                    public UInt32 Attributes;
                    public IntPtr SecurityDescriptor;
                    public IntPtr SecurityQualityOfService;

                    public void Initialize()
                    {
                        this.Length = 0;
                        this.RootDirectory = IntPtr.Zero;
                        this.ObjectName = IntPtr.Zero;
                        this.Attributes = 0;
                        this.SecurityDescriptor = IntPtr.Zero;
                        this.SecurityQualityOfService = IntPtr.Zero;
                    }
                }

                /// <summary>
                /// LSA string
                /// </summary>
                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                private struct LSA_UNICODE_STRING
                {
                    internal ushort Length;
                    internal ushort MaximumLength;
                    [MarshalAs(UnmanagedType.LPWStr)]
                    internal string Buffer;

                    internal void Set(string src)
                    {
                        this.Buffer = src;
                        this.Length = (ushort)(src.Length * sizeof(char));
                        this.MaximumLength = (ushort)(this.Length + sizeof(char));
                    }
                }

                /// <summary>
                /// Structure used as the last parameter for LSALookupNames
                /// </summary>
                [StructLayout(LayoutKind.Sequential)]
                private struct LSA_TRANSLATED_SID2
                {
                    public uint Use;
                    public IntPtr SID;
                    public int DomainIndex;
                    public uint Flags;
                };
                #endregion interop structures

                #region safe handles
                /// <summary>
                /// Handle for LSA objects including Policy and Account
                /// </summary>
                private class LsaSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
                {
                    [DllImport("advapi32.dll")]
                    private static extern uint LsaClose(IntPtr ObjectHandle);

                    /// <summary>
                    /// Prevents a default instance of the LsaPolicySafeHAndle class from being created.
                    /// </summary>
                    private LsaSafeHandle(): base(true)
                    {
                    }

                    /// <summary>
                    /// Calls NativeMethods.CloseHandle(handle)
                    /// </summary>
                    /// <returns>the return of NativeMethods.CloseHandle(handle)</returns>
                    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
                    protected override bool ReleaseHandle()
                    {
                        long returnValue = LsaSafeHandle.LsaClose(this.handle);
                        return returnValue != 0;

                    }
                }

                /// <summary>
                /// Handle for IntPtrs returned from Lsa calls that have to be freed with
                /// LsaFreeMemory
                /// </summary>
                private class SafeLsaMemoryHandle : SafeHandleZeroOrMinusOneIsInvalid
                {
                    [DllImport("advapi32")]
                    internal static extern int LsaFreeMemory(IntPtr Buffer);

                    private SafeLsaMemoryHandle() : base(true) { }

                    private SafeLsaMemoryHandle(IntPtr handle)
                        : base(true)
                    {
                        SetHandle(handle);
                    }

                    private static SafeLsaMemoryHandle InvalidHandle
                    {
                        get { return new SafeLsaMemoryHandle(IntPtr.Zero); }
                    }

                    override protected bool ReleaseHandle()
                    {
                        return SafeLsaMemoryHandle.LsaFreeMemory(handle) == 0;
                    }

                    internal IntPtr Memory
                    {
                        get
                        {
                            return this.handle;
                        }
                    }
                }
                #endregion safe handles

                #region interop function declarations
                /// <summary>
                /// Opens LSA Policy
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaOpenPolicy(
                    IntPtr SystemName,
                    ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
                    uint DesiredAccess,
                    out LsaSafeHandle PolicyHandle
                );

                /// <summary>
                /// Convert the name into a SID which is used in remaining calls
                /// </summary>
                [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
                private static extern uint LsaLookupNames2(
                    LsaSafeHandle PolicyHandle,
                    uint Flags,
                    uint Count,
                    LSA_UNICODE_STRING[] Names,
                    out SafeLsaMemoryHandle ReferencedDomains,
                    out SafeLsaMemoryHandle Sids
                );

                /// <summary>
                /// Opens the LSA account corresponding to the user's SID
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaOpenAccount(
                    LsaSafeHandle PolicyHandle,
                    IntPtr Sid,
                    uint Access,
                    out LsaSafeHandle AccountHandle);

                /// <summary>
                /// Creates an LSA account corresponding to the user's SID
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaCreateAccount(
                    LsaSafeHandle PolicyHandle,
                    IntPtr Sid,
                    uint Access,
                    out LsaSafeHandle AccountHandle);

                /// <summary>
                /// Gets the LSA Account access
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaGetSystemAccessAccount(
                    LsaSafeHandle AccountHandle,
                    out uint SystemAccess);

                /// <summary>
                /// Sets the LSA Account access
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaSetSystemAccessAccount(
                    LsaSafeHandle AccountHandle,
                    uint SystemAccess);
                #endregion interop function declarations

                /// <summary>
                /// Sets the Log On As A Service Policy for <paramref name="userName"/>, if not already set.
                /// </summary>
                /// <param name="userName">the user name we want to allow logging on as a service</param>
                /// <exception cref="ArgumentNullException">If the <paramref name="userName"/> is null or empty.</exception>
                /// <exception cref="InvalidOperationException">In the following cases:
                ///     Failure opening the LSA Policy.
                ///     The <paramref name="userName"/> is too large.
                ///     Failure looking up the user name.
                ///     Failure opening LSA account (other than account not found).
                ///     Failure creating LSA account.
                ///     Failure getting LSA account policy access.
                ///     Failure setting LSA account policy access.
                /// </exception>
                public static void SetLogOnAsServicePolicy(string userName)
                {
                    if (String.IsNullOrEmpty(userName))
                    {
                        throw new ArgumentNullException("userName");
                    }

                    LSA_OBJECT_ATTRIBUTES objectAttributes = new LSA_OBJECT_ATTRIBUTES();
                    objectAttributes.Initialize();

                    // All handles are delcared in advance so they can be closed on finally
                    LsaSafeHandle policyHandle = null;
                    SafeLsaMemoryHandle referencedDomains = null;
                    SafeLsaMemoryHandle sids = null;
                    LsaSafeHandle accountHandle = null;

                    try
                    {
                        uint status = LsaOpenPolicy(
                            IntPtr.Zero,
                            ref objectAttributes,
                            POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT,
                            out policyHandle);

                        if (status != 0)
                        {
                            throw new InvalidOperationException("CannotOpenPolicyErrorMessage");
                        }

                        // Unicode strings have a maximum length of 32KB. We don't want to create
                        // LSA strings with more than that. User lengths are much smaller so this check
                        // ensures userName's length is useful
                        if (userName.Length > UNLEN + DNLEN + EXTRA_LENGTH)
                        {
                            throw new InvalidOperationException("UserNameTooLongErrorMessage");
                        }

                        LSA_UNICODE_STRING lsaUserName = new LSA_UNICODE_STRING();
                        lsaUserName.Set(userName);

                        LSA_UNICODE_STRING[] names = new LSA_UNICODE_STRING[1];
                        names[0].Set(userName);

                        status = LsaLookupNames2(
                            policyHandle,
                            0,
                            1,
                            new LSA_UNICODE_STRING[] { lsaUserName },
                            out referencedDomains,
                            out sids);

                        if (status != 0)
                        {
                            throw new InvalidOperationException("CannotLookupNamesErrorMessage");
                        }

                        LSA_TRANSLATED_SID2 sid = (LSA_TRANSLATED_SID2)Marshal.PtrToStructure(sids.Memory, typeof(LSA_TRANSLATED_SID2));

                        status = LsaOpenAccount(policyHandle,
                                            sid.SID,
                                            ACCOUNT_VIEW | ACCOUNT_ADJUST_SYSTEM_ACCESS,
                                            out accountHandle);

                        uint currentAccess = 0;

                        if (status == 0)
                        {
                            status = LsaGetSystemAccessAccount(accountHandle, out currentAccess);

                            if (status != 0)
                            {
                                throw new InvalidOperationException("CannotGetAccountAccessErrorMessage");
                            }

                        }
                        else if (status == STATUS_OBJECT_NAME_NOT_FOUND)
                        {
                            status = LsaCreateAccount(
                                policyHandle,
                                sid.SID,
                                ACCOUNT_ADJUST_SYSTEM_ACCESS,
                                out accountHandle);

                            if (status != 0)
                            {
                                throw new InvalidOperationException("CannotCreateAccountAccessErrorMessage");
                            }
                        }
                        else
                        {
                            throw new InvalidOperationException("CannotOpenAccountErrorMessage");
                        }

                        if ((currentAccess & SECURITY_ACCESS_SERVICE_LOGON) == 0)
                        {
                            status = LsaSetSystemAccessAccount(
                                accountHandle,
                                currentAccess | SECURITY_ACCESS_SERVICE_LOGON);
                            if (status != 0)
                            {
                                throw new InvalidOperationException("CannotSetAccountAccessErrorMessage");
                            }
                        }
                    }
                    finally
                    {
                        if (policyHandle != null) { policyHandle.Close(); }
                        if (referencedDomains != null) { referencedDomains.Close(); }
                        if (sids != null) { sids.Close(); }
                        if (accountHandle != null) { accountHandle.Close(); }
                    }
                }
            }
        }
"@

    try
    {
        $null = [LogOnAsServiceHelper.NativeMethods]
    }
    catch
    {
        $logOnAsServiceText = $logOnAsServiceText.Replace('CannotOpenPolicyErrorMessage', `
            $LocalizedData.CannotOpenPolicyErrorMessage)
        $logOnAsServiceText = $logOnAsServiceText.Replace('UserNameTooLongErrorMessage', `
            $LocalizedData.UserNameTooLongErrorMessage)
        $logOnAsServiceText = $logOnAsServiceText.Replace('CannotLookupNamesErrorMessage', `
            $LocalizedData.CannotLookupNamesErrorMessage)
        $logOnAsServiceText = $logOnAsServiceText.Replace('CannotOpenAccountErrorMessage', `
            $LocalizedData.CannotOpenAccountErrorMessage)
        $logOnAsServiceText = $logOnAsServiceText.Replace('CannotCreateAccountAccessErrorMessage', `
            $LocalizedData.CannotCreateAccountAccessErrorMessage)
        $logOnAsServiceText = $logOnAsServiceText.Replace('CannotGetAccountAccessErrorMessage', `
            $LocalizedData.CannotGetAccountAccessErrorMessage)
        $logOnAsServiceText = $logOnAsServiceText.Replace('CannotSetAccountAccessErrorMessage', `
            $LocalizedData.CannotSetAccountAccessErrorMessage)
        $null = Add-Type $logOnAsServiceText -PassThru -Debug:$false
    }

    if ($UserName.StartsWith('.\'))
    {
        $UserName = $UserName.Substring(2)
    }

    try
    {
        [LogOnAsServiceHelper.NativeMethods]::SetLogOnAsServicePolicy($UserName)
    }
    catch
    {
        $message = ($LocalizedData.ErrorSettingLogOnAsServiceRightsForUser `
            -f $UserName, $_.Exception.Message)
        New-InvalidOperationException -Message $message
    }
} # function Set-LogOnAsServicePolicy

Export-ModuleMember -Function *-TargetResource
