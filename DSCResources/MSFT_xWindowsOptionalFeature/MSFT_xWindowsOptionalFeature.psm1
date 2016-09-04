# This module contains functions for Desired State Configuration Windows Optional Feature provider.
# It enables configuring optional features on Windows Client SKUs.

# Suppress PSSA issue PSAvoidGlobalVars because setting $global:DSCMachineStatus must be used
# for this resource to notify the LCM about a required restart to complete the action.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
param ()

# Fallback message strings in en-US
DATA localizedData
{
    # culture = "en-US"
    ConvertFrom-StringData @'
        DismNotAvailable = PowerShell module Dism could not be imported.
        NotSupportedSku = This Resource is only available for Windows Client or Server 2012 (or later).
        ElevationRequired = This Resource requires to be run as an Administrator.
        ValidatingPrerequisites = Validating prerequisites...
        CouldNotCovertFeatureState = Could not convert feature state '{0}' into Absent/Present.
        EnsureNotSupported = The value '{0}' for property Ensure is not supported.
        RestartNeeded = Target machine needs to be restarted.
        GetTargetResourceStartMessage = Begin executing Get functionality on the {0} feature.
        GetTargetResourceEndMessage = End executing Get functionality on the {0} feature.
        SetTargetResourceStartMessage = Begin executing Set functionality on the {0} feature.
        SetTargetResourceEndMessage = End executing Set functionality on the {0} feature.
        TestTargetResourceStartMessage = Begin executing Test functionality on the {0} feature.
        TestTargetResourceEndMessage = End executing Test functionality on the {0} feature.
        FeatureInstalled = Installed feature {0}.
        FeatureUninstalled = Uninstalled feature {0}.
        EnableFeature = Enable a Windows optional feature
        DisableFeature = Disable a Windows optional feature
'@
}
Import-Module Dism -Force -ErrorAction SilentlyContinue

<#
    .SYNOPSIS
    Gets the state of a Windows optional feature

    .PARAMETER Name
    Specify the name of the Windows optional feature
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    Write-Verbose ($LocalizedData.GetTargetResourceStartMessage -f $Name)

    Assert-ResourcePrerequisitesValid

    $result = Dism\Get-WindowsOptionalFeature -FeatureName $Name -Online

    $returnValue = @{
        LogPath = $result.LogPath
        Ensure = Convert-FeatureStateToEnsure $result.State
        CustomProperties =
            Get-SerializedCustomPropertyList -CustomProperties $result.CustomProperties
        Name = $result.FeatureName
        LogLevel = $result.LogLevel
        Description = $result.Description
        DisplayName = $result.DisplayName
    }

    $returnValue

    Write-Verbose ($LocalizedData.GetTargetResourceEndMessage -f $Name)
}

<#
    .SYNOPSIS
    Serializes a list of CustomProperty objects serialized into [System.String[]]

    .PARAMETER CustomProperties
    Provide a list of CustomProperty objects to be serialized
#>
function Get-SerializedCustomPropertyList
{
    param
    (
        $CustomProperties
    )

    $CustomProperties | Where-Object { $_ -ne $null } |
        ForEach-Object { "Name = $($_.Name), Value = $($_.Value), Path = $($_.Path)" }
}

<#
    .SYNOPSIS
    Converts state returned by Dism Get-WindowsOptionalFeature cmdlet to Present/Absent

    .PARAMETER State
    Provide a valid state Enabled or Disabled to be converted to either Present or Absent
#>
function Convert-FeatureStateToEnsure
{
    param
    (
        $State
    )

    if ($state -eq 'Disabled')
    {
        'Absent'
    }
    elseif ($state -eq 'Enabled')
    {
        'Present'
    }
    else
    {
        Write-Warning ($LocalizedData.CouldNotCovertFeatureState -f $state)
        $state
    }
}

<#
    .SYNOPSIS
    Enable or disable a Windows optional feature

    .PARAMETER Source
    Not implemented.

    .PARAMETER RemoveFilesOnDisable
    Set to $true to remove all files associated with the feature when it is disabled (that is,
    when Ensure is set to "Absent").

    .PARAMETER LogPath
    The path to a log file where you want the resource provider to log the operation.

    .PARAMETER Ensure
    Specifies whether the feature is enabled. To ensure that the feature is enabled, set this
    property to "Present". To ensure that the feature is disabled, set the property to "Absent".

    .PARAMETER NoWindowsUpdateCheck
    Specifies whether DISM contacts Windows Update (WU) when searching for the source files to
    enable a feature. If $true, DISM does not contact WU.

    .PARAMETER Name
    Indicates the name of the feature that you want to ensure is enabled or disabled.

    .PARAMETER LogLevel
    The maximum output level shown in the logs. The accepted values are: "ErrorsOnly" (only errors
    are logged), "ErrorsAndWarning" (errors and warnings are logged), and
    "ErrorsAndWarningAndInformation" (errors, warnings, and debug information are logged).
#>
function Set-TargetResource
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param
    (
        [System.String[]]
        $Source,

        [System.Boolean]
        $RemoveFilesOnDisable,

        [System.String]
        $LogPath,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure = "Present",

        [System.Boolean]
        $NoWindowsUpdateCheck,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [ValidateSet("ErrorsOnly","ErrorsAndWarning","ErrorsAndWarningAndInformation")]
        [System.String]
        $LogLevel
    )

    Write-Verbose ($LocalizedData.SetTargetResourceStartMessage -f $Name)

    Assert-ResourcePrerequisitesValid

    switch ($LogLevel)
    {
        'ErrorsOnly' { $DismLogLevel = 'Errors' }
        'ErrorsAndWarning' { $DismLogLevel = 'Warnings' }
        'ErrorsAndWarningAndInformation' { $DismLogLevel = 'WarningsInfo' }
        '' { $DismLogLevel = 'WarningsInfo' }
    }

    # Construct splatting hashtable for Dism cmdlets
    $cmdletParams = $PSBoundParameters.psobject.Copy()
    $cmdletParams['FeatureName'] = $Name
    $cmdletParams['Online'] = $true
    $cmdletParams['LogLevel'] = $DismLogLevel
    $cmdletParams['NoRestart'] = $true
    foreach ($key in @('Name', 'Ensure','RemoveFilesOnDisable','NoWindowsUpdateCheck'))
    {
        if ($cmdletParams.ContainsKey($key))
        {
           $cmdletParams.Remove($key)
        }
    }

    if ($Ensure -eq 'Present')
    {
        if ($PSCmdlet.ShouldProcess($Name, $LocalizedData.EnableFeature))
        {
            if ($NoWindowsUpdateCheck)
            {
                $cmdletParams['LimitAccess'] =  $true
            }
            $feature = Dism\Enable-WindowsOptionalFeature @cmdletParams
        }

        Write-Verbose ($LocalizedData.FeatureInstalled -f $Name)
    }
    elseif ($Ensure -eq 'Absent')
    {
        if ($PSCmdlet.ShouldProcess($Name, $LocalizedData.DisableFeature))
        {
            if ($RemoveFilesOnDisable)
            {
                $cmdletParams['Remove'] = $true
            }
            $feature = Dism\Disable-WindowsOptionalFeature @cmdletParams
        }

        Write-Verbose ($LocalizedData.FeatureUninstalled -f $Name)
    }
    else
    {
        throw ($LocalizedData.EnsureNotSupported -f $Ensure)
    }

    ## Indicate we need a restart as needed
    if ($feature.RestartNeeded)
    {
        Write-Verbose $LocalizedData.RestartNeeded
        $global:DSCMachineStatus = 1
    }

    Write-Verbose ($LocalizedData.SetTargetResourceEndMessage -f $Name)
}

<#
    .SYNOPSIS
    Test if a Windows optional feature is in the desired state (enabled or disabled)

    .PARAMETER Source
    Not implemented.

    .PARAMETER RemoveFilesOnDisable
    Set to $true to remove all files associated with the feature when it is disabled (that is,
    when Ensure is set to "Absent").

    .PARAMETER LogPath
    The path to a log file where you want the resource provider to log the operation.

    .PARAMETER Ensure
    Specifies whether the feature is enabled.     To ensure that the feature is enabled, set this
    property to "Present". To ensure that the feature is disabled, set the property to "Absent".

    .PARAMETER NoWindowsUpdateCheck
    Specifies whether DISM contacts Windows Update (WU) when searching for the source files to
    enable a feature. If $true, DISM does not contact WU.

    .PARAMETER Name
    Indicates the name of the feature that you want to ensure is enabled or disabled.

    .PARAMETER LogLevel
    The maximum output level shown in the logs. The accepted values are: "ErrorsOnly" (only errors
    are logged), "ErrorsAndWarning" (errors and warnings are logged), and
    "ErrorsAndWarningAndInformation" (errors, warnings, and debug information are logged).
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.String[]]
        $Source,

        [System.Boolean]
        $RemoveFilesOnDisable,

        [System.String]
        $LogPath,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure = "Present",

        [System.Boolean]
        $NoWindowsUpdateCheck,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [ValidateSet("ErrorsOnly","ErrorsAndWarning","ErrorsAndWarningAndInformation")]
        [System.String]
        $LogLevel
    )

    Write-Verbose ($LocalizedData.TestTargetResourceStartMessage -f $Name)

    Assert-ResourcePrerequisitesValid

    $featureState = Dism\Get-WindowsOptionalFeature -FeatureName $Name -Online
    [bool] $result = $false

    if ($null -eq $featureState)
    {
        $result = $Ensure -eq 'Absent'
    }
    if (($featureState.State -eq 'Disabled' -and $Ensure -eq 'Absent')`
        -or ($featureState.State -eq 'Enabled' -and $Ensure -eq 'Present'))
    {
        $result = $true
    }
    Write-Verbose ($LocalizedData.TestTargetResourceEndMessage -f $Name)
    return $result
}

<#
    .SYNOPSIS
    Helper function to test if the MSFT_WindowsOptionalFeature is supported on the target machine.
#>
function Assert-ResourcePrerequisitesValid
{
    Write-Verbose $LocalizedData.ValidatingPrerequisites

    # check that we're running on Server 2012 (or later) or on a client SKU
    $os = Get-CimInstance -ClassName Win32_OperatingSystem

    if (($os.ProductType -ne 1) -and ([System.Int32] $os.BuildNumber -lt 9600))
    {
        throw $LocalizedData.NotSupportedSku
    }

    # check that we are running elevated
    $windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($windowsIdentity)
    $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

    if (!$windowsPrincipal.IsInRole($adminRole))
    {
        throw $LocalizedData.ElevationRequired
    }

    # check that Dism PowerShell module is available
    Import-Module Dism -Force -ErrorVariable ev -ErrorAction SilentlyContinue

    if ($ev.Count -gt 0)
    {
        throw $LocalizedData.DismNotAvailable
    }
}

Export-ModuleMember -Function *-TargetResource
