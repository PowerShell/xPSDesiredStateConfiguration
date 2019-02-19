<#
    .SYNOPSIS
        Tests if the current machine is a Nano server.
#>
function Test-IsNanoServer
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param ()

    $isNanoServer = $false

    if (Test-CommandExists -Name 'Get-ComputerInfo')
    {
        $computerInfo = Get-ComputerInfo

        $computerIsServer = 'Server' -ieq $computerInfo.OsProductType

        if ($computerIsServer)
        {
            $isNanoServer = 'NanoServer' -ieq $computerInfo.OsServerLevel
        }
    }

    return $isNanoServer
}

<#
    .SYNOPSIS
        Tests whether or not the command with the specified name exists.

    .PARAMETER Name
        The name of the command to test for.
#>
function Test-CommandExists
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

    $command = Get-Command -Name $Name -ErrorAction 'SilentlyContinue'
    return ($null -ne $command)
}

<#
    .SYNOPSIS
        Creates and throws an invalid argument exception.

    .PARAMETER Message
        The message explaining why this error is being thrown.

    .PARAMETER ArgumentName
        The name of the invalid argument that is causing this error to be thrown.
#>
function New-InvalidArgumentException
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Message,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ArgumentName
    )

    $argumentException = New-Object -TypeName 'ArgumentException' `
        -ArgumentList @($Message, $ArgumentName)
    $newObjectParams = @{
        TypeName     = 'System.Management.Automation.ErrorRecord'
        ArgumentList = @($argumentException, $ArgumentName, 'InvalidArgument', $null)
    }
    $errorRecord = New-Object @newObjectParams

    throw $errorRecord
}

<#
    .SYNOPSIS
        Creates and throws an invalid data exception.

    .PARAMETER ErrorId
        The error Id to assign to the exception.

    .PARAMETER ErrorMessage
        The error message to assign to the exception.
#>
function New-InvalidDataException
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ErrorId,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ErrorMessage
    )

    $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidData
    $exception = New-Object `
        -TypeName System.InvalidOperationException `
        -ArgumentList $ErrorMessage
    $errorRecord = New-Object `
        -TypeName System.Management.Automation.ErrorRecord `
        -ArgumentList $exception, $ErrorId, $errorCategory, $null

    throw $errorRecord
}

<#
    .SYNOPSIS
        Creates and throws an invalid operation exception.

    .PARAMETER Message
        The message explaining why this error is being thrown.

    .PARAMETER ErrorRecord
        The error record containing the exception that is causing this terminating
        error.
#>
function New-InvalidOperationException
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Message,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    if ($null -eq $Message)
    {
        $invalidOperationException = New-Object -TypeName 'InvalidOperationException'
    }
    elseif ($null -eq $ErrorRecord)
    {
        $invalidOperationException = New-Object -TypeName 'InvalidOperationException' `
            -ArgumentList @($Message)
    }
    else
    {
        $invalidOperationException = New-Object -TypeName 'InvalidOperationException' `
            -ArgumentList @($Message, $ErrorRecord.Exception)
    }

    $newObjectParams = @{
        TypeName     = 'System.Management.Automation.ErrorRecord'
        ArgumentList = @( $invalidOperationException.ToString(), 'MachineStateIncorrect',
            'InvalidOperation', $null )
    }

    $errorRecordToThrow = New-Object @newObjectParams
    throw $errorRecordToThrow
}

<#
    .SYNOPSIS
        Retrieves the localized string data based on the machine's culture.
        Falls back to en-US strings if the machine's culture is not supported.

    .PARAMETER ResourceName
        The name of the resource as it appears before '.strings.psd1' of the localized
        string file.
        For example:
            For xWindowsOptionalFeature: MSFT_xWindowsOptionalFeature
            For xService: MSFT_xServiceResource
            For xRegistry: MSFT_xRegistryResource
#>
function Get-LocalizedData
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ResourceName
    )

    $resourceDirectory = Join-Path -Path $PSScriptRoot -ChildPath $ResourceName
    $localizedStringFileLocation = Join-Path -Path $resourceDirectory -ChildPath $PSUICulture

    if (-not (Test-Path -Path $localizedStringFileLocation))
    {
        # Fallback to en-US
        $localizedStringFileLocation = Join-Path -Path $resourceDirectory -ChildPath 'en-US'
    }

    Import-LocalizedData `
        -BindingVariable 'localizedData' `
        -FileName "$ResourceName.strings.psd1" `
        -BaseDirectory $localizedStringFileLocation

    return $localizedData
}

<#
    .SYNOPSIS
        Sets the Global DSCMachineStatus variable to a value of 1.
#>
function Set-DSCMachineRebootRequired
{
    # Suppressing this rule because $global:DSCMachineStatus is used to trigger a reboot.
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    <#
        Suppressing this rule because $global:DSCMachineStatus is only set,
        never used (by design of Desired State Configuration).
    #>
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [CmdletBinding()]
    param
    (
    )

    $global:DSCMachineStatus = 1
}

Export-ModuleMember -Function @(
    'Test-IsNanoServer',
    'New-InvalidArgumentException',
    'New-InvalidDataException',
    'New-InvalidOperationException',
    'Get-LocalizedData',
    'Set-DSCMachineRebootRequired'
)
