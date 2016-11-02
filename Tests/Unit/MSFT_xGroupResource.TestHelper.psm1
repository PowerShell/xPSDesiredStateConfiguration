Import-Module "$PSScriptRoot\..\..\DSCResources\CommonResourceHelper.psm1" -Force

<#
    .SYNOPSIS
        Determines if a Windows group exists.

    .DESCRIPTION
        This function determines if a Windows group exists on a local or remote machine.

    .PARAMETER GroupName
        The name of the group to test.

    .PARAMETER ComputerName
        The optional name of the computer to check.
        The default value is the local machine.

    .NOTES
        For remote machines, the currently logged on user must have rights to enumerate groups.
#>
function Test-GroupExists
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $GroupName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:computerName
    )

    if (Test-IsNanoServer)
    {
        return Test-GroupExistsOnNanoServer @PSBoundParameters
    }
    else
    {
        return Test-GroupExistsOnFullSKU @PSBoundParameters
    }

    if (Test-IsNanoServer)
    {
        # Try to find a group by its name.
        try
        {
            $null = Get-LocalGroup -Name $GroupName -ErrorAction Stop
            return $true
        }
        catch [System.Exception]
        {
            if ($_.CategoryInfo.ToString().Contains('GroupNotFoundException'))
            {
                # A group with the provided name does not exist.
                return $false
            }
            throw $_.Exception
        }
    }
    else
    {
        return [ADSI]::Exists("WinNT://$env:ComputerName/$GroupName,group")
    }
}

<#
    .SYNOPSIS
        Determines if a Windows group exists.

    .DESCRIPTION
        This function determines if a Windows group exists on a local or remote machine.

    .PARAMETER GroupName
        The name of the group to test.

    .PARAMETER ComputerName
        The optional name of the computer to check. Omit to check for the group on the local machine.

    .NOTES
        For remote machines, the currently logged on user must have rights to enumerate groups.
#>
function Test-GroupExistsOnFullSKU
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:computerName
    )

    Set-StrictMode -Version 'Latest'

    $adsiComputerEntry = [ADSI] "WinNT://$ComputerName"

    if ($null -ne $adsiComputerEntry.Children)
    {
        foreach ($adsiComputerEntryChild in $adsiComputerEntry.Children)
        {
            if ($adsiComputerEntryChild.Path -like "WinNT://*$ComputerName/$GroupName")
            {
                return $true
            }
        }
    }

    return $false
}

<#
    .SYNOPSIS
        Determines if a Windows group exists.

    .DESCRIPTION
        This function determines if a Windows group exists on a local or remote machine.

    .PARAMETER GroupName
        The name of the group to test.

    .PARAMETER ComputerName
        This parameter should not be used on NanoServer.
#>
function Test-GroupExistsOnNanoServer
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:computerName
    )

    Set-StrictMode -Version 'Latest'

    if ($PSBoundParameters.ContainsKey('ComputerName'))
    {
        if (-not (Test-IsLocalMachine -Scope $ComputerName))
        {
            throw 'Do not specify ComputerName when running on NanoServer unless it is the local machine.'
        }
    }

    try
    {
        Get-LocalGroup -Name $GroupName -ErrorAction Stop | Out-Null
        return $true
    }
    catch [System.Exception]
    {
        if ($_.CategoryInfo.ToString().Contains('GroupNotFoundException'))
        {
            return $false
        }
        else
        {
            throw $_.Exception
        }
    }

    return $false
}

<#
    .SYNOPSIS
        Creates a Windows group

    .DESCRIPTION
        This function creates a Windows group on the local or remote machine.

    .PARAMETER GroupName
        The name of the group to create

    .PARAMETER Description
        The optional description to set for the group.

    .PARAMETER MemberUserNames
        The usernames of the optional members to add to the group.

    .PARAMETER ComputerName
        The optional name of the computer to update. Omit to create the group on the local machine.

    .NOTES
        For remote machines, the currently logged on user must have rights to create a group.
#>
function New-Group
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [String]
        $Description,

        [String[]]
        $MemberUserNames,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:computerName
    )

    Set-StrictMode -Version 'Latest'

    if (Test-IsNanoServer)
    {
        New-GroupOnNanoServer @PSBoundParameters
    }
    else
    {
        New-GroupOnFullSKU @PSBoundParameters
    }
}

<#
    .SYNOPSIS
        Creates a Windows group on a full server

    .DESCRIPTION
        This function creates a Windows group on the local or remote full server machine.

    .PARAMETER GroupName
        The name of the group to create

    .PARAMETER Description
        The optional description to set for the group.

    .PARAMETER MemberUserNames
        The usernames of the optional members to add to the group.

    .PARAMETER ComputerName
        The optional name of the computer to update. Omit to create the group on the local machine.

    .NOTES
        For remote machines, the currently logged on user must have rights to create a group.
#>
function New-GroupOnFullSKU
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [String]
        $Description,

        [String[]]
        $MemberUserNames,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:computerName
    )

    Set-StrictMode -Version 'Latest'

    $adsiComputerEntry = [ADSI] "WinNT://$ComputerName"

    if (Test-GroupExists -GroupName $GroupName)
    {
        Remove-Group -GroupName $GroupName -ComputerName $ComputerName
    }

    $adsiGroupEntry = $adsiComputerEntry.Create('Group', $GroupName)

    if ($PSBoundParameters.ContainsKey('Description'))
    {
        $adsiGroupEntry.Put('Description', $Description) | Out-Null
    }

    $adsiGroupEntry.SetInfo() | Out-Null

    if ($PSBoundParameters.ContainsKey("MemberUserNames"))
    {
        $adsiGroupEntry = [ADSI]"WinNT://$ComputerName/$GroupName,group"

        foreach ($memberUserName in $MemberUserNames)
        {
            $adsiGroupEntry.Add("WinNT://$ComputerName/$memberUserName") | Out-Null
        }
    }
}

<#
    .SYNOPSIS
        Creates a Windows group on a Nano server

    .DESCRIPTION
        This function creates a Windows group on the local Nano server machine.

    .PARAMETER GroupName
        The name of the group to create

    .PARAMETER Description
        The optional description to set for the group.

    .PARAMETER MemberUserNames
        The usernames of the optional members to add to the group.

    .PARAMETER ComputerName
        This parameter should not be used on a Nano server.
#>
function New-GroupOnNanoServer
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [String]
        $Description,

        [String[]]
        $MemberUserNames,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:computerName
    )

    Set-StrictMode -Version 'Latest'

    if ($PSBoundParameters.ContainsKey('ComputerName'))
    {
        if (-not (Test-IsLocalMachine -Scope $ComputerName))
        {
            throw 'Do not specify ComputerName when running on NanoServer unless it is the local machine.'
        }
    }

    if (Test-GroupExists -GroupName $GroupName)
    {
        Remove-LocalGroup -Name $GroupName -ErrorAction SilentlyContinue
    }

    New-LocalGroup -Name $GroupName

    if ($PSBoundParameters.ContainsKey('Description'))
    {
        Set-LocalGroup -Name $GroupName -Description $Description
    }

    if ($PSBoundParameters.ContainsKey('MemberUserNames'))
    {
        Add-LocalGroupMember -Name $GroupName -Member $Members
    }
}

<#
    .SYNOPSIS
        Deletes a user group.

    .PARAMETER GroupName
        The name of the user group to delete.

    .PARAMETER ComputerName
        The optional name of the computer to update.
        The default value is the local machine.
#>
function Remove-Group
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:computerName
    )

    if (Test-IsNanoServer)
    {
        Remove-GroupOnNanoServer @PSBoundParameters
    }
    else
    {
        Remove-GroupOnFullSKU @PSBoundParameters
    }
}

<#
    .SYNOPSIS
        Deletes a local user group on a full server.

    .PARAMETER GroupName
        The name of the local user group to delete.

    .PARAMETER ComputerName
        The optional name of the computer to update.
        The default value is the local machine.
#>
function Remove-GroupOnFullSKU
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:computerName
    )

    Set-StrictMode -Version 'Latest'

    $adsiComputerEntry = [ADSI]"WinNT://$ComputerName"

    if (Test-GroupExists -GroupName $GroupName)
    {
        $adsiComputerEntry.Delete('Group', $GroupName) | Out-Null
    }
}

<#
    .SYNOPSIS
        Deletes a local user group on a Nano server.

    .PARAMETER GroupName
        The name of the local user group to delete.

    .PARAMETER ComputerName
        This parameter should not be used on NanoServer.
        The default value is the local machine.
#>
function Remove-GroupOnNanoServer
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:computerName
    )

    Set-StrictMode -Version 'Latest'

    if ($PSBoundParameters.ContainsKey('ComputerName'))
    {
        if (-not (Test-IsLocalMachine -Scope $ComputerName))
        {
            throw 'Do not specify ComputerName when running on NanoServer unless it is the local machine.'
        }
    }

    if (Test-GroupExists -GroupName $GroupName)
    {
        Remove-LocalGroup -Name $GroupName
    }
}

Export-ModuleMember -Function `
    New-Group, `
    Remove-Group, `
    Test-GroupExists
