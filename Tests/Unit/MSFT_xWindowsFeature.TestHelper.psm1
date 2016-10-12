<#
    .SYNOPSIS
        Returns false if the OS is windows 7 and true otherwise.  
#>
function Get-IsWin8orAbove
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param ()

    $operatingSystemVersion = (Get-CimInstance -Class Win32_OperatingSystem).Version

    # For Win 7 OS
    if ($operatingSystemVersion -like '6.1*')
    {
        return $false
    }

    return $true
}

<#
    .SYNOPSIS
        Checks if the computer is running a Windows Server operating system.
        To be used in 'should run' methods.
#>
function Get-IsServerSKU
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [String]
        $TargetComputerName
    )

    if ($TargetComputerName)
    {
        $operatingSystem = Get-CimInstance -ClassName  Win32_OperatingSystem `
                                           -ComputerName $TargetComputerName
    }
    else
    {
        $operatingSystem = Get-CimInstance -ClassName  Win32_OperatingSystem
    }

    # We should not run this test on client skus
    return ($operatingSystem.ProductType -ne 1)
}

<#
    .SYNOPSIS
        Checks if the computer is running Windows Server 2008 R2 Server Core.
#>
function Get-IsServer2008R2Core
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param ()

    $datacenterServerCore = 12
    $standardServerCore = 13
    $enterpriseServerCore = 14

    $operatingSystem = Get-CimInstance -Class Win32_OperatingSystem

    if ($operatingSystem.Version.StartsWith('6.1.')) 
    {
        if (($operatingSystem.OperatingSystemSKU -eq $datacenterServerCore) -or `
            ($operatingSystem.OperatingSystemSKU -eq $standardServerCore) -or `
            ($operatingSystem.OperatingSystemSKU -eq $enterpriseServerCore))
        {
            return $true
        }
    }
    
    return $false
}

<#
    .SYNOPSIS
        Checks if the computer is running Windows Server 2012 Server Core.
#>
function Get-IsServer2012Core
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param ()

    $operatingSystem = Get-CimInstance -Class Win32_OperatingSystem

    if ($operatingSystem.Version.StartsWith('6.2.'))
    {
        $hasKey = Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels'

        if (-not $hasKey) 
        { 
            return $false
        }

        $extendedKey = Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels'
        if (($extendedKey.GetValue('ServerCoreExtended') -eq 0) -or `
           (($extendedKey.GetValue('ServerCore') -eq 1) -and `
           -not (($extendedKey.GetValue('Server-Gui-Mgmt') -eq 1) -and `
           ($extendedKey.GetValue('Server-Gui-Shell') -eq 1)))) 
        { 
             return $true
        }
    }

    return $false
}

<#
    .SYNOPSIS
        Checks if the computer is running Windows Server 2012,
        Server Core, or Windows Server 2008 R2 Server Core.
#>
function Get-IsWMFServerCore
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param ()

    return (Get-IsServer2012Core) -or (Get-IsServer2008R2Core)
}

Export-ModuleMember -Function `
    Get-IsWin8OrAbove, `
    Get-IsServerSKU, `
    Get-IsWMFServerCore
