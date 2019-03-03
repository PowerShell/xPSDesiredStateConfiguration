# Name and description for the Firewall rules. Used in multiple locations
$script:FireWallRuleDisplayName = 'Desired State Configuration - Pull Server Port:{0}'

<#
    .SYNOPSIS
        Create a firewall exception so that DSC clients are able to access the configured Pull Server

    .PARAMETER firewallPort
        The TCP port used to create the firewall exception
#>
function Add-PullServerFirewallConfiguration
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateRange(1, 65535)]
        [System.UInt32]
        $Port
    )

    $script:netsh = "$env:windir\system32\netsh.exe"

    Write-Verbose -Message 'Disable Inbound Firewall Notification'
    & $script:netsh advfirewall set currentprofile settings inboundusernotification disable

    # remove all existing rules with that displayName
    & $script:netsh advfirewall firewall delete rule name=DSCPullServer_IIS_Port protocol=tcp localport=$Port | Out-Null

    Write-Verbose -Message "Add Firewall Rule for port $Port"
    & $script:netsh advfirewall firewall add rule name=DSCPullServer_IIS_Port dir=in action=allow protocol=TCP localport=$Port | Out-Null
}

<#
    .SYNOPSIS
        Delete the Pull Server firewall exception

    .PARAMETER firewallPort
        The TCP port for which the firewall exception should be deleted
#>
function Remove-PullServerFirewallConfiguration
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateRange(1, 65535)]
        [System.UInt32]
        $Port
    )

    if (Test-PullServerFirewallConfiguration -Port $Port)
    {
        $script:netsh = "$env:windir\system32\netsh.exe"

        # remove all existing rules with that displayName
        Write-Verbose -Message "Delete Firewall Rule for port $Port"
        & $script:netsh advfirewall firewall delete rule name=DSCPullServer_IIS_Port protocol=tcp localport=$Port | Out-Null

        # backwards compatibility with old code
        if (Get-Command -Name Get-NetFirewallRule -CommandType Cmdlet -ErrorAction:SilentlyContinue)
        {
            # Remove all rules with that name
            $ruleName = ($($FireWallRuleDisplayName) -f $port)
            Get-NetFirewallRule | Where-Object DisplayName -eq "$ruleName" | Remove-NetFirewallRule
        }
    }
    else
    {
        Write-Verbose -Message "No DSC PullServer firewall rule found with port $Port. No cleanup required"
    }
}

<#
    .SYNOPSIS
        Tests if a Pull Server firewall exception exists for a specific port

    .PARAMETER firewallPort
        The TCP port for which the firewall exception should be tested
#>
function Test-PullServerFirewallConfiguration
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateRange(1, 65535)]
        [System.UInt32]
        $Port
    )

    $script:netsh = "$env:windir\system32\netsh.exe"

    # remove all existing rules with that displayName
    Write-Verbose -Message "Testing Firewall Rule for port $Port"
    $result = & $script:netsh advfirewall firewall show rule name=DSCPullServer_IIS_Port | Select-String -Pattern "LocalPort:\s*$Port"
    return -not [string]::IsNullOrWhiteSpace($result)
}

Export-ModuleMember -Function '*-PullServerFirewallConfiguration'
