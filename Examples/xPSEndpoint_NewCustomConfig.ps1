<#PSScriptInfo
.VERSION 1.0.1
.GUID b6c3a531-1727-4c11-b0d0-162073e09933
.AUTHOR Microsoft Corporation
.COMPANYNAME Microsoft Corporation
.COPYRIGHT
.TAGS DSCConfiguration
.LICENSEURI https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/master/LICENSE
.PROJECTURI https://github.com/PowerShell/xPSDesiredStateConfiguration
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module @{ModuleName = 'xPSDesiredStateConfiguration';ModuleVersion = '8.2.0.0'}

<#
    .SYNOPSIS
        Configuration that creates and registers a new session configuration
        endpoint.

    .DESCRIPTION
        Configuration that creates and registers a new session configuration
        endpoint.

    .PARAMETER Name
        The name of the session configuration.

    .PARAMETER AccessMode
        The access mode for the session configuration. The default value is 'Remote'.

    .PARAMETER RunAsCredential
        The credential for commands of this session configuration.

    .PARAMETER SecurityDescriptorSddl
        The permissions that are required to use the new session configuration
        in the form of a Security Descriptor Definition Language (SDDL) string.

    .PARAMETER StartupScript
        The access mode for the session configuration. The default value is
        'Remote'.

    .NOTES
        To use the sample(s) with credentials, see blog at
        http://blogs.msdn.com/b/powershell/archive/2014/01/31/want-to-secure-credentials-in-windows-powershell-desired-state-configuration.aspx

    .EXAMPLE
        xPSEndpoint_NewCustomConfig -Name 'MaintenanceShell' -RunAsCredential (Get-Credential) -AccessMode 'Remote' -SecurityDescriptorSddl 'O:NSG:BAD:P(A;;GX;;;DU)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)' -StartupScript 'C:\Scripts\Maintenance.ps1'

        Compiles a configuration that creates and registers a new session configuration
        endpoint named 'MaintenanceShell'. The group 'Domain Users' has Invoke
        permission, and commands will run with the credentials provided in the
        parameter RunAsCredential. The script 'C:\Scripts\Maintenance.ps1' will
        run when a new session is started using this session configuration
        endpoint.
#>
configuration xPSEndpoint_NewCustomConfig
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [ValidateSet('Local', 'Remote', 'Disabled')]
        [System.String]
        $AccessMode = 'Remote',

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $RunAsCredential,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SecurityDescriptorSddl,

        [Parameter(Mandatory = $true)]
        [System.String]
        $StartupScript
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node 'localhost'
    {
        xPSEndpoint 'NewEndpoint'
        {
            Name                   = $Name
            Ensure                 = 'Present'
            AccessMode             = $AccessMode
            RunAsCredential        = $RunAsCredential
            SecurityDescriptorSddl = $SecurityDescriptorSddl
            StartupScript          = $StartupScript
        }
    }
}
