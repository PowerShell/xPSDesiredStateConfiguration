# Suppressing this rule since ConfigurationData is used by external scripts
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
param()

#region HEADER
# Integration Test Config Template Version: 1.2.0
#endregion

$configFile = [System.IO.Path]::ChangeExtension($MyInvocation.MyCommand.Path, 'json')
if (Test-Path -Path $configFile)
{
    $ConfigurationData = Get-Content -Path $configFile | ConvertFrom-Json
}
else
{
    $ConfigurationData = @{
        AllNodes = @(
            @{
                NodeName              = 'localhost'
                CertificateFile       = $env:DscPublicCertificatePath
                CertificateThumbprint = $env:DscCertificateThumbprint
                ConfigurationPath     = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
                EndpointName          = 'PSDSCPullServer'
                ModulePath            = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
                PhysicalPath          = "$env:SystemDrive\inetpub\PSDSCPullServer"
                Port                  = 8080
                RegistrationKeyPath   = "$env:PROGRAMFILES\WindowsPowerShell\DscService"
            }
        )
    }
}

<#
    .SYNOPSIS
        Removes a configured DSC pull server
#>
Configuration MSFT_xDSCWebService_PullTestRemoval_Config
{
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    node $AllNodes.NodeName
    {
        xDSCWebService Integration_Test
        {
            Ensure                       = 'Absent'
            AcceptSelfSignedCertificates = $true
            CertificateThumbPrint        = $Node.CertificateThumbprint
            ConfigurationPath            = $Node.ConfigurationPath
            Enable32BitAppOnWin64        = $false
            EndpointName                 = $Node.EndpointName
            ModulePath                   = $Node.ModulePath
            Port                         = $Node.Port
            PhysicalPath                 = $Node.PhysicalPath
            RegistrationKeyPath          = $Node.RegistrationKeyPath
            State                        = 'Started'
            UseSecurityBestPractices     = $true
        }
    }
}

<#
    .SYNOPSIS
        Sets up a DSC pull server using security best practices
#>
Configuration MSFT_xDSCWebService_PullTestWithSecurityBestPractices_Config
{
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    node $AllNodes.NodeName
    {
        xDSCWebService Integration_Test
        {
            Ensure                       = 'Present'
            AcceptSelfSignedCertificates = $true
            CertificateThumbPrint        = $Node.CertificateThumbprint
            ConfigurationPath            = $Node.ConfigurationPath
            Enable32BitAppOnWin64        = $false
            EndpointName                 = $Node.EndpointName
            ModulePath                   = $Node.ModulePath
            Port                         = $Node.Port
            PhysicalPath                 = $Node.PhysicalPath
            RegistrationKeyPath          = $Node.RegistrationKeyPath
            State                        = 'Started'
            UseSecurityBestPractices     = $true
        }
    }
}

<#
    .SYNOPSIS
        Sets up a DSC pull server without using security best practices
#>
Configuration MSFT_xDSCWebService_PullTestWithoutSecurityBestPractices_Config
{
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    node $AllNodes.NodeName
    {
        xDSCWebService Integration_Test
        {
            Ensure                       = 'Present'
            AcceptSelfSignedCertificates = $true
            CertificateThumbPrint        = $Node.CertificateThumbprint
            ConfigurationPath            = $Node.ConfigurationPath
            Enable32BitAppOnWin64        = $false
            EndpointName                 = $Node.EndpointName
            ModulePath                   = $Node.ModulePath
            Port                         = $Node.Port
            PhysicalPath                 = $Node.PhysicalPath
            RegistrationKeyPath          = $Node.RegistrationKeyPath
            State                        = 'Started'
            UseSecurityBestPractices     = $false
        }
    }
}

<#
    .SYNOPSIS
        Sets up a DSC pull server without firewall exceptions
#>
Configuration MSFT_xDSCWebService_PullTestWithoutFirewall_Config
{
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    node $AllNodes.NodeName
    {
        xDSCWebService Integration_Test
        {
            Ensure                       = 'Present'
            AcceptSelfSignedCertificates = $true
            CertificateThumbPrint        = $Node.CertificateThumbprint
            ConfigurationPath            = $Node.ConfigurationPath
            Enable32BitAppOnWin64        = $false
            EndpointName                 = $Node.EndpointName
            ModulePath                   = $Node.ModulePath
            Port                         = $Node.Port
            PhysicalPath                 = $Node.PhysicalPath
            RegistrationKeyPath          = $Node.RegistrationKeyPath
            State                        = 'Started'
            UseSecurityBestPractices     = $true
            ConfigureFirewall            = $false
        }
    }
}
