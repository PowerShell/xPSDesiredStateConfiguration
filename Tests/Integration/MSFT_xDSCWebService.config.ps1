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
                CertificateThumbprint = 'A337EC24D2DE62C9C92EC398F83A4BC2F733F307' #$env:DscCertificateThumbprint
                Port                  = 8080
                EndpointName          = 'PSDSCPullServer'
                PhysicalPath          = "$env:SystemDrive\inetpub\PSDSCPullServer"
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
            EndpointName                 = $Node.EndpointName
            Port                         = $Node.Port
            PhysicalPath                 = $Node.PhysicalPath
            CertificateThumbPrint        = $Node.CertificateThumbprint
            ModulePath                   = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
            ConfigurationPath            = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
            State                        = 'Started'
            RegistrationKeyPath          = "$env:PROGRAMFILES\WindowsPowerShell\DscService"
            AcceptSelfSignedCertificates = $true
            Enable32BitAppOnWin64        = $false
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
            EndpointName                 = $Node.EndpointName
            Port                         = $Node.Port
            PhysicalPath                 = $Node.PhysicalPath
            CertificateThumbPrint        = $Node.CertificateThumbprint
            ModulePath                   = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
            ConfigurationPath            = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
            State                        = 'Started'
            RegistrationKeyPath          = "$env:PROGRAMFILES\WindowsPowerShell\DscService"
            AcceptSelfSignedCertificates = $true
            Enable32BitAppOnWin64        = $false
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
            EndpointName                 = $Node.EndpointName
            Port                         = $Node.Port
            PhysicalPath                 = $Node.PhysicalPath
            CertificateThumbPrint        = $Node.CertificateThumbprint
            ModulePath                   = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
            ConfigurationPath            = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
            State                        = 'Started'
            RegistrationKeyPath          = "$env:PROGRAMFILES\WindowsPowerShell\DscService"
            AcceptSelfSignedCertificates = $true
            Enable32BitAppOnWin64        = $false
            UseSecurityBestPractices     = $false
        }
    }
}
