<#
    .SYNOPSIS
        The Sample_xDscWebServiceRegistration_Win2k12and2k12R2 configuration
        sets up a DSC pull server that is capable for client nodes to register
        with it.

        Prerequisite: Install a certificate in 'CERT:\LocalMachine\MY\' store
                      For testing environments, you could use a self-signed
                      certificate. (New-SelfSignedCertificate cmdlet could
                      generate one for you). For production environments, you
                      will need a certificate signed by valid CA. Registration
                      only works over https protocols. So to use registration
                      feature, a secure pull server setup with certificate is
                      necessary.

    .PARAMETER NodeName
        The name of the node being configured as a DSC Pull Server.

    .PARAMETER CertificateThumbPrint
        Certificate thumbprint for creating an HTTPS endpoint. Use
        "AllowUnencryptedTraffic" for setting up a non SSL based endpoint.

    .PARAMETER RegistrationKey
        This key will be used by client nodes as a shared key to authenticate
        during registration. This should be a string with enough entropy
        (randomness) to protect the registration of clients to the pull server.
        The example creates a new GUID for the registration key.

    .EXAMPLE
        $thumbprint = (New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation cert:\LocalMachine\My ).Thumbprint
        $registrationKey = [System.Guid]::NewGuid()

        Sample_xDscWebServiceRegistration_Win2k12and2k12R2 -RegistrationKey $registrationKey -certificateThumbPrint $thumbprint -Verbose
#>
Configuration Sample_xDscWebServiceRegistration_Win2k12and2k12R2
{
    param
    (
        [Parameter()]
        [System.String[]]
        $NodeName = 'localhost',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CertificateThumbPrint,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $RegistrationKey
    )

    Import-DSCResource -ModuleName xPSDesiredStateConfiguration
    # To explicitly import the resource WindowsFeature and File.
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node $NodeName
    {
        WindowsFeature DSCServiceFeature
        {
            Ensure = 'Present'
            Name   = 'DSC-Service'
        }

        xDscWebService PSDSCPullServer
        {
            Ensure                       = 'Present'
            EndpointName                 = 'PSDSCPullServer'
            Port                         = 8080
            PhysicalPath                 = "$env:SystemDrive\inetpub\PSDSCPullServer"
            CertificateThumbPrint        = $CertificateThumbPrint
            ModulePath                   = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
            ConfigurationPath            = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
            State                        = 'Started'
            DependsOn                    = '[WindowsFeature]DSCServiceFeature'
            RegistrationKeyPath          = "$env:PROGRAMFILES\WindowsPowerShell\DscService"
            AcceptSelfSignedCertificates = $true
            UseSecurityBestPractices     = $true
            Enable32BitAppOnWin64        = $true
        }

        File RegistrationKeyFile
        {
            Ensure          = 'Present'
            Type            = 'File'
            DestinationPath = "$env:ProgramFiles\WindowsPowerShell\DscService\RegistrationKeys.txt"
            Contents        = $RegistrationKey
        }
    }
}

<#
    .SYNOPSIS
        The Sample_MetaConfigurationToRegisterWithSecurePullServer registers
        a DSC client node with the pull server.

    .PARAMETER NodeName
        The name of the node being configured as a DSC Pull Server.

    .PARAMETER RegistrationKey
        This key will be used by client nodes as a shared key to authenticate
        during registration. This should be a string with enough entropy
        (randomness) to protect the registration of clients to the pull server.
        The example creates a new GUID for the registration key.

    .PARAMETER ServerName
        The HostName to use when configuring the Pull Server URL on the DSC
        client.

    .EXAMPLE
        $registrationKey = [System.Guid]::NewGuid()

        Sample_MetaConfigurationToRegisterWithSecurePullServer -RegistrationKey $registrationKey
#>
[DSCLocalConfigurationManager()]
Configuration Sample_MetaConfigurationToRegisterWithSecurePullServer
{
    param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $NodeName = 'localhost',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $RegistrationKey,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ServerName = 'localhost'
    )

    Node $NodeName
    {
        Settings
        {
            RefreshMode = 'Pull'
        }

        ConfigurationRepositoryWeb CONTOSO-PullSrv
        {
            ServerURL          = "https://$ServerName`:8080/PSDSCPullServer.svc"
            RegistrationKey    = $RegistrationKey
            ConfigurationNames = @('ClientConfig')
        }

        ReportServerWeb CONTOSO-PullSrv
        {
            ServerURL       = "https://$ServerName`:8080/PSDSCPullServer.svc"
            RegistrationKey = $RegistrationKey
        }
    }
}
