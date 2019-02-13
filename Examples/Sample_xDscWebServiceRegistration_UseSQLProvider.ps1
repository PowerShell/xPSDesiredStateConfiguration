<#
    .SYNOPSIS
        The Sample_xDscWebServiceRegistration_UseSQLProvider configuration sets
        up a DSC pull server that is capable for client nodes to register with
        it and use SQL Server as a backend DB.

        Prerequisite: 1 - Install a certificate in 'CERT:\LocalMachine\MY\'
                          store. For testing environments, you could use a
                          self-signed certificate. (New-SelfSignedCertificate
                          cmdlet could generate one for you). For production
                          environments, you will need a certificate signed by
                          valid CA. Registration only works over https
                          protocols. So to use registration feature, a secure
                          pull server setup with certificate is necessary.
                      2 - Install and Configure SQL Server

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
        Check if OS major version is higher or equal to 10.

        Note: This check is to pass example validation CI tests,
              it has not been tested to run on Windows Server 2012 R2,
              please see the following example for a Windows Server 2012 R2 version
              of this example;
              https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/master/Examples/Sample_xDscWebServiceRegistration_Win2k12and2k12R2.ps1.

        if ([Environment]::OSVersion.Version.Major -ge '10')
        {
            $thumbprint = (New-SelfSignedCertificate -Subject $env:COMPUTERNAME).Thumbprint
        }
        else
        {
            Write-Warning -Message 'Running on operating system older than major version 10, this configuration is not meant to run on OS with a major version older than version 10. Generating certificate using New-SelfSignedCertificate with an alternate method.'
            $thumbprint = (New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation cert:\LocalMachine\My ).Thumbprint
        }

        $registrationKey = [System.Guid]::NewGuid()

        Sample_xDscWebServiceRegistration_UseSQLProvider -RegistrationKey $registrationKey -CertificateThumbPrint $thumbprint -Verbose
#>
Configuration Sample_xDscWebServiceRegistration_UseSQLProvider
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
            SqlProvider                  = $true
            SqlConnectionString          = "Provider=SQLNCLI11;Data Source=(local)\SQLExpress;User ID=SA;Password=Password12!;Initial Catalog=master;"
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
