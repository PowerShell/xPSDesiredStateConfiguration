# DSC configuration for Pull Server using registration with enhanced security settings

# The Sample_xDscWebServiceRegistrationWithEnhancedSecurity configuration sets up a DSC pull server that is capable for client nodes
# to register with it and retrieve configuration documents with configuration names instead of configuration id

# Prerequisite: Install a certificate in "CERT:\LocalMachine\MY\" store
#               For testing environments, you could use a self-signed certificate. (New-SelfSignedCertificate cmdlet could generate one for you).
#               For production environments, you will need a certificate signed by valid CA.
#               Registration only works over https protocols. So to use registration feature, a secure pull server setup with certificate is necessary

# The Sample_MetaConfigurationToRegisterWithSecurePullServer register a DSC client node with the pull server

# ======================================== Arguments ======================================== #
<#
    Check if OS major version is higher or equal to 10.

    Note: This check is to pass example validation CI tests,
          it has not been tested to run on Windows Server 2012 R2,
          please see the following example for a Windows Server 2012 R2 version
          of this example;
          https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/master/Examples/Sample_xDscWebServiceRegistration_Win2k12and2k12R2.ps1.
#>
if ([Environment]::OSVersion.Version.Major -ge '10')
{
    $thumbprint = (New-SelfSignedCertificate -Subject $env:COMPUTERNAME).Thumbprint
}
else
{
    Write-Warning -Message 'Running on operating system older than major version 10, this configuration is not meant to run on OS with a major version older than version 10. Generating certificate using New-SelfSignedCertificate with an alternate method.'
    $thumbprint = (New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation cert:\LocalMachine\My ).Thumbprint
}

$registrationKey = [guid]::NewGuid()
# ======================================== Arguments ======================================== #

# =================================== Section DSC Client =================================== #
configuration Sample_xDscWebServiceRegistrationWithSecurityBestPractices
{
    param
    (
        [string[]]
        $NodeName = 'localhost',

        [ValidateNotNullOrEmpty()]
        [string]
        $certificateThumbPrint,

        [Parameter(HelpMessage = 'This should be a string with enough entropy (randomness) to protect the registration of clients to the pull server.  We will use new GUID by default.')]
        [ValidateNotNullOrEmpty()]
        [string]
        $RegistrationKey # A guid that clients use to initiate conversation with pull server
    )

    Import-DSCResource -ModuleName xPSDesiredStateConfiguration
    # To explicitly import the resource WindowsFesture and File.
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node $NodeName
    {
        WindowsFeature DSCServiceFeature
        {
            Ensure = "Present"
            Name   = "DSC-Service"
        }

        xDscWebService PSDSCPullServer
        {
            Ensure                       = "Present"
            EndpointName                 = "PSDSCPullServer"
            Port                         = 8080
            PhysicalPath                 = "$env:SystemDrive\inetpub\PSDSCPullServer"
            CertificateThumbPrint        = $certificateThumbPrint
            ModulePath                   = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
            ConfigurationPath            = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
            State                        = "Started"
            DependsOn                    = "[WindowsFeature]DSCServiceFeature"
            RegistrationKeyPath          = "$env:PROGRAMFILES\WindowsPowerShell\DscService"
            AcceptSelfSignedCertificates = $true
            UseSecurityBestPractices     = $true
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
Sample_xDscWebServiceRegistrationWithSecurityBestPractices -RegistrationKey $registrationKey -certificateThumbPrint $thumbprint
# =================================== Section Pull Server =================================== #

# =================================== Section DSC Client =================================== #
[DSCLocalConfigurationManager()]
configuration Sample_MetaConfigurationToRegisterWithSecurePullServer
{
    param
    (
        [ValidateNotNullOrEmpty()]
        [string]
        $NodeName = 'localhost',

        [ValidateNotNullOrEmpty()]
        [string]
        $RegistrationKey, # Same as the one used to setup pull server in previous configuration

        [ValidateNotNullOrEmpty()]
        [string]
        $ServerName = 'localhost' # Node name of the pull server, same as $NodeName used in previous configuration
    )

    Node $NodeName
    {
        Settings
        {
            RefreshMode = 'Pull'
        }

        ConfigurationRepositoryWeb CONTOSO-PullSrv
        {
            ServerURL          = "https://$ServerName`:8080/PSDSCPullServer.svc" # notice it is https
            RegistrationKey    = $RegistrationKey
            ConfigurationNames = @('ClientConfig')
        }

        ReportServerWeb CONTOSO-PullSrv
        {
            ServerURL       = "https://$ServerName`:8080/PSDSCPullServer.svc" # notice it is https
            RegistrationKey = $RegistrationKey
        }
    }
}

Sample_MetaConfigurationToRegisterWithSecurePullServer -RegistrationKey $registrationKey
# =================================== Section DSC Client =================================== #
