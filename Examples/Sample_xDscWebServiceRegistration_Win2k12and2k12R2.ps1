# DSC configuration for Pull Server using registration with enhanced security settings

# The Sample_xDscWebServiceRegistration_Win2k12and2k12R2 configuration sets up a DSC pull server that is capable for client nodes
# to register with it.

# Prerequisite:1- Install a certificate in "CERT:\LocalMachine\MY\" store
#               For testing environments, you could use a self-signed certificate. (New-SelfSignedCertificate cmdlet could generate one for you).
#               For production environments, you will need a certificate signed by valid CA.
#               Registration only works over https protocols. So to use registration feature, a secure pull server setup with certificate is necessary

# The Sample_MetaConfigurationToRegisterWithSecurePullServer register a DSC client node with the pull server



# ======================================== Arguments ======================================== #

$thumbprint = (New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation cert:\LocalMachine\My ).Thumbprint
$registrationKey = [guid]::NewGuid()

# ======================================== Arguments ======================================== #

# =================================== Section Pull Server =================================== #
configuration Sample_xDscWebServiceRegistration_Win2k12and2k12R2
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

Sample_xDscWebServiceRegistration_Win2k12and2k12R2 -RegistrationKey $registrationKey -certificateThumbPrint $thumbprint -Verbose
# =================================== Section Pull Server =================================== #

# Prerequisite:1- Import a the above created certificate to "CERT:\LocalMachine\Trusted Root Certification Authority\" store

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
