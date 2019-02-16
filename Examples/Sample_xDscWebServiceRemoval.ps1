# DSC configuration for removal of Pull Server and Compliance Server

configuration Sample_xDscWebServiceRemoval
{
    param
    (
        [System.String[]]
        $NodeName = 'localhost'
    )

    Import-DSCResource -ModuleName xPSDesiredStateConfiguration

    Node $NodeName
    {
        WindowsFeature DSCServiceFeature
        {
            Ensure = "Present"
            Name   = "DSC-Service"
        }

        xDscWebService PSDSCPullServer
        {
            Ensure                   = "Absent"
            EndpointName             = "PSDSCPullServer"
            CertificateThumbPrint    = "notNeededForRemoval"
            UseSecurityBestPractices = $false
        }
    }
}
