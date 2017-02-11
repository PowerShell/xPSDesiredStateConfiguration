<#
    .SYNOPSIS
        Expands the archive located at 'C:\ArchivePath\Archive.zip' to the destination path
        'C:\DestinationPath\Destination'.

        The added specification of a Credential here allows you to provide the credential of a user
        to provide the resource access to the archive and destination paths.

        The resource will only check if the expanded archive files exist at the destination. 
        No validation is performed on any existing files at the destination to ensure that they
        match the files in the archive.
#>
Configuration Sample_xArchive_ExpandArchiveNoValidationCredential
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xArchive Archive1
        {
            Path = 'C:\ArchivePath\Archive.zip'
            Destination = 'C:\DestinationPath\Destination'
            Credential = $Credential
            Ensure = 'Present'
        }
    }
}
