<#
    .SYNOPSIS
        Expands the archive located at 'C:\ArchivePath\Archive.zip' to the destination path
        'C:\DestinationPath\Destination'.

        The resource will only check if the expanded archive files exist at the destination. 
        No validation is performed on any existing files at the destination to ensure that they
        match the files in the archive.  
#>
Configuration Sample_xArchive_ExpandArchiveNoValidation
{
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xArchive Archive1
        {
            Path = 'C:\ArchivePath\Archive.zip'
            Destination = 'C:\DestinationPath\Destination'
            Ensure = 'Present'
        }
    }
}
