<#
    .SYNOPSIS
        Removes the expansion of the archive located at 'C:\ArchivePath\Archive.zip' from the
        destination path 'C:\DestinationPath\Destination'.

        The resource will only check if the expanded archive files exist at the destination. 
        No validation is performed on any existing files at the destination to ensure that they
        match the files in the archive before removing them.  
#>
Configuration Sample_xArchive_RemoveArchiveNoValidation
{
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xArchive Archive5
        {
            Path = 'C:\ArchivePath\Archive.zip'
            Destination = 'C:\DestinationPath\Destination'
            Ensure = 'Absent'
        }
    }
}
