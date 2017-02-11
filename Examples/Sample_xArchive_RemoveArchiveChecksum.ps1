<#
    .SYNOPSIS
        Remove the expansion of the archive located at 'C:\ArchivePath\Archive.zip' from the
        destination path 'C:\DestinationPath\Destination'.

        Since Validate is specified as $true and the Checksum parameter is specified as SHA-256, the
        resource will check if the SHA-256 hash of the file in the archive matches the SHA-256 hash
        of the correspnding file at the destination and will not remove any files that do not match.
#>
Configuration Sample_xArchive_RemoveArchiveChecksum
{
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xArchive Archive4
        {
            Path = 'C:\ArchivePath\Archive.zip'
            Destination = 'C:\DestinationPath\Destination'
            Validate = $true
            Checksum = 'SHA-256'
            Ensure = 'Absent'
        }
    }
}
