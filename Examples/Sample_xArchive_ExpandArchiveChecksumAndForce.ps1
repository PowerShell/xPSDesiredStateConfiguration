<#
    .SYNOPSIS
        Expands the archive located at 'C:\ArchivePath\Archive.zip' to the destination path
        'C:\DestinationPath\Destination'.

        Since Validate is specified as $true and the Checksum parameter is specified as SHA-256, the
        resource will check if the SHA-256 hash of the file in the archive matches the SHA-256 hash
        of the correspnding file at the destination and replace any files that do not match.

        Since Force is specified as $true, the resource will overwrite any mismatching files at the
        destination. If Force is specified as $false, the resource will throw an error instead of
        overwrite any files at the destination.
#>
Configuration Sample_xArchive_ExpandArchiveChecksumAndForce
{
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xArchive Archive3
        {
            Path = 'C:\ArchivePath\Archive.zip'
            Destination = 'C:\DestinationPath\Destination'
            Validate = $true
            Checksum = 'SHA-256'
            Force = $true
            Ensure = 'Present'
        }
    }
}
