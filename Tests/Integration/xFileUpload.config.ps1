param
(
    [Parameter(Mandatory = $true)]
    [String]
    $ConfigurationName
)

Configuration $ConfigurationName
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DestinationPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $SourcePath
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    xFileUpload UploadFileOrFolder
    {
        DestinationPath = $DestinationPath
        SourcePath = $SourcePath
    }
}
