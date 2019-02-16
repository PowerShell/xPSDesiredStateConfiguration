<#PSScriptInfo
.VERSION 1.0.1
.GUID 4b9e3719-034a-4f3e-aa48-321cc242fa9e
.AUTHOR Microsoft Corporation
.COMPANYNAME Microsoft Corporation
.COPYRIGHT
.TAGS DSCConfiguration
.LICENSEURI https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/master/LICENSE
.PROJECTURI https://github.com/PowerShell/xPSDesiredStateConfiguration
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module @{ModuleName = 'xPSDesiredStateConfiguration';ModuleVersion = '8.2.0.0'}

<#
    .SYNOPSIS
        Configuration that uploads file or folder to a SMB share.

    .DESCRIPTION
        Configuration that uploads file or folder to a SMB share.

    .PARAMETER DestinationPath
        The destination SMB share to upload to. It must be the root of the SMB
        share or an existing folder under the SMB share,
        e.g. '\\MachineName\ShareName\DestinationFolder'.

    .PARAMETER SourcePath
        The source file or folder to upload, e.g. 'C:\Folder' or
        'C:\Folder\file.txt'.

    .PARAMETER Credential
        Credentials to access the SMB share where file or folder should be
        uploaded.

    .PARAMETER CertificateThumbprint
        Thumbprint of the certificate which should be used for encryption and
        decryption of the password. The certificate must already exist on the
        target node in the machine personal store ('cert:\LocalMachine\My').
        This parameter must be provided if the Credential parameter is provided.

    .EXAMPLE
        xFileUpload_UploadToSMBShareConfig -DestinationPath '\\MachineName\Folder' -SourcePath 'C:\Folder\file.txt' -Credential (Get-Credential) -CertificateThumbprint 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

        Compiles a configuration that uploads the file 'C:\Folder\file.txt' to
        the root od the SMB share '\\MachineName\Folder', and uses the thumbprint
        'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' to encrypt and decrypt the
        password of the credentials, the credential is used to log in to the
        SMB share.
#>
Configuration xFileUpload_UploadToSMBShareConfig
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $DestinationPath,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SourcePath,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.String]
        $CertificateThumbprint
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xFileUpload fileUpload
        {
            DestinationPath       = $DestinationPath
            SourcePath            = $SourcePath
            Credential            = $Credential
            CertificateThumbprint = $CertificateThumbprint
        }
    }
}
