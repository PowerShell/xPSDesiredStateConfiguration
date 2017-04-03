﻿# Suppress Global Vars PSSA Error because $global:DSCMachineStatus must be allowed
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
param()

$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

# Import CommonResourceHelper for Get-LocalizedData
$script:dscResourcesFolderFilePath = Split-Path $PSScriptRoot -Parent
$script:commonResourceHelperFilePath = Join-Path -Path $script:dscResourcesFolderFilePath -ChildPath 'CommonResourceHelper.psm1'
Import-Module -Name $script:commonResourceHelperFilePath

# Import PackageHelper
$script:packageHelperFilePath = Join-Path -Path $script:dscResourcesFolderFilePath -ChildPath 'PackageHelper.psm1'
Import-Module -Name $script:packageHelperFilePath

# Localized messages for verbose and error statements in this resource
$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_xMsiPackage'

# Path to the directory where the files for a package from a file server will be downloaded to
$script:packageCacheLocation = "$env:ProgramData\Microsoft\Windows\PowerShell\Configuration\BuiltinProvCache\MSFT_xMsiPackage"
$script:msiTools = $null

<#
    .SYNOPSIS
        Retrieves the current state of the MSI file with the given Product ID.

    .PARAMETER ProductId
        The ID of the MSI file to retrieve the state of.

    .PARAMETER Path
        Not used in Get-TargetResource
#>
function Get-TargetResource
{
    [OutputType([Hashtable])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ProductId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )

    $identifyingNumber = Convert-ProductIdToIdentifyingNumber -ProductId $ProductId

    $packageResourceResult = @{}

    $productEntry = Get-ProductEntry -IdentifyingNumber $identifyingNumber

    if ($null -eq $productEntry)
    {
        $packageResourceResult = @{
            Ensure = 'Absent'
            ProductId = $identifyingNumber
        }
    }
    else
    {
        $packageResourceResult = Get-ProductEntryInfo -ProductEntry $productEntry
        $packageResourceResult['ProductId'] = $identifyingNumber

        Write-Verbose -Message ($script:localizedData.GetTargetResourceFound -f $ProductId)
    }

    return $packageResourceResult
}

<#
    .SYNOPSIS
        Installs or uninstalls the MSI file at the given path.

    .PARAMETER ProductId
        The product ID of the MSI file to install or uninstall.

    .PARAMETER Path
        The path to the MSI file to install or uninstall.

    .PARAMETER Ensure
        Indicates whether to given MSI should be installed or uninstalled.
        Set this property to Present to install the MSI, and Absent to uninstall
        the MSI.

    .PARAMETER Arguments
        
    .PARAMETER Credential

    .PARAMETER LogPath

    .PARAMETER FileHash

    .PARAMETER HashAlgorithm

    .PARAMETER SignerSubject

    .PARAMETER SignerThumbprint

    .PARAMETER ServerCertificateValidationCallback

    .PARAMETER RunAsCredential

#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ProductId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure = 'Present',

        [String]
        $Arguments,

        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [String]
        $LogPath,

        [String]
        $FileHash,

        [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5', 'RIPEMD160')]
        [String]
        $HashAlgorithm,

        [String]
        $SignerSubject,

        [String]
        $SignerThumbprint,

        [String]
        $ServerCertificateValidationCallback,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $RunAsCredential
    )

    if (Test-TargetResource @PSBoundParameters)
    {
        return
    }

    Assert-PathExtensionValid -Path $Path

    $uri = Convert-PathToUri -Path $Path
    $identifyingNumber = Convert-ProductIdToIdentifyingNumber -ProductId $ProductId

    <#
        Path gets overwritten in the download code path. Retain the user's original Path so as
        to provide a more descriptive error message in case the install succeeds but the named
        package can't be found on the system afterward.
    #>
    $originalPath = $Path

    Write-Verbose -Message $script:localizedData.PackageConfigurationStarting

    $psDrive = $null
    $downloadedFileName = $null

    try
    {
        if (-not [String]::IsNullOrEmpty($LogPath))
        {
            try
            {
                <#
                    Pre-verify the log path exists and is writable ahead of time so the user won't
                    have to detect why the MSI log path doesn't exist.
                #>
                if (Test-Path -Path $LogPath)
                {
                    Remove-Item -Path $LogPath
                }

                New-Item -Path $LogPath -Type 'File' | Out-Null
            }
            catch
            {
                New-InvalidOperationException -Message ($script:localizedData.CouldNotOpenLog -f $LogPath) -ErrorRecord $_
            }
        }

        # Download or mount file as necessary
        if ($Ensure -eq 'Present')
        {
            if ($uri.IsUnc)
            {
                $psDriveArgs = @{
                    Name = [Guid]::NewGuid()
                    PSProvider = 'FileSystem'
                    Root = Split-Path -Path $uri.LocalPath
                }

                if ($null -ne $Credential)
                {
                    $psDriveArgs['Credential'] = $Credential
                }

                $psDrive = New-PSDrive @psDriveArgs
                $Path = Join-Path -Path $psDrive.Root -ChildPath (Split-Path -Path $uri.LocalPath -Leaf)
            }
            elseif (@( 'http', 'https' ) -contains $uri.Scheme)
            {
                $outStream = $null

                try
                {
                    Write-Verbose -Message ($script:localizedData.CreatingCacheLocation)

                    if (-not (Test-Path -Path $script:packageCacheLocation -PathType 'Container'))
                    {
                        $null = New-Item -Path $script:packageCacheLocation -ItemType 'Directory'
                    }

                    $destinationPath = Join-Path -Path $script:packageCacheLocation -ChildPath (Split-Path -Path $uri.LocalPath -Leaf)

                    Write-Verbose -Message ($script:localizedData.NeedtodownloadfilefromschemedestinationwillbedestName -f $uri.Scheme, $destinationPath)

                    try
                    {
                        Write-Verbose -Message ($script:localizedData.CreatingTheDestinationCacheFile)
                        $outStream = New-Object -TypeName 'System.IO.FileStream' -ArgumentList @( $destinationPath, 'Create' )
                    }
                    catch
                    {
                        # Should never happen since we own the cache directory
                        New-InvalidOperationException -Message ($script:localizedData.CouldNotOpenDestFile -f $destinationPath) -ErrorRecord $_
                    }

                    try
                    {
                        $responseStream = Get-WebRequestResponse -Uri $uri -ServerCertificateValidationCallback $ServerCertificateValidationCallback

                        Copy-ResponseStreamToFileStream -ResponseStream $responseStream -FileStream $outStream
                    }
                    finally
                    {
                        if ($null -ne $responseStream)
                        {
                            Close-Stream -Stream $responseStream
                        }
                    }
                }
                finally
                {
                    if ($null -ne $outStream)
                    {
                        Close-Stream -Stream $outStream
                    }
                }

                Write-Verbose -Message ($script:localizedData.RedirectingPackagePathToCacheFileLocation)
                $Path = $destinationPath
                $downloadedFileName = $destinationPath
            }

            # At this point the Path should be valid if this is an install case
            if (-not (Test-Path -Path $Path -PathType 'Leaf'))
            {
                New-InvalidOperationException -Message ($script:localizedData.PathDoesNotExist -f $Path)
            }

            Assert-FileValid -Path $Path -HashAlgorithm $HashAlgorithm -FileHash $FileHash -SignerSubject $SignerSubject -SignerThumbprint $SignerThumbprint
        }

        $startInfo = New-Object -TypeName 'System.Diagnostics.ProcessStartInfo'

        # Necessary for I/O redirection
        $startInfo.UseShellExecute = $false

        $process = New-Object -TypeName 'System.Diagnostics.Process'
        $process.StartInfo = $startInfo

        # Concept only, will never touch disk
        $errorLogPath = $LogPath + '.err'

        $startInfo.FileName = "$env:winDir\system32\msiexec.exe"

        if ($Ensure -eq 'Present')
        {
            # Check if the MSI package specifies the ProductCode
            $productCode = Get-MsiProductCode -Path $Path

            if ((-not [String]::IsNullOrEmpty($identifyingNumber)) -and ($identifyingNumber -ne $productCode))
            {
                New-InvalidArgumentException -ArgumentName 'ProductId' -Message ($script:localizedData.InvalidId -f $identifyingNumber, $productCode)
            }

            $startInfo.Arguments = '/i "{0}"' -f $Path
        }
        else
        {
            $productEntry = Get-ProductEntry -IdentifyingNumber $identifyingNumber

            $id = Split-Path -Path $productEntry.Name -Leaf
            $startInfo.Arguments = ('/x{0}' -f $id)
        }

        if ($LogPath)
        {
            $startInfo.Arguments += (' /log "{0}"' -f $LogPath)
        }

        $startInfo.Arguments += ' /quiet /norestart'

        if ($Arguments)
        {
            # Append any specified arguments with a space
            $startInfo.Arguments += (' {0}' -f $Arguments)
        }

        Write-Verbose -Message ($script:localizedData.StartingWithStartInfoFileNameStartInfoArguments -f $startInfo.FileName, $startInfo.Arguments)

        $exitCode = 0

        try
        {
            if ($PSBoundParameters.ContainsKey('RunAsCredential'))
            {
                $commandLine = ('"{0}" {1}' -f $startInfo.FileName, $startInfo.Arguments)
                $exitCode = Invoke-PInvoke -CommandLine $commandLine -RunAsCredential $RunAsCredential
            }
            else
            {
               $process = Invoke-Process -Process $process
               $exitCode = $process.ExitCode
            }
        }
        catch
        {
            New-InvalidOperationException -Message ($script:localizedData.CouldNotStartProcess -f $Path) -ErrorRecord $_
        }
    }
    finally
    {
        if ($psDrive)
        {
            Remove-PSDrive -Name $psDrive -Force
        }
    }

    if ($downloadedFileName)
    {
        <#
            This is deliberately not in the finally block because we want to leave the downloaded
            file on disk if an error occurred as a debugging aid for the user.
        #>
        Remove-Item -Path $downloadedFileName
    }

    <#
        Check if a reboot is required, if so notify CA. The MSFT_ServerManagerTasks provider is
        missing on some client SKUs (worked on both Server and Client Skus in Windows 10).
    #>
    $serverFeatureData = Invoke-CimMethod -Name 'GetServerFeature' `
                                          -Namespace 'root\microsoft\windows\servermanager' `
                                          -Class 'MSFT_ServerManagerTasks' `
                                          -Arguments @{ BatchSize = 256 } `
                                          -ErrorAction 'Ignore'

    $registryData = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction 'Ignore'

    if (($serverFeatureData -and $serverFeatureData.RequiresReboot) -or $registryData -or $exitcode -eq 3010 -or $exitcode -eq 1641)
    {
        Write-Verbose $script:localizedData.MachineRequiresReboot
        $global:DSCMachineStatus = 1
    }
    elseif ($Ensure -eq 'Present')
    {
        $productEntry = Get-ProductEntry -IdentifyingNumber $identifyingNumber

        if ($null -eq $productEntry)
        {
            New-InvalidOperationException -Message ($script:localizedData.PostValidationError -f $originalPath)
        }
    }

    if ($Ensure -eq 'Present')
    {
        Write-Verbose -Message $script:localizedData.PackageInstalled
    }
    else
    {
        Write-Verbose -Message $script:localizedData.PackageUninstalled
    }

    Write-Verbose -Message $script:localizedData.PackageConfigurationComplete
}

<#
    .SYNOPSIS
        Tests if the MSI file with the given product ID is installed or uninstalled.

    .PARAMETER ProductId
        The product ID of the MSI file to check the state of.
          
    .PARAMETER Path
        Not Used in Test-TargetResource

    .PARAMETER Ensure
        Indicates whether the MSI file should be installed or uninstalled.
        Set this property to Present if the MSI file should be installed. Set
        this property to Absent if the MSI file should be uninstalled.

    .PARAMETER Arguments
        Not Used in Test-TargetResource

    .PARAMETER Credential
        Not Used in Test-TargetResource

    .PARAMETER LogPath
        Not Used in Test-TargetResource

    .PARAMETER FileHash
        Not Used in Test-TargetResource

    .PARAMETER HashAlgorithm
        Not Used in Test-TargetResource

    .PARAMETER SignerSubject
        Not Used in Test-TargetResource

    .PARAMETER SignerThumbprint
        Not Used in Test-TargetResource

    .PARAMETER ServerCertificateValidationCallback
        Not Used in Test-TargetResource

    .PARAMETER RunAsCredential
        Not Used in Test-TargetResource
#>
function Test-TargetResource
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ProductId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure = 'Present',

        [String]
        $Arguments,

        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [String]
        $LogPath,

        [String]
        $FileHash,

        [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5', 'RIPEMD160')]
        [String]
        $HashAlgorithm,

        [String]
        $SignerSubject,

        [String]
        $SignerThumbprint,

        [String]
        $ServerCertificateValidationCallback,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $RunAsCredential
    )

    $identifyingNumber = Convert-ProductIdToIdentifyingNumber -ProductId $ProductId

    $productEntry = Get-ProductEntry -IdentifyingNumber $identifyingNumber

    if ($null -ne $productEntry)
    {
        $displayName = $productEntry.GetValue('DisplayName')
        Write-Verbose -Message ($script:localizedData.PackageAppearsInstalled -f $displayName)
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.PackageDoesNotAppearInstalled -f $ProductId)
    }

    return (($null -ne $productEntry -and $Ensure -eq 'Present') -or ($null -eq $productEntry -and $Ensure -eq 'Absent'))
}

<#
    .SYNOPSIS
        Asserts that the path extension is '.msi'

    .PARAMETER Path
        The path to the file to validate the extension of.
#>
function Assert-PathExtensionValid
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )

    $pathExtension = [System.IO.Path]::GetExtension($Path)
    Write-Verbose -Message ($script:localizedData.ThePathExtensionWasPathExt -f $pathExtension)

    if ($pathExtension.ToLower() -ne '.msi')
    {
        New-InvalidArgumentException -ArgumentName 'Path' -Message ($script:localizedData.InvalidBinaryType -f $Path)
    }
}

<#
    .SYNOPSIS
        Converts the given path to a URI and returns the URI object.
        Throws an exception if the path's scheme as a URI is not valid.

    .PARAMETER Path
        The path to the file to retrieve as a URI.
#>
function Convert-PathToUri
{
    [OutputType([Uri])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )

    try
    {
        $uri = [Uri] $Path
    }
    catch
    {
        New-InvalidArgumentException -ArgumentName 'Path' -Message ($script:localizedData.InvalidPath -f $Path)
    }

    $validUriSchemes = @( 'file', 'http', 'https' )

    if ($validUriSchemes -notcontains $uri.Scheme)
    {
        Write-Verbose -Message ($script:localizedData.TheUriSchemeWasUriScheme -f $uri.Scheme)
        New-InvalidArgumentException -ArgumentName 'Path' -Message ($script:localizedData.InvalidPath -f $Path)
    }

    return $uri
}

<#
    .SYNOPSIS
        Retrieves the product ID as an identifying number.

    .PARAMETER ProductId
        The product ID to retrieve as an identifying number.
#>
function Convert-ProductIdToIdentifyingNumber
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ProductId
    )

    try
    {
        Write-Verbose -Message ($script:localizedData.ParsingProductIdAsAnIdentifyingNumber -f $ProductId)
        $identifyingNumber = '{{{0}}}' -f [Guid]::Parse($ProductId).ToString().ToUpper()

        Write-Verbose -Message ($script:localizedData.ParsedProductIdAsIdentifyingNumber -f $ProductId, $identifyingNumber)
        return $identifyingNumber
    }
    catch
    {
        New-InvalidArgumentException -ArgumentName 'ProductId' -Message ($script:localizedData.InvalidIdentifyingNumber -f $ProductId)
    }
}


<#
    .SYNOPSIS
        Retrieves the product entry for the package with the given identifying number.

    .PARAMETER IdentifyingNumber
        The identifying number of the product entry to retrieve.
#>
function Get-ProductEntry
{
    [OutputType([Microsoft.Win32.RegistryKey])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $IdentifyingNumber
    )

    $uninstallRegistryKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $uninstallRegistryKeyWow64 = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'

    $productEntry = $null

    if (-not [String]::IsNullOrEmpty($IdentifyingNumber))
    {
        $productEntryKeyLocation = Join-Path -Path $uninstallRegistryKey -ChildPath $IdentifyingNumber
        $productEntry = Get-Item -Path $productEntryKeyLocation -ErrorAction 'SilentlyContinue'

        if ($null -eq $productEntry)
        {
            $productEntryKeyLocation = Join-Path -Path $uninstallRegistryKeyWow64 -ChildPath $IdentifyingNumber
            $productEntry = Get-Item $productEntryKeyLocation -ErrorAction 'SilentlyContinue'
        }
    }

    return $productEntry
}

<#
    .SYNOPSIS
        Retrieves the information for the given product entry and returns it as a hashtable.

    .PARAMETER ProductEntry
        The product entry to retrieve the information for.
#>
function Get-ProductEntryInfo
{
    [OutputType([Hashtable])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.RegistryKey]
        $ProductEntry
    )

    $installDate = Get-ProductEntryValue -ProductEntry $ProductEntry -Property 'InstallDate'

    if ($null -ne $installDate)
    {
        try
        {
            $installDate = '{0:d}' -f [DateTime]::ParseExact($installDate, 'yyyyMMdd',[System.Globalization.CultureInfo]::CurrentCulture).Date
        }
        catch
        {
            $installDate = $null
        }
    }

    $publisher = Get-ProductEntryValue -ProductEntry $ProductEntry -Property 'Publisher'

    $estimatedSize = Get-ProductEntryValue -ProductEntry $ProductEntry -Property 'EstimatedSize'

    if ($null -ne $estimatedSize)
    {
        $estimatedSize = $estimatedSize / 1024
    }

    $displayVersion = Get-ProductEntryValue -ProductEntry $ProductEntry -Property 'DisplayVersion'

    $comments = Get-ProductEntryValue -ProductEntry $ProductEntry -Property 'Comments'

    $displayName = Get-ProductEntryValue -ProductEntry $ProductEntry -Property 'DisplayName'

    $installSource = Get-ProductEntryValue -ProductEntry $ProductEntry -Property 'InstallSource'

    return @{
        Ensure = 'Present'
        Name = $displayName
        InstallSource = $installSource
        InstalledOn = $installDate
        Size = $estimatedSize
        Version = $displayVersion
        PackageDescription = $comments
        Publisher = $publisher
    }
}

<#
    .SYNOPSIS
        Retrieves the value of the given property for the given product entry.
        This is a wrapper for unit testing.

    .PARAMETER ProductEntry
        The product entry object to retrieve the property value from.

    .PARAMETER Property
        The property to retrieve the value of from the product entry.
#>
function Get-ProductEntryValue
{
    [OutputType([Object])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.RegistryKey]
        $ProductEntry,

        [Parameter(Mandatory = $true)]
        [String]
        $Property
    )

    return $ProductEntry.GetValue($Property)
}

<#
    .SYNOPSIS
        Retrieves the web requet response as a stream for the MSI file with the given URI.

    .PARAMETER Uri
        The Uri to retrieve the web request from.

    .PARAMETER ServerCertificationValidationCallback
        The callback ....
#>
function Get-WebRequestResponse
{
    [OutputType([System.IO.Stream])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Uri]
        $Uri,

        [String]
        $ServerCertificateValidationCallback
    )

    try
    {
        $uriScheme = $Uri.Scheme

        Write-Verbose -Message ($script:localizedData.CreatingTheSchemeStream -f $uriScheme)
        $webRequest = [System.Net.WebRequest]::Create($Uri)
    
        Write-Verbose -Message ($script:localizedData.SettingDefaultCredential)
        $webRequest.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        $webRequest.AuthenticationLevel = [System.Net.Security.AuthenticationLevel]::None
    
        if ($uriScheme -eq 'http')
        {
            # Default value is MutualAuthRequested, which applies to the https scheme
            Write-Verbose -Message ($script:localizedData.SettingAuthenticationLevel)
            $webRequest.AuthenticationLevel = [System.Net.Security.AuthenticationLevel]::None
        }
        elseif ($uriScheme -eq 'https' -and -not [String]::IsNullOrEmpty($ServerCertificateValidationCallback))
        {
            Write-Verbose -Message $script:localizedData.SettingCertificateValidationCallback
            $serverCertificateValidationScriptBlock = [ScriptBlock]::Create($ServerCertificateValidationCallback)
            $webRequest.ServerCertificateValidationCallBack = $serverCertificateValidationScriptBlock
        }
    
        Write-Verbose -Message ($script:localizedData.Gettingtheschemeresponsestream -f $uriScheme)
        $responseStream = (([System.Net.HttpWebRequest]$webRequest).GetResponse()).GetResponseStream()

        return $responseStream
    }
    catch
    {
         New-InvalidOperationException -Message ($script:localizedData.CouldNotGetResponseFromWebRequest -f $uriScheme, $Uri.OriginalString) -ErrorRecord $_
    }
}
<#
    .SYNOPSIS
        Copies the given response stream to the given file stream.

    .PARAMETER ResponseStream
        The response stream to copy over.

    .PARAMETER FileStream
        The file stream to copy to.
#>
function Copy-ResponseStreamToFileStream
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.IO.Stream]
        $ResponseStream,

        [Parameter(Mandatory = $true)]
        [System.IO.Stream]
        $FileStream
    )

    try
    {
        Write-Verbose -Message ($script:localizedData.CopyingTheSchemeStreamBytesToTheDiskCache)
        $ResponseStream.CopyTo($FileStream)
        $ResponseStream.Flush()
        $FileStream.Flush()
    }
    catch
    {
        New-InvalidOperationException -Message ($script:localizedData.ErrorCopyingDataToFile) -ErrorRecord $_
    }
}

<#
    .SYNOPSIS
        Closes the given stream.
        Wrapper function for unit testing.

    .PARAMETER Stream
        The stream to close.
#>
function Close-Stream
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.IO.Stream]
        $Stream
    )

    $Stream.Close()
}

<#
    .SYNOPSIS
        Asserts that the file at the given path has a valid hash, signer thumbprint, and/or
        signer subject. If only Path is provided, then this function will never throw.
        If FileHash is provided and HashAlgorithm is not, then Sha-256 will be used as the hash
        algorithm by default.

    .PARAMETER Path
        The path to the file to check.

    .PARAMETER FileHash
        The hash that should match the hash of the file.

    .PARAMETER HashAlgorithm
        The algorithm to use to retrieve the file hash.

    .PARAMETER SignerThumbprint
        The certificate thumbprint that should match the file's signer certificate.

    .PARAMETER SignerSubject
        The certificate subject that should match the file's signer certificate.
#>
function Assert-FileValid
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [String]
        $FileHash,

        [String]
        $HashAlgorithm,

        [String]
        $SignerThumbprint,

        [String]
        $SignerSubject
    )

    if (-not [String]::IsNullOrEmpty($FileHash))
    {
        Assert-FileHashValid -Path $Path -Hash $FileHash -Algorithm $HashAlgorithm
    }

    if (-not [String]::IsNullOrEmpty($SignerThumbprint) -or -not [String]::IsNullOrEmpty($SignerSubject))
    {
        Assert-FileSignatureValid -Path $Path -Thumbprint $SignerThumbprint -Subject $SignerSubject
    }
}

<#
    .SYNOPSIS
        Asserts that the hash of the file at the given path matches the given hash.

    .PARAMETER Path
        The path to the file to check the hash of.

    .PARAMETER Hash
        The hash to check against.

    .PARAMETER Algorithm
        The algorithm to use to retrieve the file's hash.
#>
function Assert-FileHashValid
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [String]
        $Hash,

        [String]
        $Algorithm = 'SHA256'
    )

    Write-Verbose -Message ($script:localizedData.CheckingFileHash -f $Path, $Hash, $Algorithm)

    $fileHash = Get-FileHash -LiteralPath $Path -Algorithm $Algorithm

    if ($fileHash.Hash -ne $Hash)
    {
        New-InvalidArgumentException -ArgumentName 'FileHash' -Message ($script:localizedData.InvalidFileHash -f $Path, $Hash, $Algorithm)
    }
}

<#
    .SYNOPSIS
        Asserts that the signature of the file at the given path is valid.

    .PARAMETER Path
        The path to the file to check the signature of

    .PARAMETER Thumbprint
        The certificate thumbprint that should match the file's signer certificate.

    .PARAMETER Subject
        The certificate subject that should match the file's signer certificate.
#>
function Assert-FileSignatureValid
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [String]
        $Thumbprint,

        [String]
        $Subject
    )

    Write-Verbose -Message ($script:localizedData.CheckingFileSignature -f $Path)

    $signature = Get-AuthenticodeSignature -LiteralPath $Path

    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid)
    {
        New-InvalidArgumentException -ArgumentName 'Path' -Message ($script:localizedData.InvalidFileSignature -f $Path, $signature.Status)
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.FileHasValidSignature -f $Path, $signature.SignerCertificate.Thumbprint, $signature.SignerCertificate.Subject)
    }

    if ($null -ne $Subject -and ($signature.SignerCertificate.Subject -notlike $Subject))
    {
        New-InvalidArgumentException -ArgumentName 'SignerSubject' -Message ($script:localizedData.WrongSignerSubject -f $Path, $Subject)
    }

    if ($null -ne $Thumbprint -and ($signature.SignerCertificate.Thumbprint -ne $Thumbprint))
    {
        New-InvalidArgumentException -ArgumentName 'SignerThumbprint' -Message ($script:localizedData.WrongSignerThumbprint -f $Path, $Thumbprint)
    }
}

<#
    .SYNOPSIS
        Retrieves the name of a product from the MSI at the givin path.

    .PARAMETER Path
        The path to the MSI to retrieve the name from.
#>
function Get-MsiProductName
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )

    $msiTools = Get-MsiTool

    $productName = $msiTools::GetProductName($Path)

    return $productName
}

<#
    .SYNOPSIS
        Retrieves the code of a product from the MSI at the given path.

    .PARAMETER Path
        The path to the MSI to retrieve the code from.
#>
function Get-MsiProductCode
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )

    $msiTools = Get-MsiTool

    $productCode = $msiTools::GetProductCode($Path)

    return $productCode
}

<#
    .SYNOPSIS
        Retrieves the MSI tools type.
#>
function Get-MsiTool
{
    [OutputType([System.Type])]
    [CmdletBinding()]
    param ()

    if ($null -ne $script:msiTools)
    {
        return $script:msiTools
    }
    ### what's going on in this script?
    $msiToolsCodeDefinition = @'
    [DllImport("msi.dll", CharSet = CharSet.Unicode, PreserveSig = true, SetLastError = true, ExactSpelling = true)]
    private static extern UInt32 MsiOpenPackageExW(string szPackagePath, int dwOptions, out IntPtr hProduct);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, PreserveSig = true, SetLastError = true, ExactSpelling = true)]
    private static extern uint MsiCloseHandle(IntPtr hAny);
    [DllImport("msi.dll", CharSet = CharSet.Unicode, PreserveSig = true, SetLastError = true, ExactSpelling = true)]
    private static extern uint MsiGetPropertyW(IntPtr hAny, string name, StringBuilder buffer, ref int bufferLength);
    private static string GetPackageProperty(string msi, string property)
    {
        IntPtr MsiHandle = IntPtr.Zero;
        try
        {
            var res = MsiOpenPackageExW(msi, 1, out MsiHandle);
            if (res != 0)
            {
                return null;
            }
            int length = 256;
            var buffer = new StringBuilder(length);
            res = MsiGetPropertyW(MsiHandle, property, buffer, ref length);
            return buffer.ToString();
        }
        finally
        {
            if (MsiHandle != IntPtr.Zero)
            {
                MsiCloseHandle(MsiHandle);
            }
        }
    }
    public static string GetProductCode(string msi)
    {
        return GetPackageProperty(msi, "ProductCode");
    }
    public static string GetProductName(string msi)
    {
        return GetPackageProperty(msi, "ProductName");
    }
'@

    if (([System.Management.Automation.PSTypeName]'Microsoft.Windows.DesiredStateConfiguration.xPackageResource.MsiTools').Type)
    {
        $script:msiTools = ([System.Management.Automation.PSTypeName]'Microsoft.Windows.DesiredStateConfiguration.xPackageResource.MsiTools').Type
    }
    else
    {
        $script:msiTools = Add-Type `
            -Namespace 'Microsoft.Windows.DesiredStateConfiguration.xPackageResource' `
            -Name 'MsiTools' `
            -Using 'System.Text' `
            -MemberDefinition $msiToolsCodeDefinition `
            -PassThru
    }

    return $script:msiTools
}

<#
    .SYNOPSIS
        Runs a process as the specified user via PInvoke. Returns the exitCode that
        PInvoke returns.

    .PARAMETER CommandLine
        The command line (including arguments) of the process to start.

    .PARAMETER RunAsCredential
        The user credential to start the process as.
#>
function Invoke-PInvoke
{
    [OutputType([System.Int32])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $CommandLine,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $RunAsCredential
    )

    Register-PInvoke
    [System.Int32] $exitCode = 0

    [Source.NativeMethods]::CreateProcessAsUser($CommandLine, `
        $RunAsCredential.GetNetworkCredential().Domain, `
        $RunAsCredential.GetNetworkCredential().UserName, `
        $RunAsCredential.GetNetworkCredential().Password, `
        [ref] $exitCode
    )

    return $exitCode
}

<#
    .SYNOPSIS
        Starts and waits for a process.

    .DESCRIPTION
        Allows mocking and testing of process arguments.

    .PARAMETER Process
        The System.Diagnositics.Process object to start.
#>
function Invoke-Process
{
    [OutputType([System.Diagnostics.Process])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Diagnostics.Process]
        $Process
    )

    $null = $Process.Start()

    $Process.WaitForExit()
    return $Process
}

<#
    .SYNOPSIS
        Registers PInvoke to run a process as a user.
#>
function Register-PInvoke
{
    $programSource = @'
        using System;
        using System.Collections.Generic;
        using System.Text;
        using System.Security;
        using System.Runtime.InteropServices;
        using System.Diagnostics;
        using System.Security.Principal;
        using System.ComponentModel;
        using System.IO;
        namespace Source
        {
            [SuppressUnmanagedCodeSecurity]
            public static class NativeMethods
            {
                //The following structs and enums are used by the various Win32 API's that are used in the code below
                [StructLayout(LayoutKind.Sequential)]
                public struct STARTUPINFO
                {
                    public Int32 cb;
                    public string lpReserved;
                    public string lpDesktop;
                    public string lpTitle;
                    public Int32 dwX;
                    public Int32 dwY;
                    public Int32 dwXSize;
                    public Int32 dwXCountChars;
                    public Int32 dwYCountChars;
                    public Int32 dwFillAttribute;
                    public Int32 dwFlags;
                    public Int16 wShowWindow;
                    public Int16 cbReserved2;
                    public IntPtr lpReserved2;
                    public IntPtr hStdInput;
                    public IntPtr hStdOutput;
                    public IntPtr hStdError;
                }
                [StructLayout(LayoutKind.Sequential)]
                public struct PROCESS_INFORMATION
                {
                    public IntPtr hProcess;
                    public IntPtr hThread;
                    public Int32 dwProcessID;
                    public Int32 dwThreadID;
                }
                [Flags]
                public enum LogonType
                {
                    LOGON32_LOGON_INTERACTIVE = 2,
                    LOGON32_LOGON_NETWORK = 3,
                    LOGON32_LOGON_BATCH = 4,
                    LOGON32_LOGON_SERVICE = 5,
                    LOGON32_LOGON_UNLOCK = 7,
                    LOGON32_LOGON_NETWORK_CLEARTEXT = 8,
                    LOGON32_LOGON_NEW_CREDENTIALS = 9
                }
                [Flags]
                public enum LogonProvider
                {
                    LOGON32_PROVIDER_DEFAULT = 0,
                    LOGON32_PROVIDER_WINNT35,
                    LOGON32_PROVIDER_WINNT40,
                    LOGON32_PROVIDER_WINNT50
                }
                [StructLayout(LayoutKind.Sequential)]
                public struct SECURITY_ATTRIBUTES
                {
                    public Int32 Length;
                    public IntPtr lpSecurityDescriptor;
                    public bool bInheritHandle;
                }
                public enum SECURITY_IMPERSONATION_LEVEL
                {
                    SecurityAnonymous,
                    SecurityIdentification,
                    SecurityImpersonation,
                    SecurityDelegation
                }
                public enum TOKEN_TYPE
                {
                    TokenPrimary = 1,
                    TokenImpersonation
                }
                [StructLayout(LayoutKind.Sequential, Pack = 1)]
                internal struct TokPriv1Luid
                {
                    public int Count;
                    public long Luid;
                    public int Attr;
                }
                public const int GENERIC_ALL_ACCESS = 0x10000000;
                public const int CREATE_NO_WINDOW = 0x08000000;
                internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
                internal const int TOKEN_QUERY = 0x00000008;
                internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
                internal const string SE_INCRASE_QUOTA = "SeIncreaseQuotaPrivilege";
                [DllImport("kernel32.dll",
                    EntryPoint = "CloseHandle", SetLastError = true,
                    CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
                public static extern bool CloseHandle(IntPtr handle);
                [DllImport("advapi32.dll",
                    EntryPoint = "CreateProcessAsUser", SetLastError = true,
                    CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
                public static extern bool CreateProcessAsUser(
                    IntPtr hToken,
                    string lpApplicationName,
                    string lpCommandLine,
                    ref SECURITY_ATTRIBUTES lpProcessAttributes,
                    ref SECURITY_ATTRIBUTES lpThreadAttributes,
                    bool bInheritHandle,
                    Int32 dwCreationFlags,
                    IntPtr lpEnvrionment,
                    string lpCurrentDirectory,
                    ref STARTUPINFO lpStartupInfo,
                    ref PROCESS_INFORMATION lpProcessInformation
                    );
                [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
                public static extern bool DuplicateTokenEx(
                    IntPtr hExistingToken,
                    Int32 dwDesiredAccess,
                    ref SECURITY_ATTRIBUTES lpThreadAttributes,
                    Int32 ImpersonationLevel,
                    Int32 dwTokenType,
                    ref IntPtr phNewToken
                    );
                [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
                public static extern Boolean LogonUser(
                    String lpszUserName,
                    String lpszDomain,
                    String lpszPassword,
                    LogonType dwLogonType,
                    LogonProvider dwLogonProvider,
                    out IntPtr phToken
                    );
                [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
                internal static extern bool AdjustTokenPrivileges(
                    IntPtr htok,
                    bool disall,
                    ref TokPriv1Luid newst,
                    int len,
                    IntPtr prev,
                    IntPtr relen
                    );
                [DllImport("kernel32.dll", ExactSpelling = true)]
                internal static extern IntPtr GetCurrentProcess();
                [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
                internal static extern bool OpenProcessToken(
                    IntPtr h,
                    int acc,
                    ref IntPtr phtok
                    );
                [DllImport("kernel32.dll", ExactSpelling = true)]
                internal static extern int WaitForSingleObject(
                    IntPtr h,
                    int milliseconds
                    );
                [DllImport("kernel32.dll", ExactSpelling = true)]
                internal static extern bool GetExitCodeProcess(
                    IntPtr h,
                    out int exitcode
                    );
                [DllImport("advapi32.dll", SetLastError = true)]
                internal static extern bool LookupPrivilegeValue(
                    string host,
                    string name,
                    ref long pluid
                    );
                public static void CreateProcessAsUser(string strCommand, string strDomain, string strName, string strPassword, ref int ExitCode )
                {
                    var hToken = IntPtr.Zero;
                    var hDupedToken = IntPtr.Zero;
                    TokPriv1Luid tp;
                    var pi = new PROCESS_INFORMATION();
                    var sa = new SECURITY_ATTRIBUTES();
                    sa.Length = Marshal.SizeOf(sa);
                    Boolean bResult = false;
                    try
                    {
                        bResult = LogonUser(
                            strName,
                            strDomain,
                            strPassword,
                            LogonType.LOGON32_LOGON_BATCH,
                            LogonProvider.LOGON32_PROVIDER_DEFAULT,
                            out hToken
                            );
                        if (!bResult)
                        {
                            throw new Win32Exception("Logon error #" + Marshal.GetLastWin32Error().ToString());
                        }
                        IntPtr hproc = GetCurrentProcess();
                        IntPtr htok = IntPtr.Zero;
                        bResult = OpenProcessToken(
                                hproc,
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                ref htok
                            );
                        if(!bResult)
                        {
                            throw new Win32Exception("Open process token error #" + Marshal.GetLastWin32Error().ToString());
                        }
                        tp.Count = 1;
                        tp.Luid = 0;
                        tp.Attr = SE_PRIVILEGE_ENABLED;
                        bResult = LookupPrivilegeValue(
                            null,
                            SE_INCRASE_QUOTA,
                            ref tp.Luid
                            );
                        if(!bResult)
                        {
                            throw new Win32Exception("Lookup privilege error #" + Marshal.GetLastWin32Error().ToString());
                        }
                        bResult = AdjustTokenPrivileges(
                            htok,
                            false,
                            ref tp,
                            0,
                            IntPtr.Zero,
                            IntPtr.Zero
                            );
                        if(!bResult)
                        {
                            throw new Win32Exception("Token elevation error #" + Marshal.GetLastWin32Error().ToString());
                        }
                        bResult = DuplicateTokenEx(
                            hToken,
                            GENERIC_ALL_ACCESS,
                            ref sa,
                            (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                            (int)TOKEN_TYPE.TokenPrimary,
                            ref hDupedToken
                            );
                        if(!bResult)
                        {
                            throw new Win32Exception("Duplicate Token error #" + Marshal.GetLastWin32Error().ToString());
                        }
                        var si = new STARTUPINFO();
                        si.cb = Marshal.SizeOf(si);
                        si.lpDesktop = "";
                        bResult = CreateProcessAsUser(
                            hDupedToken,
                            null,
                            strCommand,
                            ref sa,
                            ref sa,
                            false,
                            0,
                            IntPtr.Zero,
                            null,
                            ref si,
                            ref pi
                            );
                        if(!bResult)
                        {
                            throw new Win32Exception("Create process as user error #" + Marshal.GetLastWin32Error().ToString());
                        }
                        int status = WaitForSingleObject(pi.hProcess, -1);
                        if(status == -1)
                        {
                            throw new Win32Exception("Wait during create process failed user error #" + Marshal.GetLastWin32Error().ToString());
                        }
                        bResult = GetExitCodeProcess(pi.hProcess, out ExitCode);
                        if(!bResult)
                        {
                            throw new Win32Exception("Retrieving status error #" + Marshal.GetLastWin32Error().ToString());
                        }
                    }
                    finally
                    {
                        if (pi.hThread != IntPtr.Zero)
                        {
                            CloseHandle(pi.hThread);
                        }
                        if (pi.hProcess != IntPtr.Zero)
                        {
                            CloseHandle(pi.hProcess);
                        }
                        if (hDupedToken != IntPtr.Zero)
                        {
                            CloseHandle(hDupedToken);
                        }
                    }
                }
            }
        }
'@
    Add-Type -TypeDefinition $programSource -ReferencedAssemblies 'System.ServiceProcess'
}

Export-ModuleMember -Function *-TargetResource