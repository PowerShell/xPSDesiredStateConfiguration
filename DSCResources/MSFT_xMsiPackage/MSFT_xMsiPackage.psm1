# Suppress Global Vars PSSA Error because $global:DSCMachineStatus must be allowed
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

$script:packageCacheLocation = "$env:programData\Microsoft\Windows\PowerShell\Configuration\BuiltinProvCache\MSFT_xMsiPackage"
$script:msiTools = $null

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
        ######## not used in Get-TargetResource
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
        <#
            Identifying number can still be null here (e.g. remote MSI with Name specified).
            If the user gave a product ID just pass it through, otherwise get it from the product.
        #>
        if ($null -eq $identifyingNumber -and $null -ne $productEntry.Name)
        {
            $identifyingNumber = Split-Path -Path $productEntry.Name -Leaf
        }

        $installDate = $productEntry.GetValue('InstallDate')

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

        $publisher = $productEntry.GetValue('Publisher')

        $estimatedSize = $productEntry.GetValue('EstimatedSize')

        if ($null -ne $estimatedSize)
        {
            $estimatedSize = $estimatedSize / 1024
        }

        $displayVersion = $productEntry.GetValue('DisplayVersion')

        $comments = $productEntry.GetValue('Comments')

        $displayName = $productEntry.GetValue('DisplayName')

        $installSource = $productEntry.GetValue('InstallSource')

        $packageResourceResult = @{
            Ensure = 'Present'
            Name = $displayName
            InstallSource = $installSource
            InstalledOn = $installDate
            ProductId = $identifyingNumber
            Size = $estimatedSize
            Version = $displayVersion
            PackageDescription = $comments
            Publisher = $publisher
        }
    }

    return $packageResourceResult
}

function Set-TargetResource
{
    [CmdletBinding(SupportsShouldProcess = $true)]
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

    $productEntry = Get-ProductEntry -IdentifyingNumber $identifyingNumber

    <#
        Path gets overwritten in the download code path. Retain the user's original Path in case
        the install succeeded but the named package wasn't present on the system afterward so we
        can give a better error message.
    #>
    $originalPath = $Path

    Write-Verbose -Message $script:localizedData.PackageConfigurationStarting

    $logStream = $null
    $psDrive = $null
    $downloadedFileName = $null

    try
    {
        if (-not [String]::IsNullOrEmpty($LogPath))
        {
            try
            {
                <#
                    We want to pre-verify the log path exists and is writable ahead of time
                    even in the MSI case, as detecting WHY the MSI log path doesn't exist would
                    be rather problematic for the user.
                #>
                if ((Test-Path -Path $LogPath) -and $PSCmdlet.ShouldProcess($script:localizedData.RemoveExistingLogFile, $null, $null))
                {
                    Remove-Item -Path $LogPath
                }

                if ($PSCmdlet.ShouldProcess($script:localizedData.CreateLogFile, $null, $null))
                {
                    New-Item -Path $LogPath -Type 'File' | Out-Null
                }
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

                # If we pass a null for Credential, a dialog will pop up.
                if ($null -ne $Credential)
                {
                    $psDriveArgs['Credential'] = $Credential
                }

                $psDrive = New-PSDrive @psDriveArgs
                $Path = Join-Path -Path $psDrive.Root -ChildPath (Split-Path -Path $uri.LocalPath -Leaf)
            }
            elseif (@( 'http', 'https' ) -contains $uri.Scheme)
            {
                $uriScheme = $uri.Scheme
                $outStream = $null
                $responseStream = $null

                try
                {
                    Write-Verbose -Message ($script:localizedData.CreatingCacheLocation)

                    if (-not (Test-Path -Path $script:packageCacheLocation -PathType 'Container'))
                    {
                        New-Item -Path $script:packageCacheLocation -ItemType 'Directory' | Out-Null
                    }

                    $destinationPath = Join-Path -Path $script:packageCacheLocation -ChildPath (Split-Path -Path $uri.LocalPath -Leaf)

                    Write-Verbose -Message ($script:localizedData.NeedtodownloadfilefromschemedestinationwillbedestName -f $uriScheme, $destinationPath)

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
                        Write-Verbose -Message ($script:localizedData.CreatingTheSchemeStream -f $uriScheme)
                        $webRequest = [System.Net.WebRequest]::Create($uri)

                        Write-Verbose -Message ($script:localizedData.SettingDefaultCredential)
                        $webRequest.Credentials = [System.Net.CredentialCache]::DefaultCredentials

                        if ($uriScheme -eq 'http')
                        {
                            # Default value is MutualAuthRequested, which applies to the https scheme
                            Write-Verbose -Message ($script:localizedData.SettingAuthenticationLevel)
                            $webRequest.AuthenticationLevel = [System.Net.Security.AuthenticationLevel]::None
                        }
                        elseif ($uriScheme -eq 'https' -and -not [String]::IsNullOrEmpty($ServerCertificateValidationCallback))
                        {
                            Write-Verbose -Message 'Assigning user-specified certificate verification callback'
                            $serverCertificateValidationScriptBlock = [ScriptBlock]::Create($ServerCertificateValidationCallback)
                            $webRequest.ServerCertificateValidationCallBack = $serverCertificateValidationScriptBlock
                        }

                        Write-Verbose -Message ($script:localizedData.Gettingtheschemeresponsestream -f $uriScheme)
                        $responseStream = (([System.Net.HttpWebRequest]$webRequest).GetResponse()).GetResponseStream()
                    }
                    catch
                    {
                         Write-Verbose -Message ($script:localizedData.ErrorOutString -f ($_ | Out-String))
                         New-InvalidOperationException -Message ($script:localizedData.CouldNotGetHttpStream -f $uriScheme, $Path) -ErrorRecord $_
                    }

                    try
                    {
                        Write-Verbose -Message ($script:localizedData.CopyingTheSchemeStreamBytesToTheDiskCache -f $uriScheme)
                        $responseStream.CopyTo($outStream)
                        $responseStream.Flush()
                        $outStream.Flush()
                    }
                    catch
                    {
                        New-InvalidOperationException -Message ($script:localizedData.ErrorCopyingDataToFile -f $Path, $destinationPath) -ErrorRecord $_
                    }
                }
                finally
                {
                    if ($null -ne $outStream)
                    {
                        $outStream.Close()
                    }

                    if ($null -ne $responseStream)
                    {
                        $responseStream.Close()
                    }
                }

                Write-Verbose -Message ($script:localizedData.RedirectingPackagePathToCacheFileLocation)
                $Path = $destinationPath
                $downloadedFileName = $destinationPath
            }

            # At this point the Path ought to be valid unless it's a MSI uninstall case
            if (-not (Test-Path -Path $Path -PathType 'Leaf'))
            {
                New-InvalidOperationException -Message ($script:localizedData.PathDoesNotExist -f $Path)
            }

            Assert-FileValid -Path $Path -HashAlgorithm $HashAlgorithm -FileHash $FileHash -SignerSubject $SignerSubject -SignerThumbprint $SignerThumbprint
        }

        $startInfo = New-Object -TypeName 'System.Diagnostics.ProcessStartInfo'

        # Necessary for I/O redirection and just generally a good idea
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

            # We may have used the Name earlier, now we need the actual ID
            $id = Split-Path -Path $productEntry.Name -Leaf
            $startInfo.Arguments = '/x{0}' -f $id
        }

        if ($LogPath)
        {
            $startInfo.Arguments += ' /log "{0}"' -f $LogPath
        }

        $startInfo.Arguments += ' /quiet /norestart'

        if ($Arguments)
        {
            # Append any specified arguments with a space (#195)
            $startInfo.Arguments += ' {0}' -f $Arguments
        }

        Write-Verbose -Message ($script:localizedData.StartingWithStartInfoFileNameStartInfoArguments -f $startInfo.FileName, $startInfo.Arguments)

        $exitCode = 0

        try
        {
            if($PSBoundParameters.ContainsKey('RunAsCredential'))
            {
                $commandLine = '"{0}" {1}' -f $startInfo.FileName, $startInfo.Arguments
                $exitCode = Invoke-PInvoke -CommandLine $commandLine -RunAsCredential $RunAsCredential
            }
            else
            {
               $process = Invoke-Process -Process $process -LogStream ($null -ne $logStream)
               $exitCode = $process.ExitCode
            }
        }
        catch
        {
            New-InvalidOperationException -Message ($script:localizedData.CouldNotStartProcess -f $Path) -ErrorRecord $_
        }

        if ($logStream)
        {
            #We have to re-mux these since they appear to us as different streams
            #The underlying Win32 APIs prevent this problem, as would constructing a script
            #on the fly and executing it, but the former is highly problematic from PowerShell
            #and the latter doesn't let us get the return code for UI-based EXEs
            $outputEvents = Get-Event -SourceIdentifier $LogPath
            $errorEvents = Get-Event -SourceIdentifier $errorLogPath
            $masterEvents = @() + $outputEvents + $errorEvents
            $masterEvents = $masterEvents | Sort-Object -Property TimeGenerated

            foreach($event in $masterEvents)
            {
                $logStream.Write($event.SourceEventArgs.Data);
            }

            Remove-Event -SourceIdentifier $LogPath
            Remove-Event -SourceIdentifier $errorLogPath
        }
    }
    finally
    {
        if ($psDrive)
        {
            Remove-PSDrive -Name $psDrive -Force
        }

        if ($logStream)
        {
            $logStream.Dispose()
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

    $operationMessageString = $script:localizedData.PackageUninstalled

    if ($Ensure -eq 'Present')
    {
        $operationMessageString = $script:localizedData.PackageInstalled
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

    Write-Verbose -Message $operationMessageString
    Write-Verbose -Message $script:localizedData.PackageConfigurationComplete
}

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

    Assert-PathExtensionValid -Path $Path
    $uri = Convert-PathToUri -Path $Path

    $identifyingNumber = Convert-ProductIdToIdentifyingNumber -ProductId $ProductId

    $productEntry = Get-ProductEntry -IdentifyingNumber $identifyingNumber

    Write-Verbose -Message ($script:localizedData.EnsureIsEnsure -f $Ensure)

    if ($null -ne $productEntry)
    {
        $displayName = $productEntry.GetValue('DisplayName')
        Write-Verbose -Message ($script:localizedData.PackageAppearsInstalled -f $displayName)
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.PackageDoesNotAppearInstalled -f $ProductId)
    }

    Write-Verbose -Message ($script:localizedData.ProductAsBooleanIs -f [Boolean]$productEntry)

    return (($null -ne $productEntry -and $Ensure -eq 'Present') -or ($null -eq $productEntry -and $Ensure -eq 'Absent'))
}

<#
    .SYNOPSIS
        Asserts that the path extension is '.msi'

    .PARAMETER Path
        The path to validate the extension of.
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
        Converts the given path to a URI.
        Throws an exception if the path's scheme as a URI is not valid.

    .PARAMETER Path
        The path to retrieve as a URI.
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
        Write-Verbose -Message ($Localized.TheUriSchemeWasUriScheme -f $uri.Scheme)
        New-InvalidArgumentException -ArgumentName 'Path' -Message ($script:localizedData.InvalidPath -f $Path)
    }

    return $uri
}

<#
    .SYNOPSIS
        Retrieves the product ID as an identifying number.

    .PARAMETER ProductId
        The product id to retrieve as an identifying number.
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
        Asserts that the file at the given path is valid.

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

    if ([String]::IsNullOrEmpty($Algorithm))
    {
        $Algorithm = 'SHA256'
    }

    Write-Verbose -Message ($script:localizedData.CheckingFileHash -f $Path, $Hash, $Algorithm)

    $fileHash = Get-FileHash -LiteralPath $Path -Algorithm $Algorithm -ErrorAction 'Stop'

    if ($fileHash.Hash -ne $Hash)
    {
        throw ($script:localizedData.InvalidFileHash -f $Path, $Hash, $Algorithm)
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

    $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction 'Stop'

    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid)
    {
        throw ($script:localizedData.InvalidFileSignature -f $Path, $signature.Status)
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.FileHasValidSignature -f $Path, $signature.SignerCertificate.Thumbprint, $signature.SignerCertificate.Subject)
    }

    if ($null -ne $Subject -and ($signature.SignerCertificate.Subject -notlike $Subject))
    {
        throw ($script:localizedData.WrongSignerSubject -f $Path, $Subject)
    }

    if ($null -ne $Thumbprint -and ($signature.SignerCertificate.Thumbprint -ne $Thumbprint))
    {
        throw ($script:localizedData.WrongSignerThumbprint -f $Path, $Thumbprint)
    }
}

<#
    .SYNOPSIS
        Retrieves the name of a product from an msi.

    .PARAMETER Path
        The path to the msi to retrieve the name from.
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
        Retrieves the code of a product from an msi.

    .PARAMETER Path
        The path to the msi to retrieve the code from.
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
        Runs a process as the specified user via PInvoke.

    .PARAMETER CommandLine
        The command line (including arguments) of the process to start.

    .PARAMETER RunAsCredential
        The user credential to start the process as.
#>
function Invoke-PInvoke
{
    [CmdletBinding()]
    [OutputType([System.Int32])]
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
        $Credential.GetNetworkCredential().Domain, `
        $Credential.GetNetworkCredential().UserName, `
        $Credential.GetNetworkCredential().Password, `
        [ref] $exitCode
    )

    return $exitCode;
}

<#
    .SYNOPSIS
        Starts and waits for a process.

    .DESCRIPTION
        Allows mocking and testing of process arguments.

    .PARAMETER Process
        The System.Diagnositics.Process object to start.

    .PARAMETER LogStream
        Redirect STDOUT and STDERR output.
#>
function Invoke-Process
{
    [CmdletBinding()]
    [OutputType([System.Diagnostics.Process])]
    param (
        [Parameter(Mandatory)]
        [System.Diagnostics.Process]
        $Process,

        [Parameter()]
        [System.Boolean]
        $LogStream
    )

    $Process.Start() | Out-Null

    if ($LogStream)
    {
        $Process.BeginOutputReadLine()
        $Process.BeginErrorReadLine()
    }

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
