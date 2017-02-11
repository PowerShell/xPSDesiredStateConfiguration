$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

# Import CommonResourceHelper for Get-LocalizedData, Test-IsNanoServer
$script:dscResourcesFolderFilePath = Split-Path $PSScriptRoot -Parent
$script:commonResourceHelperFilePath = Join-Path -Path $script:dscResourcesFolderFilePath -ChildPath 'CommonResourceHelper.psm1'
Import-Module -Name $script:commonResourceHelperFilePath

# Localized messages for verbose and error statements in this resource
$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_xArchive'

if (Test-IsNanoServer)
{
    Add-Type -AssemblyName 'System.IO.Compression'
}
else
{
    Add-Type -AssemblyName 'System.IO.Compression'
    Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
}

<#
    .SYNOPSIS
        Retrieves the current state of the archive resource with the specified path and destination.

    .PARAMETER Path
        The path to the archive file that should be decompressed at the specified destination.

    .PARAMETER Destination
        The path where the archive file at the specified path should be decompressed.

    .PARAMETER Validate
        Specifies whether or not to validate that files in the archive at the specified path match
        the files at the specified destination using the specified Checksum method.

        The default value is false.

    .PARAMETER Checksum
        The Checksum method to use to validate whether or not the archive file at the given path
        has been decompressed at the given destination.

        This parameter should only be specified if Validate is specified as true.

        The default value is ModifiedDate.

    .PARAMETER Credential
        The credential of a user account with permissions to access the specified archive path and
        destination if needed.
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
        $Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Destination,

        [Parameter()]
        [Boolean]
        $Validate = $false,

        [Parameter()]
        [ValidateSet('SHA-1', 'SHA-256', 'SHA-512', 'CreatedDate', 'ModifiedDate')]
        [String]
        $Checksum = 'ModifiedDate',

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    Write-Verbose -Message ($script:localizedData.RetrievingArchiveState -f $Path, $Destination)

    # Initialize the state of the archive resource with the specified path and destination
    $archiveState = @{
        Path = $Path
        Destination = $Destination
    }

    <#
        Initialize the required parameters for testing if the archive resource exists in the
        specified state
    #>
    $testTargetResourceParameters = @{
        Path = $Path
        Destination = $Destination
    }

    <#
        Add any specified optional parameters for testing if the archive resource exists in the
        specified state
    #>
    $optionalTestTargetResourceParameters = @( 'Validate', 'Checksum', 'Credential' )

    foreach ($optionalTestTargetResourceParameter in $optionalTestTargetResourceParameters)
    {
        if ($PSBoundParameters.ContainsKey($optionalTestTargetResourceParameter))
        {
            $testTargetResourceParameters[$optionalTestTargetResourceParameter] = $PSBoundParameters.$optionalTestTargetResourceParameter
        }
    }

    # Test if the archive resource exists in the specified state
    $archiveResourceExists = Test-TargetResource @testTargetResourceParameters

    <#
        Populate the Ensure property of the state of the archive resource based on whether the
        archive resource exists in the specified state or not
    #>
    if ($archiveResourceExists)
    {
        Write-Verbose -Message ($script:localizedData.ArchiveExistsAtDestination -f $Path, $Destination)
        $archiveState['Ensure'] = 'Present'
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.ArchiveDoesNotExistAtDestination -f $Path, $Destination)
        $archiveState['Ensure'] = 'Absent'
    }

    return $archiveState
}

<#
    .SYNOPSIS
        Sets the state of the archive resource with the specified path and destination.

    .PARAMETER Path
        The path to the archive file whose content should or should not exist at the specified
        destination.

    .PARAMETER Destination
        The destination path where the content of the archive file at the specified path should or
        should not exist.

    .PARAMETER Ensure
        Specifies whether or not the content of the archive file at the specified path should exist
        at the specified destination.

        To update the specified destination to have the content of the archive file at the
        specified path, specify this property as Present.
        To remove the content of the archive file at the specified path from the specified
        destination, specify this property as Absent.

        The default value is Present.

    .PARAMETER Validate
        Specifies whether or not to validate that the content of the archive at the specified path
        matches files at the specified destination using the specified Checksum method.

        The default value is false.

    .PARAMETER Checksum
        The Checksum method to use to validate whether or not the content of thearchive file at the
        specified path matches files at the specified destination.

        An invalid argument exception will be thrown if the this parameter is specified while the
        Validate parameter is false.

        The default value is ModifiedDate.

    .PARAMETER Credential
        The credential of a user account with permissions to access the specified archive path and
        destination if needed.

    .PARAMETER Force
        Specifies whether or not existing files or directories at the specified destination should
        be overwritten to match the content of the archive at the specified path.

        The default value is false.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Destination,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure = 'Present',

        [Parameter()]
        [Boolean]
        $Validate = $false,

        [Parameter()]
        [ValidateSet('SHA-1', 'SHA-256', 'SHA-512', 'CreatedDate', 'ModifiedDate')]
        [String]
        $Checksum = 'ModifiedDate',

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter()]
        [Boolean]
        $Force = $false
    )

    # Check if Checksum is specified and Validate is false
    if ($PSBoundParameters.ContainsKey('Checksum') -and -not $Validate)
    {
        # If Checksum is specified and Validate is false, throw an error
        $errorMessage = $script:localizedData.ChecksumSpecifiedAndValidateFalse -f $Checksum, $Path, $Destination
        New-InvalidArgumentException -ArgumentName 'Checksum or Validate' -Message $errorMessage 
    }

    $psDrive = $null

    # Check if Credential is specified
    if ($PSBoundParameters.ContainsKey('Credential'))
    {
        # If Credential is specified, mount the drive to the specified path with the specified credential
        $psDrive = Mount-PSDriveWithCredential -Path $Path -Credential $Credential
    }

    try
    {
        # Assert that the path exists as a leaf
        Assert-PathExistsAsLeaf -Path $Path

        # Assert that the destination does not exist or if it does that it is not a file
        Assert-DestinationDoesNotExistAsFile -Destination $Destination

        Write-Verbose -Message ($script:localizedData.SettingArchiveState -f $Path, $Destination)
        
        # Initialize the parameters to update the archive
        $expandArchiveToDestinationParameters = @{
            ArchiveSourcePath = $Path
            Destination = $Destination
            Force = $Force
        }

        # Initilize the parameter to remove the archive
        $removeArchiveFromDestinationParameters = @{
            ArchiveSourcePath = $Path
            Destination = $Destination
        }

        # Test if the user wants to validate that the files at the destination match the archive files
        if ($Validate)
        {
            # If the user wants to validate that the files at the destination match the archive files, add the specified Checksum method to the parameters to update the archive
            $expandArchiveToDestinationParameters['Checksum'] = $Checksum

            # If the user wants to validate that the files at the destination match the archive files, add the specified Checksum method to the parameters to remove the archive
            $removeArchiveFromDestinationParameters['Checksum'] = $Checksum
        }

        # Test if the destination exists or not
        if (Test-Path -LiteralPath $Destination)
        {
            Write-Verbose -Message ($script:localizedData.DestinationExists -f $Destination)

            # If the destination exists, check if the user wants the archive present at the destination or not
            if ($Ensure -eq 'Present')
            {
                # If the user wants the archive present at the destination, update it
                Expand-ArchiveToDestination @expandArchiveToDestinationParameters
            }
            else
            {
                # If the user does not want the archive present at the destination, remove it
                Remove-ArchiveFromDestination @removeArchiveFromDestinationParameters
            }
        }
        else
        {
            Write-Verbose -Message ($script:localizedData.DestinationDoesNotExist -f $Destination)

            # If the destination does not exist, check if the user wants the archive present at the destination or not
            if ($Ensure -eq 'Present')
            {
                Write-Verbose -Message ($script:localizedData.CreatingDirectoryAtDestination -f $Destination)

                # If the user wants the archive present at the destination, create a directory at the destination
                $null = New-Item -Path $Destination -ItemType 'Directory'

                # Update the archive at the destination
                Expand-ArchiveToDestination @expandArchiveToDestinationParameters
            }
        }

        Write-Verbose -Message ($script:localizedData.ArchiveStateSet -f $Path, $Destination)
    }
    finally
    {
        # Test if a PSDrive was mounted
        if ($null -ne $psDrive)
        {
            Write-Verbose -Message ($script:localizedData.RemovingPSDrive -f $psDrive.Root)

            # If a PSDrive was mounted, remove it
            $null = Remove-PSDrive -Name $psDrive -Force -ErrorAction 'SilentlyContinue'
        }
    }
}

<#
    .SYNOPSIS
        Tests whether or not the archive resource with the specified path and destination is in the desired state.

    .PARAMETER Path
        The path to the archive file whose content should or should not exist at the specified
        destination.

    .PARAMETER Destination
        The destination path where the content of the archive file at the specified path should or
        should not exist.

    .PARAMETER Ensure
        Specifies whether or not the content of the archive file at the specified path should exist
        at the specified destination.

        To test whether the content of the archive file at the specified path exists at the
        specified destination, specify this property as Present.
        To test whether the content of the archive file at the specified path does not exist at the
        specified destination, specify this property as Absent.

        The default value is Present.

    .PARAMETER Validate
        Specifies whether or not to validate that the content of the archive at the specified path
        matches files at the specified destination using the specified Checksum method.

        The default value is false.

    .PARAMETER Checksum
        The Checksum method to use to validate whether or not the content of thearchive file at the
        specified path matches files at the specified destination.

        An invalid argument exception will be thrown if the this parameter is specified while the
        Validate parameter is false.

        The default value is ModifiedDate.

    .PARAMETER Credential
        The credential of a user account with permissions to access the specified archive path and
        destination if needed.

    .PARAMETER Force
        Specifies whether or not existing files or directories at the specified destination should
        be overwritten to match the content of the archive at the specified path.

        The default value is false.
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
        $Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Destination,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure = 'Present',

        [Parameter()]
        [Boolean]
        $Validate = $false,

        [Parameter()]
        [ValidateSet('SHA-1', 'SHA-256', 'SHA-512', 'CreatedDate', 'ModifiedDate')]
        [String]
        $Checksum = 'ModifiedDate',

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter()]
        [Boolean]
        $Force = $false
    )

    # Check if Checksum is specified and Validate is false
    if ($PSBoundParameters.ContainsKey('Checksum') -and -not $Validate)
    {
        # If Checksum is specified and Validate is false, throw an error
        $errorMessage = $script:localizedData.ChecksumSpecifiedAndValidateFalse -f $Checksum, $Path, $Destination
        New-InvalidArgumentException -ArgumentName 'Checksum or Validate' -Message $errorMessage 
    }

    # Initialize whether or not the archive is in the desired state by assuming the archive is present at the destination
    $archiveInDesiredState = $Ensure -eq 'Present'

    $psDrive = $null

    # Check if Credential is specified
    if ($PSBoundParameters.ContainsKey('Credential'))
    {
        # If Credential is specified, mount the drive to the specified path with the specified credential
        $psDrive = Mount-PSDriveWithCredential -Path $Path -Credential $Credential
    }

    try
    {
        # Assert that the path exists as a leaf
        Assert-PathExistsAsLeaf -Path $Path

        # Assert that the destination does not exist or if it does that it is not a file
        Assert-DestinationDoesNotExistAsFile -Destination $Destination

        Write-Verbose -Message ($script:localizedData.TestingArchiveState -f $Path, $Destination)

        # Initilize the parameters to test if the archive exists at the destination
        $testArchiveExistsAtDestinationParameters = @{
            ArchiveSourcePath = $Path
            Destination = $Destination
        }

        # Test if the user wants to validate that the files at the destination match the archive files
        if ($Validate)
        {
            # If the user wants to validate that the files at the destination match the archive files, add the specified Checksum method to the parameters to test if the archive exists at the destination
            $testArchiveExistsAtDestinationParameters['Checksum'] = $Checksum
        }

        # Test if the destination exists or not
        if (Test-Path -LiteralPath $Destination)
        {
            Write-Verbose -Message ($script:localizedData.DestinationExists -f $Destination)

            # If the destination exists, test if the archive exists at the destination
            $archiveExists = Test-ArchiveExistsAtDestination @testArchiveExistsAtDestinationParameters

            # Set whether or not the archive is in the desired state by checking if the archive's existence at the destination matches the provided Ensure value
            $archiveInDesiredState = $archiveExists -eq ($Ensure -eq 'Present')
        }
        else
        {
            Write-Verbose -Message ($script:localizedData.DestinationDoesNotExist -f $Destination)

            # If the destination does not exist, set whether or not the archive is in the desired state by checking if the destination's existence matches the provided Ensure value
            $archiveInDesiredState = $Ensure -eq 'Absent'
        }
    }
    finally
    {
        # Test if a PSDrive was mounted
        if ($null -ne $psDrive)
        {
            Write-Verbose -Message ($script:localizedData.RemovingPSDrive -f $psDrive.Root)

            # If a PSDrive was mounted, remove it
            $null = Remove-PSDrive -Name $psDrive -Force -ErrorAction 'SilentlyContinue'
        }
    }

    return $archiveInDesiredState
}

<#
    .SYNOPSIS
        Creates a new GUID.
        This is a wrapper function for unit testing.
#>
function New-Guid
{
    [OutputType([Guid])]
    [CmdletBinding()]
    param ()

    return [Guid]::NewGuid()
}

<#
    .SYNOPSIS
        Mounts a PSDrive to access the specified path with the permissions granted by the specified
        credential.

    .PARAMETER Path
        The path to which to mount a PSDrive.

    .PARAMETER Credential
        The credential of the user account with permissions to access the specified path.
#>
function Mount-PSDriveWithCredential
{
    [OutputType([System.Management.Automation.PSDriveInfo])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    $newPSDrive = $null

    if (Test-Path -LiteralPath $Path -ErrorAction 'SilentlyContinue')
    {
        Write-Verbose -Message ($script:localizedData.PathAccessiblePSDriveNotNeeded -f $Path)
    }
    else
    {
        $pathIsADirectory = $Path.EndsWith('\')

        if ($pathIsADirectory)
        {
            $pathToPSDriveRoot = $Path
        }
        else
        {
            $lastIndexOfBackslash = $Path.LastIndexOf('\')
            $pathDoesNotContainADirectory = $lastIndexOfBackslash -eq -1

            if ($pathDoesNotContainADirectory)
            {
                $errorMessage = $script:localizedData.PathDoesNotContainValidPSDriveRoot -f $Path
                New-InvalidArgumentException -ArgumentName 'Path' -Message $errorMessage
            }
            else
            {
                $pathToPSDriveRoot = $Path.Substring(0, $lastIndexOfBackslash)
            }
        }

        $newPSDriveParameters = @{
            Name = New-Guid
            PSProvider = 'FileSystem'
            Root = $pathToPSDriveRoot
            Scope = 'Script'
            Credential = $Credential
        }

        try
        {
            Write-Verbose -Message ($script:localizedData.CreatingPSDrive -f $pathToPSDriveRoot, $Credential.UserName)
            $newPSDrive = New-PSDrive @newPSDriveParameters
        }
        catch
        {
            $errorMessage = $script:localizedData.ErrorCreatingPSDrive -f $pathToPSDriveRoot, $Credential.UserName
            New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
        }
    }

    return $newPSDrive
}

<#
    .SYNOPSIS
        Throws an invalid argument exception if the specified path does not exist or is not a path
        leaf.

    .PARAMETER Path
        The path to assert.
#>
function Assert-PathExistsAsLeaf
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )

    $pathExistsAsLeaf = Test-Path -LiteralPath $Path -PathType 'Leaf' -ErrorAction 'SilentlyContinue'

    if (-not $pathExistsAsLeaf)
    {
        $errorMessage = $script:localizedData.PathDoesNotExistAsLeaf -f $Path
        New-InvalidArgumentException -ArgumentName 'Path' -Message $errorMessage
    }
}

<#
    .SYNOPSIS
        Throws an invalid argument exception if the specified destination path already exists as a
        file.

    .PARAMETER Destination
        The destination path to assert.
#>
function Assert-DestinationDoesNotExistAsFile
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Destination
    )

    $itemAtDestination = Get-Item -LiteralPath $Destination -ErrorAction 'SilentlyContinue'

    $itemAtDestinationExists = $null -ne $itemAtDestination
    $itemAtDestinationIsFile = $itemAtDestination -is [System.IO.FileInfo]

    if ($itemAtDestinationExists -and $itemAtDestinationIsFile)
    {
        $errorMessage = $script:localizedData.DestinationExistsAsFile -f $Destination
        New-InvalidArgumentException -ArgumentName 'Destination' -Message $errorMessage
    }
}

<#
    .SYNOPSIS
        Opens the archive at the given path.
        This is a wrapper function for unit testing.

    .PARAMETER Path
        The path to the archive to open.
#>
function Open-Archive
{
    [OutputType([System.IO.Compression.ZipArchive])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path
    )

    Write-Verbose -Message ($script:localizedData.OpeningArchive -f $Path)

    try
    {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
    }
    catch
    {
        $errorMessage = $script:localizedData.ErrorOpeningArchive -f $Path
        New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
    }

    return $archive
}

<#
    .SYNOPSIS
        Closes the specified archive.
        This is a wrapper function for unit testing.

    .PARAMETER Archive
        The archive to close.
#>
function Close-Archive
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.Compression.ZipArchive]
        $Archive
    )

    Write-Verbose -Message ($script:localizedData.ClosingArchive -f $Path)
    $null = $Archive.Dispose()
}

<#
    .SYNOPSIS
        Retrieves the full name of the specified archive entry.
        This is a wrapper function for unit testing.

    .PARAMETER ArchiveEntry
        The archive entry to retrieve the full name of.
#>
function Get-ArchiveEntryFullName
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.Compression.ZipArchiveEntry]
        $ArchiveEntry
    )

    return $ArchiveEntry.FullName
}

<#
    .SYNOPSIS
        Opens the specified archive entry.
        This is a wrapper function for unit testing.

    .PARAMETER ArchiveEntry
        The archive entry to open.
#>
function Open-ArchiveEntry
{
    [OutputType([System.IO.Stream])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.Compression.ZipArchiveEntry]
        $ArchiveEntry
    )

    Write-Verbose -Message ($script:localizedData.OpeningArchiveEntry -f $ArchiveEntry.FullName)
    return $ArchiveEntry.Open()
}

<#
    .SYNOPSIS
        Copies the contents of the specified source stream to the specified destination stream.
        This is a wrapper function for unit testing.

    .PARAMETER SourceStream
        The stream to copy from.

    .PARAMETER DestinationStream
        The stream to copy to.
#>
function Copy-FromStreamToStream
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.Stream]
        $SourceStream,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.Stream]
        $DestinationStream
    )

    $null = $SourceStream.CopyTo($DestinationStream)
}

<#
    .SYNOPSIS
        Closes the specified stream.
        This is a wrapper function for unit testing.

    .PARAMETER Stream
        The stream to close.
#>
function Close-Stream
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.Stream]
        $Stream
    )

    $null = $Stream.Dispose()
}

<#
    .SYNOPSIS
        Retrieves the last write time of the specified archive entry.
        This is a wrapper function for unit testing.

    .PARAMETER ArchiveEntry
        The archive entry to retrieve the last write time of.
#>
function Get-ArchiveEntryLastWriteTime
{
    [OutputType([DateTime])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.Compression.ZipArchiveEntry]
        $ArchiveEntry
    )

    return $ArchiveEntry.LastWriteTime.DateTime
}

<#
    .SYNOPSIS
        Copies the specified archive entry to the specified destination path.

    .PARAMETER ArchiveEntry
        The archive entry to copy to the destination.

    .PARAMETER DestinationPath
        The destination file path to copy the archive entry to.
#>
function Copy-ArchiveEntryToDestination
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.Compression.ZipArchiveEntry]
        $ArchiveEntry,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DestinationPath
    )

    Write-Verbose -Message ($script:localizedData.CopyingArchiveEntryToDestination -f $DestinationPath)

    $archiveEntryFullName = Get-ArchiveEntryFullName -ArchiveEntry $ArchiveEntry

    if ($archiveEntryFullName.EndsWith('\'))
    {
        $null = New-Item -Path $DestinationPath -ItemType 'Directory'
    }
    else
    {
        $openStreams = @()

        try
        {
            $archiveEntryStream = Open-ArchiveEntry -ArchiveEntry $ArchiveEntry
            $openStreams += $archiveEntryStream

            # The Create mode will create a new file if it does not exist or overwrite the file if it already exists
            $destinationStreamMode = [System.IO.FileMode]::Create

            $destinationStream = New-Object -TypeName 'System.IO.FileStream' -ArgumentList @( $DestinationPath, $destinationStreamMode )
            $openStreams += $destinationStream

            Copy-FromStreamToStream -SourceStream $archiveEntryStream -DestinationStream $destinationStream
        }
        catch
        {
            $errorMessage = $script:localizedData.ErrorCopyingFromArchiveToDestination -f $DestinationPath
            New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
        }
        finally
        {
            foreach ($openStream in $openStreams)
            {
                Close-Stream -Stream $openStream
            }
        }

        $newArchiveFileInfo = New-Object -TypeName 'System.IO.FileInfo' -ArgumentList @( $DestinationPath )

        $updatedTimestamp = Get-ArchiveEntryLastWriteTime -ArchiveEntry $ArchiveEntry

        $null = Set-ItemProperty -LiteralPath $DestinationPath -Name 'LastWriteTime' -Value $updatedTimestamp
        $null = Set-ItemProperty -LiteralPath $DestinationPath -Name 'LastAccessTime' -Value $updatedTimestamp
        $null = Set-ItemProperty -LiteralPath $DestinationPath -Name 'CreationTime' -Value $updatedTimestamp
    }
}

<#
    .SYNOPSIS
        Tests if the given checksum method name is the name of a SHA checksum method.

    .PARAMETER Checksum
        The name of the checksum method to test.
#>
function Test-ChecksumIsSha
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Checksum
    )
    
    return ($Checksum.Length -ge 'SHA'.Length) -and ($Checksum.Substring(0, 3) -ieq 'SHA')
}

<#
    .SYNOPSIS
        Converts the specified DSC hash algorithm name (with a hyphen) to a PowerShell hash
        algorithm name (without a hyphen). The in-box PowerShell Get-FileHash cmdlet will only hash
        algorithm names without hypens.

    .PARAMETER DscHashAlgorithmName
        The DSC hash algorithm name to convert.
#>
function ConvertTo-PowerShellHashAlgorithmName
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DscHashAlgorithmName
    )

    return $DscHashAlgorithmName.Replace('-', '')
}

<#
    .SYNOPSIS
        Tests if the hash of the specified file matches the hash of the specified archive entry
        using the specified hash algorithm.

    .PARAMETER FilePath
        The path to the file to test the hash of.

    .PARAMETER CacheEntry
        The cache entry to test the hash of.

    .PARAMETER HashAlgorithmName
        The name of the hash algorithm to use to retrieve the hashes of the file and archive entry.
#>
function Test-FileHashMatchesArchiveEntryHash
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FilePath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.Compression.ZipArchiveEntry]
        $ArchiveEntry,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $HashAlgorithmName
    )

    $archiveEntryFullName = Get-ArchiveEntryFullName -ArchiveEntry $ArchiveEntry

    Write-Verbose -Message ($script:localizedData.ComparingHashes -f $FilePath, $archiveEntryFullName, $HashAlgorithmName)

    $fileHashMatchesArchiveEntryHash = $false

    $powerShellHashAlgorithmName = ConvertTo-PowerShellHashAlgorithmName -DscHashAlgorithmName $HashAlgorithmName

    $openStreams = @()

    try
    {
        $archiveEntryStream = Open-ArchiveEntry -ArchiveEntry $ArchiveEntry
        $openStreams += $archiveEntryStream

        # The Open mode will open the file for reading without modifying the file
        $fileStreamMode = [System.IO.FileMode]::Open

        $fileStream = New-Object -TypeName 'System.IO.FileStream' -ArgumentList @( $FilePath, $fileStreamMode )
        $openStreams += $fileStream

        $fileHash = Get-FileHash -InputStream $fileStream -Algorithm $powerShellHashAlgorithmName
        $archiveEntryHash = Get-FileHash -InputStream $archiveEntryStream -Algorithm $powerShellHashAlgorithmName

        $hashAlgorithmsMatch = $fileHash.Algorithm -eq $archiveEntryHash.Algorithm
        $hashesMatch = $fileHash.Hash -eq $archiveEntryHash.Hash

        $fileHashMatchesArchiveEntryHash = $hashAlgorithmsMatch -and $hashesMatch
    }
    catch
    {
        $errorMessage = $script:localizedData.ErrorComparingHashes -f $FilePath, $archiveEntryFullName, $HashAlgorithmName
        New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
    }
    finally
    {
        foreach ($openStream in $openStreams)
        {
            Close-Stream -Stream $openStream
        }
    }

    return $fileHashMatchesArchiveEntryHash
}

<#
    .SYNOPSIS
        Retrieves the timestamp of the specified file for the specified checksum method.

    .PARAMETER File
        The file to retrieve the timestamp of.

    .PARAMETER Checksum
        The checksum method to retrieve the timestamp for.
#>
function Get-TimestampForChecksum
{
    [OutputType([System.DateTime])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]
        $File,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CreatedDate', 'ModifiedDate')]
        [String]
        $Checksum
    )

    $relevantTimestamp = $null

    if ($Checksum -ieq 'CreatedDate')
    {
        $relevantTimestamp = $File.CreationTime
    }
    elseif ($Checksum -ieq 'ModifiedDate')
    {
        $relevantTimestamp = $File.LastWriteTime
    }

    return $relevantTimestamp
}

<#
    .SYNOPSIS
        Tests if the specified file matches the specified archive entry based on the specified
        checksum method.

    .PARAMETER File
        The file to test against the specified archive entry.

    .PARAMETER ArchiveEntry
        The archive entry to test against the specified file.

    .PARAMETER Checksum
        The checksum method to use to determine whether or not the specified file matches the
        specified archive entry.
#>
function Test-FileMatchesArchiveEntryByChecksum
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]
        $File,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.Compression.ZipArchiveEntry]
        $ArchiveEntry,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Checksum
    )

    $archiveEntryFullName = Get-ArchiveEntryFullName -ArchiveEntry $ArchiveEntry

    Write-Verbose -Message ($script:localizedData.TestingIfFileMatchesArchiveEntryByChecksum -f $File.FullName, $archiveEntryFullName, $Checksum)

    $fileMatchesArchiveEntry = $false

    # If the user wants to validate the file, test whether the specified checksum method is a SHA method
    if (Test-ChecksumIsSha -Checksum $Checksum)
    {
        # If the checksum method is a SHA method, retrieve whether or not the files match using the specified SHA checksum method
        $fileHashMatchesArchiveEntryHash = Test-FileHashMatchesArchiveEntryHash -FilePath $File.FullName -ArchiveEntry $ArchiveEntry -HashAlgorithmName $Checksum

        # Test if the files match using the specified SHA checksum method
        if ($fileHashMatchesArchiveEntryHash)
        {
            # If the files match using the specified SHA checksum method, write a verbose message and continue
            Write-Verbose -Message ($script:localizedData.FilesMatchesArchiveEntryByChecksum -f $File.FullName, $archiveEntryFullName, $Checksum)
            $fileMatchesArchiveEntry = $true
        }
    }
    else
    {
        # If the specified Checksum is not a SHA method, retrieve the relevant timestamp of the file at the destination based on the specified checksum method
        $fileTimestampForChecksum = Get-TimestampForChecksum -File $File -Checksum $Checksum

        $archiveEntryLastWriteTime = Get-ArchiveEntryLastWriteTime -ArchiveEntry $ArchiveEntry

        # Test if the relevant timestamp matches the timestamp of the archive file
        if ($fileTimestampForChecksum.Equals($archiveEntryLastWriteTime))
        {
            # If the relevant timestamp matches the timestamp of the archive file, write a verbose message and continue
            Write-Verbose -Message ($script:localizedData.FilesMatchesArchiveEntryByChecksum -f $File.FullName, $archiveEntryFullName, $Checksum)
            $fileMatchesArchiveEntry = $true
        }
    }

    return $fileMatchesArchiveEntry
}

<#
    .SYNOPSIS
        Retrieves the archive entries from the specified archive.
        This is a wrapper function for unit testing.

    .PARAMETER Archive
        The archive of which to retrieve the archive entries.
#>
function Get-ArchiveEntries
{
    [OutputType([System.IO.Compression.ZipArchiveEntry[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.Compression.ZipArchive]
        $Archive
    )

    return $Archive.Entries
}

<#
    .SYNOPSIS
        Expands the archive at the specified source path to the specified destination path.

    .PARAMETER ArchiveSourcePath
        The source path of the archive to expand to the specified destination path.

    .PARAMETER Destination
        The destination path at which to expand the archive at the specified source path.

    .PARAMETER Checksum
        The checksum method to use to determin if a file at the destination already matches a file
        in the archive.

    .PARAMETER Force
        Specified whether or not to overwrite files that exist at the destination but do not match
        the file of the same name in the archive based on the specified checksum method.
#>
function Expand-ArchiveToDestination
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ArchiveSourcePath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Destination,

        [Parameter()]
        [ValidateSet('SHA-1', 'SHA-256', 'SHA-512', 'CreatedDate', 'ModifiedDate')]
        [String]
        $Checksum,

        [Parameter()]
        [Boolean]
        $Force = $false
    )

    Write-Verbose -Message ($script:localizedData.ExpandingArchiveToDestination -f $ArchiveSourcePath, $Destination)

    # Open the archive
    $archive = Open-Archive -Path $ArchiveSourcePath

    try
    {
        $archiveEntries = Get-ArchiveEntries -Archive $archive

        # For each file in the archive...
        foreach ($archiveEntry in $archiveEntries)
        {
            $archivEntryFullName = Get-ArchiveEntryFullName -ArchiveEntry $archiveEntry

            # Find the full path the file should have at the destination
            $archiveEntryPathAtDestination = Join-Path -Path $Destination -ChildPath $archivEntryFullName

            # Retrieve the archive entry item at the destination
            $archiveEntryItemAtDestination = Get-Item -LiteralPath $archiveEntryPathAtDestination -ErrorAction 'SilentlyContinue'

            # Test if the archive entry item exists at the destination or not
            if ($null -eq $archiveEntryItemAtDestination)
            {
                Write-Verbose -Message ($script:localizedData.ItemWithArchiveEntryNameDoesNotExist -f $archiveEntryPathAtDestination)

                # If the archive entry item does not exist at the destination, test if the archive entry is a directory or not
                if (-not $archivEntryFullName.EndsWith('\'))
                {
                    # If the archive entry is a file, find the path to the parent directory of the file
                    $parentDirectory = Split-Path -Path $archiveEntryPathAtDestination -Parent

                    # Test if the parent directory of the file does not exist
                    if (-not (Test-Path -Path $parentDirectory))
                    {
                        Write-Verbose -Message ($script:localizedData.CreatingDirectory -f $parentDirectory)

                        # If the parent directory of the file does not exist, create it
                        $null = New-Item -Path $parentDirectory -ItemType 'Directory'
                    }
                }

                # Copy the file to the destination
                Copy-ArchiveEntryToDestination -ArchiveEntry $archiveEntry -DestinationPath $archiveEntryPathAtDestination
            }
            else
            {
                Write-Verbose -Message ($script:localizedData.ItemWithArchiveEntryNameExists -f $archiveEntryPathAtDestination)
                $overwriteArchiveEntry = $true

                if ($archivEntryFullName.EndsWith('\'))
                {
                    $overwriteArchiveEntry = -not ($archiveEntryItemAtDestination -is [System.IO.DirectoryInfo])
                }
                elseif ($archiveEntryItemAtDestination -is [System.IO.FileInfo])
                {
                    if ($PSBoundParameters.ContainsKey('Checksum'))
                    {
                        $overwriteArchiveEntry = -not (Test-FileMatchesArchiveEntryByChecksum -File $archiveEntryItemAtDestination -ArchiveEntry $archiveEntry -Checksum $Checksum)
                    }
                    else
                    {
                        $overwriteArchiveEntry = $false
                    }
                }
   
                if ($overwriteArchiveEntry)
                {
                    # If the item at the destination is not a file, test if the user wants to forcibly overwrite the item
                    if ($Force)
                    {
                        # If the user wants to forcibly overwrite the item, remove it
                        Write-Verbose -Message ($script:localizedData.OverwritingFile -f $archiveEntryPathAtDestination)
                        $null = Remove-Item -LiteralPath $archiveEntryPathAtDestination

                        # Copy the file to the destination
                        Copy-ArchiveEntryToDestination -ArchiveEntry $archiveEntry -DestinationPath $archiveEntryPathAtDestination
                    }
                    else
                    {
                        # If the user does not want to forcibly overwrite the item, throw an error
                        New-InvalidOperationException -Message ($script:localizedData.ForceNotSpecifiedToOverwriteItem -f $archiveEntryPathAtDestination, $archivEntryFullName)
                    }
                }
            }
        }
    }
    finally
    {
        # Close the archive
        Close-Archive -Archive $archive
    }
}

<#
    .SYNOPSIS
        Removes the specified directory from the specified destination path.
        
    .PARAMETER Directory
        The partial path under the destination path of the directory to remove.

    .PARAMETER Destination
        The destination from which to remove the directory.
#>
function Remove-DirectoryFromDestination
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Directory,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Destination
    )

    # Sort the array of directories so that child directories appear first - Sort-Object requires the use of a pipe to function properly
    $Directory = $Directory | Sort-Object -Descending -Unique

    foreach ($directoryToRemove in $Directory)
    {
        # Find the full path to the directory at the destination
        $directoryPathAtDestination = Join-Path -Path $Destination -ChildPath $directoryToRemove

        $directoryExists = Test-Path -LiteralPath $directoryPathAtDestination -PathType 'Container'

        # Test if the item exists as a directory
        if ($directoryExists)
        {
            $directoryIsEmpty = $null -eq (Get-ChildItem -LiteralPath $directoryPathAtDestination -ErrorAction 'SilentlyContinue')

            # If the item exists as a directory, test if it is empty or not 
            if ($directoryIsEmpty)
            {
                Write-Verbose -Message ($script:localizedData.RemovingDirectory -f $directoryPathAtDestination)

                # If the directory is empty, remove the item
                $null = Remove-Item -LiteralPath $directoryPathAtDestination
            }
            else
            {
                # If the directory is not empty, write a verbose message and continue
                Write-Verbose -Message ($script:localizedData.DirectoryIsNotEmpty -f $directoryPathAtDestination)
            }
        }
    }
}

<#
    .SYNOPSIS
        Removes the specified archive from the specified destination.

    .PARAMETER Archive
        The archive to remove from the specified destination.

    .PARAMETER Destination
        The path to the destination to remove the specified archive from.

    .PARAMETER Checksum
        The checksum method to use to determine whether a file in the archive matches a file at the destination.
        If not provided, only the existence of the items in the archive will be checked.
#>
function Remove-ArchiveFromDestination
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ArchiveSourcePath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Destination,

        [Parameter()]
        [ValidateSet('SHA-1', 'SHA-256', 'SHA-512', 'CreatedDate', 'ModifiedDate')]
        [String]
        $Checksum
    )

    Write-Verbose -Message ($script:localizedData.RemovingArchiveFromDestination -f $Destination)

    # Open the archive
    $archive = Open-Archive -Path $ArchiveSourcePath

    try
    {
        # Initialize an empty array of the relative paths to directories in the archive
        $directoriesToRemove = @()

        $archiveEntries = Get-ArchiveEntries -Archive $archive

        # For every entry in the archive...
        foreach ($archiveEntry in $archiveEntries)
        {
            $archivEntryFullName = Get-ArchiveEntryFullName -ArchiveEntry $archiveEntry

            $archiveEntryIsDirectory = $archivEntryFullName.EndsWith('\')

            # Find the full path the file should have at the destination
            $archiveEntryPathAtDestination = Join-Path -Path $Destination -ChildPath $archivEntryFullName

            # Retrieve the archive entry item at the destination
            $itemAtDestination = Get-Item -LiteralPath $archiveEntryPathAtDestination -ErrorAction 'SilentlyContinue'

            # Test if the archive entry item exists at the destination or not
            if ($null -eq $itemAtDestination)
            {
                Write-Verbose -Message ($script:localizedData.ItemWithArchiveEntryNameDoesNotExist -f $archiveEntryPathAtDestination)
            }
            else
            {
                Write-Verbose -Message ($script:localizedData.ItemWithArchiveEntryNameExists -f $archiveEntryPathAtDestination)

                $itemAtDestinationIsDirectory = $itemAtDestination -is [System.IO.DirectoryInfo]
                $itemAtDestinationIsFile = $itemAtDestination -is [System.IO.FileInfo]

                $removeArchiveEntry = $false

                if ($archiveEntryIsDirectory -and $itemAtDestinationIsDirectory)
                {
                    $removeArchiveEntry = $true

                    # Add directory to list of those to be removed
                    $directoriesToRemove += $archivEntryFullName

                }
                elseif ((-not $archiveEntryIsDirectory) -and $itemAtDestinationIsFile)
                {
                    $removeArchiveEntry = $true
                        
                    if ($PSBoundParameters.ContainsKey('Checksum'))
                    {
                        $removeArchiveEntry = Test-FileMatchesArchiveEntryByChecksum -File $itemAtDestination -ArchiveEntry $archiveEntry -Checksum $Checksum
                    }

                    if ($removeArchiveEntry)
                    {
                        Write-Verbose -Message ($script:localizedData.RemovingFile -f $archiveEntryPathAtDestination)
                        $null = Remove-Item -LiteralPath $archiveEntryPathAtDestination
                    }
                }
                else
                {
                    Write-Verbose -Message ($script:localizedData.CouldNotRemoveItemOfIncorrectType -f $archiveEntryPathAtDestination, $archivEntryFullName)
                }

                if ($removeArchiveEntry)
                {
                    # Find the path to the parent directory of this file
                    $parentDirectory = Split-Path -Path $archivEntryFullName -Parent

                    # Until we reach the root archive directory...
                    while (-not [String]::IsNullOrEmpty($parentDirectory))
                    {
                        # Add the parent of this file to the list of directories
                        $directoriesToRemove += $parentDirectory

                        # Find the parent of that file
                        $parentDirectory = Split-Path -Path $parentDirectory -Parent
                    }
                }
            }
        }

        if ($directoriesToRemove.Count -gt 0)
        {
            $null = Remove-DirectoryFromDestination -Directory $directoriesToRemove -Destination $Destination
        }

        Write-Verbose -Message ($script:localizedData.ArchiveRemovedFromDestination -f $Destination)

    }
    finally
    {
        # Close the archive
        Close-Archive -Archive $archive
    }
}

<#
    .SYNOPSIS
        Tests if the specified archive exists in its expanded form at the destination.

    .PARAMETER Archive
        The archive to test for existence at the specified destination.

    .PARAMETER Destination
        The path to the destination to check for the presence of the expanded form of the specified
        archive.

    .PARAMETER Checksum
        The checksum method to use to determine whether a file in the archive matches a file at the destination.
        If not provided, only the existence of the items in the archive will be checked.
#>
function Test-ArchiveExistsAtDestination
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ArchiveSourcePath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Destination,

        [Parameter()]
        [ValidateSet('SHA-1', 'SHA-256', 'SHA-512', 'CreatedDate', 'ModifiedDate')]
        [String]
        $Checksum
    )

    Write-Verbose -Message ($script:localizedData.TestingIfArchiveExistsAtDestination -f $Destination)

    $archiveExistsAtDestination = $true

    # Open the archive
    $archive = Open-Archive -Path $ArchiveSourcePath

    try
    {
        $archiveEntries = Get-ArchiveEntries -Archive $archive

        # For each file in the archive...
        foreach ($archiveEntry in $archiveEntries)
        {
            $archivEntryFullName = Get-ArchiveEntryFullName -ArchiveEntry $archiveEntry

            # Find the full path the file should have at the destination
            $archiveEntryPathAtDestination = Join-Path -Path $Destination -ChildPath $archivEntryFullName

            # Retrieve the archive entry item at the destination
            $archiveEntryItemAtDestination = Get-Item -LiteralPath $archiveEntryPathAtDestination -ErrorAction 'SilentlyContinue'

            # Test if the archive entry item exists at the destination or not
            if ($null -eq $archiveEntryItemAtDestination)
            {
                Write-Verbose -Message ($script:localizedData.ItemWithArchiveEntryNameDoesNotExist -f $archiveEntryPathAtDestination)

                $archiveExistsAtDestination = $false
                break
            }
            else
            {
                Write-Verbose -Message ($script:localizedData.ItemWithArchiveEntryNameExists -f $archiveEntryPathAtDestination)

                # If the archive entry item exists at the destination, test if the archive entry item is a directory or not
                if ($archivEntryFullName.EndsWith('\'))
                {
                    # If the archive entry item is a directory, test if the item at the destination is not a directory
                    if (-not ($archiveEntryItemAtDestination -is [System.IO.DirectoryInfo]))
                    {
                        $archiveExistsAtDestination = $false
                        break
                    }
                }
                else
                {
                    # If the archive entry item is not a directroy, test if the item at the destination is a file
                    if ($archiveEntryItemAtDestination -is [System.IO.FileInfo])
                    {
                        # If the item at the destination is a file, test if the user wants to validate the file
                        if ($PSBoundParameters.ContainsKey('Checksum'))
                        {
                            if (-not (Test-FileMatchesArchiveEntryByChecksum -File $archiveEntryItemAtDestination -ArchiveEntry $archiveEntry -Checksum $Checksum))
                            {
                                $archiveExistsAtDestination = $false
                                break
                            }
                        }
                    }
                    else
                    {
                        $archiveExistsAtDestination = $false
                        break
                    }
                }
            }
        }
    }
    finally
    {
        Close-Archive -Archive $archive
    }

    return $archiveExistsAtDestination
}
