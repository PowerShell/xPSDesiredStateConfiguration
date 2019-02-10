# Import CommonResourceHelper
$script:dscResourcesFolderFilePath = Split-Path -Path $PSScriptRoot -Parent
$script:commonResourceHelperFilePath = Join-Path -Path $script:dscResourcesFolderFilePath -ChildPath 'CommonResourceHelper.psm1'
Import-Module -Name $script:commonResourceHelperFilePath

# Localized messages for verbose and error statements in this resource
$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_xRemoteFile'

# Path where cache will be stored. It's cleared whenever LCM gets new configuration.
$script:cacheLocation = "$env:ProgramData\Microsoft\Windows\PowerShell\Configuration\BuiltinProvCache\MSFT_xRemoteFile"

<#
    .SYNOPSIS
        The Get-TargetResource function is used to fetch the status of file specified in DestinationPath on the target machine.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DestinationPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Uri
    )

    # Check whether DestinationPath is existing file
    $ensure = 'Absent'
    $pathItemType = Get-PathItemType -Path $DestinationPath

    switch ($pathItemType)
    {
        'File'
        {
            Write-Verbose -Message ($script:localizedData.DestinationPathIsExistingFile -f $DestinationPath)
            $ensure = 'Present'
        }

        'Directory'
        {
            Write-Verbose -Message ($script:localizedData.DestinationPathIsExistingPath -f $DestinationPath)

            # If it's existing directory, let's check whether expectedDestinationPath exists
            $uriFileName = Split-Path -Path $Uri -Leaf
            $expectedDestinationPath = Join-Path -Path $DestinationPath -ChildPath $uriFileName

            if (Test-Path -Path $expectedDestinationPath)
            {
                Write-Verbose -Message ($script:localizedData.FileExistsInDestinationPath -f $uriFileName)
                $ensure = 'Present'
            }
        }

        'Other'
        {
            Write-Verbose -Message ($script:localizedData.DestinationPathUnknownType -f $DestinationPath, $pathItemType)
        }

        'NotExists'
        {
            Write-Verbose -Message ($script:localizedData.DestinationPathDoesNotExist -f $DestinationPath)
        }
    }

    return @{
        DestinationPath = $DestinationPath
        Uri             = $Uri
        Ensure          = $ensure
    }
}

<#
    .SYNOPSIS
        The Set-TargetResource function is used to download file found under Uri location to DestinationPath
        Additional parameters can be specified to configure web request
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DestinationPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Uri,

        [Parameter()]
        [System.String]
        $UserAgent,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $Headers,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter()]
        [System.Boolean]
        $MatchSource = $true,

        [Parameter()]
        [System.Uint32]
        $TimeoutSec,

        [Parameter()]
        [System.String]
        $Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $ProxyCredential
    )

    # Validate Uri
    if (-not (Test-UriScheme -Uri $Uri -Scheme 'http|https|file'))
    {
        $errorMessage = $script:localizedData.InvalidWebUriError -f $Uri
        New-InvalidDataException `
            -errorId 'UriValidationFailure' `
            -errorMessage $errorMessage
    }

    # Validate DestinationPath scheme
    if (-not (Test-UriScheme -Uri $DestinationPath -Scheme 'file'))
    {
        $errorMessage = $script:localizedData.InvalidDestinationPathSchemeError -f $DestinationPath
        New-InvalidDataException `
            -errorId 'DestinationPathSchemeValidationFailure' `
            -errorMessage $errorMessage
    }

    # Validate DestinationPath is not UNC path
    if ($DestinationPath.StartsWith("\\"))
    {
        $errorMessage = $script:localizedData.DestinationPathIsUncError -f $DestinationPath
        New-InvalidDataException `
            -errorId 'DestinationPathIsUncFailure' `
            -errorMessage $errorMessage
    }

    # Validate DestinationPath does not contain invalid characters
    @('*', '?', '"', '<', '>', '|') | Foreach-Object -Process {
        if ($DestinationPath.Contains($_))
        {
            $errorMessage = $script:localizedData.DestinationPathHasInvalidCharactersError -f $DestinationPath
            New-InvalidDataException `
                -errorId 'DestinationPathHasInvalidCharactersError' `
                -errorMessage $errorMessage
        }
    }

    # Validate DestinationPath does not end with / or \ (Invoke-WebRequest requirement)
    if ($DestinationPath.EndsWith('/') -or $DestinationPath.EndsWith('\'))
    {
        $errorMessage = $script:localizedData.DestinationPathEndsWithInvalidCharacterError -f $DestinationPath
        New-InvalidDataException `
            -errorId 'DestinationPathEndsWithInvalidCharacterError' `
            -errorMessage $errorMessage
    }

    # Check whether DestinationPath's parent directory exists. Create if it doesn't.
    $destinationPathParent = Split-Path -Path $DestinationPath -Parent

    if (-not (Test-Path $destinationPathParent))
    {
        $null = New-Item -ItemType Directory -Path $destinationPathParent -Force
    }

    # Check whether DestinationPath's leaf is an existing folder
    $uriFileName = Split-Path -Path $Uri -Leaf

    if (Test-Path $DestinationPath -PathType Container)
    {
        $DestinationPath = Join-Path -Path $DestinationPath -ChildPath $uriFileName
    }

    # Remove DestinationPath and MatchSource from parameters as they are not parameters of Invoke-WebRequest
    $null = $PSBoundParameters.Remove('DestinationPath')
    $null = $PSBoundParameters.Remove('MatchSource')

    # Convert headers to hashtable
    $null = $PSBoundParameters.Remove('Headers')
    $headersHashtable = $null

    if ($Headers -ne $null)
    {
        $headersHashtable = Convert-KeyValuePairArrayToHashtable -Array $Headers
    }

    # Invoke web request
    try
    {
        $currentProgressPreference = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'

        Write-Verbose -Message ($script:localizedData.DownloadingURI -f $DestinationPath, $URI)

        Invoke-WebRequest @PSBoundParameters -Headers $headersHashtable -OutFile $DestinationPath
    }
    catch [System.OutOfMemoryException]
    {
        $errorMessage = $script:localizedData.DownloadOutOfMemoryException -f $_
        New-InvalidDataException `
            -errorId 'SystemOutOfMemoryException' `
            -errorMessage $errorMessage
    }
    catch [System.Exception]
    {
        $errorMessage = $script:localizedData.DownloadException -f $_
        New-InvalidDataException `
            -errorId 'SystemException' `
            -errorMessage $errorMessage
    }
    finally
    {
        $ProgressPreference = $currentProgressPreference
    }

    # Update cache
    if (Test-Path -Path $DestinationPath)
    {
        $downloadedFile = Get-Item -Path $DestinationPath
        $lastWriteTime = $downloadedFile.LastWriteTimeUtc
        $filesize = $downloadedFile.Length
        $inputObject = @{}
        $inputObject['LastWriteTime'] = $lastWriteTime
        $inputObject['FileSize'] = $filesize
        Update-Cache -DestinationPath $DestinationPath -Uri $Uri -InputObject $inputObject
    }
}

<#
    .SYNOPSIS
        The Test-TargetResource function is used to validate if the DestinationPath exists on the machine.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DestinationPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Uri,

        [Parameter()]
        [System.String]
        $UserAgent,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $Headers,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter()]
        [System.Boolean]
        $MatchSource = $true,

        [Parameter()]
        [System.Uint32]
        $TimeoutSec,

        [Parameter()]
        [System.String]
        $Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $ProxyCredential
    )

    # Check whether DestinationPath points to existing file or directory
    $fileExists = $false
    $uriFileName = Split-Path -Path $Uri -Leaf
    $pathItemType = Get-PathItemType -Path $DestinationPath

    switch ($pathItemType)
    {
        'File'
        {
            Write-Verbose -Message ($script:localizedData.DestinationPathIsExistingFile -f $DestinationPath)

            if ($MatchSource)
            {
                $file = Get-Item -Path $DestinationPath
                # Getting cache. It's cleared every time user runs Start-DscConfiguration
                $cache = Get-Cache -DestinationPath $DestinationPath -Uri $Uri

                if ($cache -ne $null `
                        -and ($cache.LastWriteTime -eq $file.LastWriteTimeUtc) `
                        -and ($cache.FileSize -eq $file.Length))
                {
                    Write-Verbose -Message $script:localizedData.CacheReflectsCurrentState
                    $fileExists = $true
                }
                else
                {
                    Write-Verbose -Message $script:localizedData.CacheIsEmptyOrNotMatchCurrentState
                }
            }
            else
            {
                Write-Verbose -Message $script:localizedData.MatchSourceFalse
                $fileExists = $true
            }
        }

        'Directory'
        {
            Write-Verbose -Message ($script:localizedData.DestinationPathIsExistingPath -f $DestinationPath)

            $expectedDestinationPath = Join-Path -Path $DestinationPath -ChildPath $uriFileName

            if (Test-Path -Path $expectedDestinationPath)
            {
                if ($MatchSource)
                {
                    $file = Get-Item -Path $expectedDestinationPath
                    $cache = Get-Cache -DestinationPath $expectedDestinationPath -Uri $Uri

                    if ($cache -ne $null -and ($cache.LastWriteTime -eq $file.LastWriteTimeUtc))
                    {
                        Write-Verbose -Message $script:localizedData.CacheReflectsCurrentState
                        $fileExists = $true
                    }
                    else
                    {
                        Write-Verbose -Message $script:localizedData.CacheIsEmptyOrNotMatchCurrentState
                    }
                }
                else
                {
                    Write-Verbose -Message $script:localizedData.MatchSourceFalse
                    $fileExists = $true
                }
            }
        }

        'Other'
        {
            Write-Verbose -Message ($script:localizedData.DestinationPathUnknownType -f $DestinationPath, $pathItemType)
        }

        'NotExists'
        {
            Write-Verbose -Message ($script:localizedData.DestinationPathDoesNotExist -f $DestinationPath)
        }
    }

    $result = $fileExists

    return $result
}

<#
    .SYNOPSIS
        Throws terminating error of category InvalidData with specified errorId and errorMessage
#>
function New-InvalidDataException
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ErrorId,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ErrorMessage
    )

    $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidData
    $exception = New-Object `
        -TypeName System.InvalidOperationException `
        -ArgumentList $ErrorMessage
    $errorRecord = New-Object `
        -TypeName System.Management.Automation.ErrorRecord `
        -ArgumentList $exception, $ErrorId, $errorCategory, $null

    throw $errorRecord
}

<#
    .SYNOPSIS
        Checks whether given URI represents specific scheme

    .DESCRIPTION
        Most common schemes: file, http, https, ftp
        We can also specify logical expressions like: [http|https]
#>
function Test-UriScheme
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Uri,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Scheme
    )

    $newUri = $Uri -as [System.URI]

    return ($newUri.AbsoluteURI -ne $null -and $newUri.Scheme -match $Scheme)
}

<#
    .SYNOPSIS
        Gets type of the item which path points to.

    .OUTPUTS
        File, Directory, Other or NotExists
#>
function Get-PathItemType
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path
    )

    $type = $null

    # Check whether path exists
    if (Test-Path $path)
    {
        # Check type of the path
        $pathItem = Get-Item -Path $Path
        $pathItemType = $pathItem.GetType().Name

        if ($pathItemType -eq 'FileInfo')
        {
            $type = 'File'
        }
        elseif ($pathItemType -eq 'DirectoryInfo')
        {
            $type = 'Directory'
        }
        else
        {
            $type = 'Other'
        }
    }
    else
    {
        $type = 'NotExists'
    }

    return $type
}

<#
    .SYNOPSIS
        Converts CimInstance array of type KeyValuePair to hashtable
#>
function Convert-KeyValuePairArrayToHashtable
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $Array
    )

    $hashtable = @{}

    foreach ($item in $Array)
    {
        $hashtable += @{
            $item.Key = $item.Value
        }
    }

    return $hashtable
}

<#
    .SYNOPSIS
        Gets cache for specific DestinationPath and Uri
#>
function Get-Cache
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DestinationPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Uri
    )

    $cacheContent = $null
    $key = Get-CacheKey -DestinationPath $DestinationPath -Uri $Uri
    $path = Join-Path -Path $script:cacheLocation -ChildPath $key

    Write-Verbose -Message ($script:localizedData.CacheLookingForPath -f $Path)

    if (-not (Test-Path -Path $path))
    {
        Write-Verbose -Message ($script:localizedData.CacheNotFoundForPath -f $DestinationPath, $Uri, $Key)

        $cacheContent = $null
    }
    else
    {
        $cacheContent = Import-CliXml -Path $path
        Write-Verbose -Message ($script:localizedData.CacheFoundForPath -f $DestinationPath, $Uri, $Key)
    }

    return $cacheContent
}

<#
    .SYNOPSIS
        Creates or updates cache for specific DestinationPath and Uri
#>
function Update-Cache
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DestinationPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Uri,

        [Parameter(Mandatory = $true)]
        [System.Object]
        $InputObject
    )

    $key = Get-CacheKey -DestinationPath $DestinationPath -Uri $Uri
    $path = Join-Path -Path $script:cacheLocation -ChildPath $key

    if (-not (Test-Path -Path $script:cacheLocation))
    {
        $null = New-Item -ItemType Directory -Path $script:cacheLocation
    }

    Write-Verbose -Message ($script:localizedData.UpdatingCache -f $DestinationPath, $Uri, $Key)

    Export-CliXml -Path $path -InputObject $InputObject -Force
}

<#
    .SYNOPSIS
        Returns cache key for given parameters
#>
function Get-CacheKey
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DestinationPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Uri
    )

    return [System.String]::Join('', @($DestinationPath, $Uri)).GetHashCode().ToString()
}

Export-ModuleMember -Function Get-TargetResource, Set-TargetResource, Test-TargetResource
