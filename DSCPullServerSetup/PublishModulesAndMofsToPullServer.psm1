<#
    .SYNOPSIS
        Package DSC modules and mof configuration document and publish them on an enterprise DSC pull server in the required format.

    .DESCRIPTION
        Uses Publish-DSCModulesAndMof function to package DSC modules into zip files with the version info.
        Publishes the zip modules on "$env:ProgramFiles\WindowsPowerShell\DscService\Modules".
        Publishes all mof configuration documents that are present in the $Source folder on "$env:ProgramFiles\WindowsPowerShell\DscService\Configuration"-
        Use $Force to overwrite the version of the module that exists in the PowerShell module path with the version from the $source folder.
        Use $ModuleNameList to specify the names of the modules to be published if the modules do not exist in $Source folder.

    .PARAMETER Source
        The folder that contains the configuration mof documents and modules to be published on Pull server.
        Everything in this folder will be packaged and published.

    .PARAMETER Force
        Switch to overwrite the module in PSModulePath with the version provided in $Sources.

    .PARAMETER ModuleNameList
        Package and publish the modules listed in $ModuleNameList based on PowerShell module path content.

    .EXAMPLE
        $ModuleList = @("xWebAdministration", "xPhp")
        Publish-DSCModuleAndMof -Source C:\LocalDepot -ModuleNameList $ModuleList

    .EXAMPLE
        Publish-DSCModuleAndMof -Source C:\LocalDepot -Force
#>
function Publish-DSCModuleAndMof
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $True)]
        [ValidateScript({Test-Path -Path $_})]
        [System.String]
        $Source,

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $Force,

        [Parameter()]
        [System.String[]]
        $ModuleNameList
    )

    # Create working directory
    $tempFolder = Join-Path -Path $Source -ChildPath 'temp'
    New-Item -Path $tempFolder -ItemType Directory -Force -ErrorAction SilentlyContinue

    # Copy the mof documents from the $Source to working dir
    Copy-Item -Path "$Source\*.mof" -Destination $tempFolder -Force

    # Start Deployment!
    Write-LogEntry -Scope $MyInvocation -Message 'Start Deployment'
    Create-ZipFromPSModulePath -ListModuleNames $ModuleNameList -Destination $tempFolder
    Create-ZipFromSource -Source $Source -Destination $tempFolder

    # Generate the checkSum file for all the zip and mof files.
    New-DSCCheckSum -Path $tempFolder -Force

    # Publish mof and modules to pull server repositories
    Publish-ModulesAndChecksum -Source $tempFolder
    Publish-MofsInSource -Source $tempFolder

    # Deployment is complete!
    Remove-Item -Path $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
    Write-LogEntry -Scope $MyInvocation -Message 'End Deployment'
}

<#
    .SYNOPSIS
        Creates a zip archive containing all the modules whose module name was assigned to the parameter ListModuleNames.
        The zip archive is created in the path assigned to the parameter Destination.

    .PARAMETER ListModuleNames
        List of Modules to package

    .PARAMETER Destination
        Destionation path to copy packaged modules to
#>
function Create-ZipFromPSModulePath
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String[]]
        $ListModuleNames,
 
        [Parameter()]
        [ValidateScript({Test-Path -Path $_})]
        [System.String]       
        $Destination
    )

    # Move all required  modules from powershell module path to a temp folder and package them
    if ([System.String]::IsNullOrEmpty($ListModuleNames))
    {
        Write-LogEntry -Scope $MyInvocation -Message 'No additional modules are specified to be packaged.'
    }

    foreach ($module in $ListModuleNames)
    {
        $allVersions = Get-Module -Name $module -ListAvailable

        # Package all versions of the module
        foreach ($moduleVersion in $allVersions)
        {
            $name = $moduleVersion.Name
            $source = "$Destination\$name"

            # Create package zip
            $path = $moduleVersion.ModuleBase
            $version = $moduleVersion.Version.ToString()
            Write-LogEntry -Scope $MyInvocation -Message "Zipping $name ($version)"
            Compress-Archive -Path "$path\*" -DestinationPath "$source.zip" -Force
            $newName = "$Destination\$name" + '_' + "$version" + '.zip'

            # Rename the module folder to contain the version info.
            if (Test-Path $newName)
            {
                Remove-Item $newName -Recurse -Force
            }

            Rename-Item -Path "$source.zip" -NewName $newName -Force
        }
    }
}

<#
    .SYNOPSIS
        Deploys all DSC resource modules in the path assigned to the parameter Source. The DSC resource modules are copied
        to the path '$env:ProgramFiles\WindowsPowerShell\Modules', and also packaged into a zip archive that is saved to
        the path assigned to the parameter Destination.

    .PARAMETER Source
        Folder containing DSC Resource Modules to package

    .PARAMETER Destination
        Destination path to copy zipped DSC Resources to
#>
function Create-ZipFromSource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_})]
        [System.String]
        $Source,
        
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_})]
        $Destination
    )

    # For each module under $Source folder create a zip package that has the same name as the folder.
    $allModulesInSource = Get-ChildItem -Path $Source -Directory
    $modules = @()

    foreach ($item in $allModulesInSource)
    {
        $name = $Item.Name
        $alreadyExists = Get-Module -Name $name -ListAvailable

        if (($null -eq $alreadyExists) -or ($Force))
        {
            # Install the modules into PowerShell module path and overwrite the content
            Copy-Item -Path $item.FullName -Recurse -Force -Destination "$env:ProgramFiles\WindowsPowerShell\Modules"
        }
        else
        {
            Write-Warning -Message "Skipping module overwrite. Module with the name $name already exists."
            Write-Warning -Message "Please specify -Force to overwrite the module with the local version of the module located in $Source or list names of the modules in ModuleNameList parameter to be packaged from PowerShell module pat instead and remove them from $Source folder"
        }

        $modules += @("$name")
    }

    # Package the module in $destination
    Create-ZipFromPSModulePath -ListModuleNames $modules -Destination $Destination
}


<#
    .SYNOPSIS
        Deploy modules to the Pull sever repository.

    .PARAMETER Source
        Folder containing zipped DSC Resources to publish
#>
function Publish-ModulesAndChecksum
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_})]
        [System.String]
        $Source
    )

    # Check if the current machine is a server sku.
    $moduleRepository = "$env:ProgramFiles\WindowsPowerShell\DscService\Modules"

    if ((Get-Module ServerManager -ListAvailable) -and (Test-Path $moduleRepository))
    {
        Write-LogEntry -Scope $MyInvocation -Message "Copying modules and checksums to [$moduleRepository]."
        Copy-Item -Path "$Source\*.zip*" -Destination $moduleRepository -Force
    }
    else
    {
        Write-Warning -Message 'Copying modules to Pull server module repository skipped because the machine is not a server sku or Pull server endpoint is not deployed.'
    }
}

<#
    .SYNOPSIS
        Deploy configurations and their checksums.

    .PARAMETER Source
        Folder containing MOFs to publish
#>
function Publish-MofsInSource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_})]
        [System.String]
        $Source
    )

    # Check if the current machine is a server sku.
    $mofRepository = "$env:ProgramFiles\WindowsPowerShell\DscService\Configuration"

    if ((Get-Module ServerManager -ListAvailable) -and (Test-Path $mofRepository))
    {
        Write-LogEntry -Scope $MyInvocation -Message "Copying mofs and checksums to [$mofRepository]."
        Copy-Item -Path "$Source\*.mof*" -Destination $mofRepository -Force
    }
    else
    {
        Write-Warning -Message 'Copying configuration(s) to Pull server configuration repository skipped because the machine is not a server sku or Pull server endpoint is not deployed.'
    }
}

<#
    .SYNOPSIS
        Writes a version message with the current time, caller, and message.
#>
function Write-LogEntry
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.DateTime]
        $Date = $(Get-Date),

        [Parameter(Mandatory = $true)]
        [System.Object]
        $Scope,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Message
    )

    Write-Verbose -Message "$Date [$($Scope.MyCommand)] :: $Message"
}


<#
    .SYNOPSIS
        Deploy DSC modules to the pullserver.

    .DESCRIPTION
        Publish DSC module using Module Info object as an input.
        The cmdlet will figure out the location of the module repository using web.config of the pullserver.

    .PARAMETER Name
        Name of the module.

    .PARAMETER ModuleBase
        This is the location of the base of the module.

    .PARAMETER Version
        This is the version of the module

    .PARAMETER PullServerWebConfig
        Defaults to $env:SystemDrive\inetpub\wwwroot\PSDSCPullServer\web.config

    .PARAMETER OutputFolderPath
        Defaults to $null

    .EXAMPLE
       Get-Module <ModuleName> | Publish-ModuleToPullServer
#>
function Publish-ModuleToPullServer
{
    [CmdletBinding()]
    [OutputType([System.Void])]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [System.String]
        $ModuleBase,

        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 2)]
        [Version]
        $Version,

        [Parameter()]
        [System.String]
        $PullServerWebConfig = "$env:SystemDrive\inetpub\wwwroot\PSDSCPullServer\web.config",

        [Parameter()]
        [System.String]
        $OutputFolderPath = $null
    )

    Begin
    {
        if (-not($OutputFolderPath))
        {
            if ( -not(Test-Path $PullServerWebConfig))
            {
                throw "Web.Config of the pullserver does not exist on the default path $PullServerWebConfig. Please provide the location of your pullserver web configuration using the parameter -PullServerWebConfig or an alternate path where you want to publish the pullserver modules to"
            }
            else
            {
                # Pull Server exist figure out the module path of the pullserver and use this value as output folder path.
                $webConfigXml = [System.Xml.XmlDocument] (Get-Content -Path $PullServerWebConfig)
                $moduleXElement = $webConfigXml.SelectNodes("//appSettings/add[@key = 'ModulePath']")
                $OutputFolderPath = $moduleXElement.Value
            }
        }
    }
    Process
    {
        Write-Verbose -Message "Name: $Name , ModuleBase : $ModuleBase ,Version: $Version"
        $targetPath = Join-Path $OutputFolderPath "$($Name)_$($Version).zip"

        if (Test-Path $targetPath)
        {
            Compress-Archive -DestinationPath $targetPath -Path "$($ModuleBase)\*" -Update
        }
        else
        {
            Compress-Archive -DestinationPath $targetPath -Path "$($ModuleBase)\*"
        }
    }
    End
    {
        # Now that all the modules are published generate thier checksum.
        New-DscChecksum -Path $OutputFolderPath

    }
}


<#
    .SYNOPSIS
        Deploy DSC Configuration document to the pullserver.

    .DESCRIPTION
        Publish Mof file to the pullserver. It takes File Info object as
        pipeline input. It also auto detects the location of the configuration
repository using the web.config of the pullserver.

    .PARAMETER FullName
        MOF File Name

    .EXAMPLE
        Dir <path>\*.mof | Publish-MOFToPullServer
#>
function Publish-MOFToPullServer
{
    [CmdletBinding()]
    [OutputType([System.Void])]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [System.String]
        $FullName,

        [Parameter()]
        [System.String]
        $PullServerWebConfig = "$env:SystemDrive\inetpub\wwwroot\PSDSCPullServer\web.config"
    )

    Begin
    {
        $webConfigXml = [System.Xml.XmlDocument] (Get-Content -Path $PullServerWebConfig)
        $configXElement = $webConfigXml.SelectNodes("//appSettings/add[@key = 'ConfigurationPath']")
        $OutputFolderPath = $configXElement.Value
    }
    Process
    {
        $fileInfo = New-Item -Path $FullName -ItemType File
        if ($fileInfo.Extension -eq '.mof')
        {
            if (Test-Path -Path $FullName)
            {
                Copy-Item -Path $FullName -Destination $OutputFolderPath -Force
            }
            else
            {
                throw "File not found at $FullName"
            }
        }
        else
        {
            throw "Invalid file $FullName. Only mof files can be copied to the pullserver configuration repository"
        }
    }
    End
    {
        New-DscChecksum -Path $OutputFolderPath -Force
    }
}

Export-ModuleMember -Function Publish-*
