# Import the helper functions
Import-Module -Name $PSScriptRoot\PSWSIISEndpoint.psm1 -Verbose:$false
Import-Module -Name $PSScriptRoot\UseSecurityBestPractices.psm1 -Verbose:$false

#region LocalizedData
$script:culture = 'en-US'

if (Test-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath $PSUICulture))
{
    $script:culture = $PSUICulture
}

$ImportLocalizedDataParams = @{
    BindingVariable = 'LocalizedData'
    Filename        = 'MSFT_xDSCWebService.psd1'
    BaseDirectory   = $PSScriptRoot
    UICulture       = $script:culture
}
Import-LocalizedData @ImportLocalizedDataParams
#endregion

# The Get-TargetResource cmdlet.
function Get-TargetResource
{
    [CmdletBinding(DefaultParameterSetName = 'CertificateThumbPrint')]
    [OutputType([Hashtable])]
    param
    (
        # Prefix of the WCF SVC File
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $EndpointName,

        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(ParameterSetName = 'CertificateThumbPrint')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateThumbPrint,

        # Subject of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(ParameterSetName = 'CertificateSubject')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateSubject,

        # Certificate Template Name of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(ParameterSetName = 'CertificateSubject')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateTemplateName = 'WebServer',

        # Pull Server is created with the most secure practices
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $UseSecurityBestPractices,

        # Exceptions of security best practices
        [Parameter()]
        [ValidateSet("SecureTLSProtocols")]
        [String[]]
        $DisableSecurityBestPractices,

        # When this property is set to true, Pull Server will run on a 32 bit process on a 64 bit machine
        [Parameter()]
        [Boolean]
        $Enable32BitAppOnWin64 = $false
    )

    # If Certificate Subject is not specified then a value for CertificateThumbprint must be explicitly set instead.
    # The Mof schema doesn't allow for a mandatory parameter in a parameter set.
    if ($PScmdlet.ParameterSetName -eq 'CertificateThumbPrint' -and $PSBoundParameters.ContainsKey('CertificateThumbPrint') -ne $true)
    {
        throw $LocalizedData.ThrowCertificateThumbprint
    }

    $webSite = Get-Website -Name $EndpointName

    if ($webSite)
    {
            $Ensure = 'Present'
            $acceptSelfSignedCertificates = $false

            # Get Full Path for Web.config file
            $webConfigFullPath = Join-Path -Path $website.physicalPath -ChildPath "web.config"

            # Get module and configuration path
            $modulePath = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ModulePath"
            $configurationPath = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ConfigurationPath"
            $registrationKeyPath = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "RegistrationKeyPath"

            # Get database path
            switch ((Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "dbprovider"))
            {
                "ESENT" {
                    $databasePath = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "dbconnectionstr" | Split-Path -Parent
                }

                "System.Data.OleDb" {
                    $connectionString = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "dbconnectionstr"
                    if ($connectionString -match 'Data Source=(.*)\\Devices\.mdb')
                    {
                        $databasePath = $Matches[0]
                    }
                    else
                    {
                        $databasePath = $connectionString
                    }
                }
            }

            $urlPrefix = $website.bindings.Collection[0].protocol + "://"

            $fqdn = $env:COMPUTERNAME
            if ($env:USERDNSDOMAIN)
            {
                $fqdn = $env:COMPUTERNAME + "." + $env:USERDNSDOMAIN
            }

            $iisPort = $website.bindings.Collection[0].bindingInformation.Split(":")[1]

            $svcFileName = (Get-ChildItem -Path $website.physicalPath -Filter "*.svc").Name

            $serverUrl = $urlPrefix + $fqdn + ":" + $iisPort + "/" + $svcFileName

            $webBinding = Get-WebBinding -Name $EndpointName

            if((Test-IISSelfSignedModuleEnabled -EndpointName $EndpointName))
            {
                $acceptSelfSignedCertificates = $true
            }
        }
    else
    {
        $Ensure = 'Absent'
    }

    $output = @{
        EndpointName                    = $EndpointName
        Port                            = $iisPort
        PhysicalPath                    = $website.physicalPath
        State                           = $webSite.state
        DatabasePath                    = $databasePath
        ModulePath                      = $modulePath
        ConfigurationPath               = $configurationPath
        DSCServerUrl                    = $serverUrl
        Ensure                          = $Ensure
        RegistrationKeyPath             = $registrationKeyPath
        AcceptSelfSignedCertificates    = $acceptSelfSignedCertificates
        UseSecurityBestPractices        = $UseSecurityBestPractices
        DisableSecurityBestPractices    = $DisableSecurityBestPractices
        Enable32BitAppOnWin64           = $Enable32BitAppOnWin64
    }

    if ($CertificateThumbPrint -eq 'AllowUnencryptedTraffic')
    {
        $output.Add('CertificateThumbPrint', $certificateThumbPrint)
    }
    else
    {
        $certificate = ([Array] (Get-ChildItem -Path 'Cert:\LocalMachine\My\')) | Where-Object -FilterScript {
            $_.Thumbprint -eq $webBinding.CertificateHash
        }

        # Try to parse the Certificate Template Name. The property is not available on all Certificates.
        $actualCertificateTemplateName = ''
        $certificateTemplateProperty = $certificate.Extensions | Where-Object -FilterScript {
            $_.Oid.FriendlyName -eq 'Certificate Template Name'
        }

        if ($null -ne $certificateTemplateProperty)
        {
            $actualCertificateTemplateName = $certificateTemplateProperty.Format($false)
        }

        $output.Add('CertificateThumbPrint',   $webBinding.CertificateHash)
        $output.Add('CertificateSubject',      $certificate.Subject)
        $output.Add('CertificateTemplateName', $actualCertificateTemplateName)
    }

    return $output
}

# The Set-TargetResource cmdlet.
function Set-TargetResource
{
    [CmdletBinding(DefaultParameterSetName = 'CertificateThumbPrint')]
    param
    (
        # Prefix of the WCF SVC File
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $EndpointName,

        # Port number of the DSC Pull Server IIS Endpoint
        [Parameter()]
        [Uint32]
        $Port = 8080,

        # Physical path for the IIS Endpoint on the machine (usually under inetpub)
        [Parameter()]
        [String]
        $PhysicalPath = "$env:SystemDrive\inetpub\$EndpointName",

        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(ParameterSetName = 'CertificateThumbPrint')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateThumbPrint,

        # Subject of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(ParameterSetName = 'CertificateSubject')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateSubject,

        # Certificate Template Name of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(ParameterSetName = 'CertificateSubject')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateTemplateName = 'WebServer',

        [Parameter()]
        [ValidateSet("Present", "Absent")]
        [String]
        $Ensure = "Present",

        [Parameter()]
        [ValidateSet("Started", "Stopped")]
        [String]
        $State = "Started",

        # Location on the disk where the database is stored
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]
        $DatabasePath = "$env:PROGRAMFILES\WindowsPowerShell\DscService",

        # Location on the disk where the Modules are stored
        [Parameter()]
        [String]
        $ModulePath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules",

        # Location on the disk where the Configuration is stored
        [Parameter()]
        [String]
        $ConfigurationPath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration",

        # Location on the disk where the RegistrationKeys file is stored
        [Parameter()]
        [String]
        $RegistrationKeyPath = "$env:PROGRAMFILES\WindowsPowerShell\DscService",

        # Add the IISSelfSignedCertModule native module to prevent self-signed certs being rejected.
        [Parameter()]
        [Boolean]
        $AcceptSelfSignedCertificates = $true,

        # Required Field when user want to enable DSC to use SQL server as backend DB
        [Parameter()]
        [Boolean]
        $SqlProvider = $false,

        # User is required to provide the SQL Connection String with the ServerProvider , ServerName , UserID , and Passwords fields  to enable DSC to use SQL server as backend DB
        [Parameter()]
        [String]
        $SqlConnectionString,

        # Pull Server is created with the most secure practices
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $UseSecurityBestPractices,

        # Exceptions of security best practices
        [Parameter()]
        [ValidateSet("SecureTLSProtocols")]
        [String[]]
        $DisableSecurityBestPractices,

        # When this property is set to true, Pull Server will run on a 32 bit process on a 64 bit machine
        [Parameter()]
        [Boolean]
        $Enable32BitAppOnWin64 = $false
    )

    # If Certificate Subject is not specified then a value for CertificateThumbprint must be explicitly set instead.
    # The Mof schema doesn't allow for a mandatory parameter in a parameter set.
    if ($PScmdlet.ParameterSetName -eq 'CertificateThumbPrint' -and $PSBoundParameters.ContainsKey('CertificateThumbPrint') -ne $true)
    {
        throw $LocalizedData.ThrowCertificateThumbprint
    }

    # Find a certificate that matches the Subject and Template Name
    if ($PSCmdlet.ParameterSetName -eq 'CertificateSubject')
    {
        $certificateThumbPrint = Find-CertificateThumbprintWithSubjectAndTemplateName -Subject $CertificateSubject -TemplateName $CertificateTemplateName
    }

    # Check parameter values
    if ($UseSecurityBestPractices -and ($CertificateThumbPrint -eq "AllowUnencryptedTraffic"))
    {
        throw $LocalizedData.ThrowUseSecurityBestPractice
        # No need to proceed any more
        return
    }

    # Initialize with default values

    $pathPullServer = "$pshome\modules\PSDesiredStateConfiguration\PullServer"
    $jet4provider = "System.Data.OleDb"
    $jet4database = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=$DatabasePath\Devices.mdb;"
    $eseprovider = "ESENT"
    $esedatabase = "$DatabasePath\Devices.edb"

    $cultureInfo = Get-Culture
    $languagePath = $cultureInfo.IetfLanguageTag
    $language = $cultureInfo.TwoLetterISOLanguageName

    # the two letter iso languagename is not actually implemented in the source path, it's always 'en'
    if (-not (Test-Path -Path $pathPullServer\$languagePath\Microsoft.Powershell.DesiredStateConfiguration.Service.Resources.dll))
    {
        $languagePath = 'en'
    }

    $os = Get-OSVersion

    $isBlue = $false
    if($os.Major -eq 6 -and $os.Minor -eq 3)
    {
        $isBlue = $true
    }

    $isDownlevelOfBlue = $false
    if($os.Major -eq 6 -and $os.Minor -lt 3)
    {
        $isDownlevelOfBlue= $true
    }

    # Use Pull Server values for defaults
    $webConfigFileName = "$pathPullServer\PSDSCPullServer.config"
    $svcFileName = "$pathPullServer\PSDSCPullServer.svc"
    $pswsMofFileName = "$pathPullServer\PSDSCPullServer.mof"
    $pswsDispatchFileName = "$pathPullServer\PSDSCPullServer.xml"

    # ============ Absent block to remove existing site =========
    if(($Ensure -eq "Absent"))
    {
         $website = Get-Website -Name $EndpointName
         if($null -ne $website)
         {
            # there is a web site, but there shouldn't be one
            Write-Verbose -Message "Removing web site $EndpointName"
            PSWSIISEndpoint\Remove-PSWSEndpoint -SiteName $EndpointName
         }

         # we are done here, all stuff below is for 'Present'
         return
    }
    # ===========================================================

    Write-Verbose -Message "Create the IIS endpoint"
    PSWSIISEndpoint\New-PSWSEndpoint -site $EndpointName `
                     -path $PhysicalPath `
                     -cfgfile $webConfigFileName `
                     -port $Port `
                     -applicationPoolIdentityType LocalSystem `
                     -app $EndpointName `
                     -svc $svcFileName `
                     -mof $pswsMofFileName `
                     -dispatch $pswsDispatchFileName `
                     -asax "$pathPullServer\Global.asax" `
                     -dependentBinaries  "$pathPullServer\Microsoft.Powershell.DesiredStateConfiguration.Service.dll" `
                     -language $language `
                     -dependentMUIFiles  "$pathPullServer\$languagePath\Microsoft.Powershell.DesiredStateConfiguration.Service.Resources.dll" `
                     -certificateThumbPrint $certificateThumbPrint `
                     -EnableFirewallException $true `
                     -Enable32BitAppOnWin64 $Enable32BitAppOnWin64 `
                     -Verbose

    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "anonymous"
    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "basic"
    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "windows"

    if($SqlProvider)
    {
        Write-Verbose -Message "Set values into the web.config that define the SQL Connection "
        PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $jet4provider
        PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr"-value $SqlConnectionString
        if ($isBlue)
        {
            Set-BindingRedirectSettingInWebConfig -path $PhysicalPath
        }
    }
    elseif ($isBlue)
    {
        Write-Verbose -Message "Set values into the web.config that define the repository for BLUE OS"
        PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $eseprovider
        PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr"-value $esedatabase

        Set-BindingRedirectSettingInWebConfig -path $PhysicalPath
    }
    else
    {
        if($isDownlevelOfBlue)
        {
            Write-Verbose -Message "Set values into the web.config that define the repository for non-BLUE Downlevel OS"
            $repository = Join-Path -Path "$DatabasePath" -ChildPath "Devices.mdb"
            Copy-Item -Path "$pathPullServer\Devices.mdb" -Destination $repository -Force

            PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $jet4provider
            PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr" -value $jet4database
        }
        else
        {
            Write-Verbose -Message "Set values into the web.config that define the repository later than BLUE OS"
            Write-Verbose -Message "Only ESENT is supported on Windows Server 2016"

            PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $eseprovider
            PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr"-value $esedatabase
        }

    }

    Write-Verbose -Message "Pull Server: Set values into the web.config that indicate the location of repository, configuration, modules"

    # Create the application data directory calculated above
    $null = New-Item -path $DatabasePath -itemType "directory" -Force

    $null = New-Item -path "$ConfigurationPath" -itemType "directory" -Force

    PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "ConfigurationPath" -value $configurationPath

    $null = New-Item -path "$ModulePath" -itemType "directory" -Force

    PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "ModulePath" -value $ModulePath

    $null = New-Item -path "$RegistrationKeyPath" -itemType "directory" -Force

    PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "RegistrationKeyPath" -value $registrationKeyPath

    if($AcceptSelfSignedCertificates)
    {
        Write-Verbose -Message 'Accepting self signed certificates from incoming hosts'
        Enable-IISSelfSignedModule -EndpointName $EndpointName -Enable32BitAppOnWin64:$Enable32BitAppOnWin64
    }
    else
    {
        Disable-IISSelfSignedModule -EndpointName $EndpointName
    }

    if($UseSecurityBestPractices)
    {
        UseSecurityBestPractices\Set-UseSecurityBestPractice -DisableSecurityBestPractices $DisableSecurityBestPractices
    }
}

# The Test-TargetResource cmdlet.
function Test-TargetResource
{
    [CmdletBinding(DefaultParameterSetName = 'CertificateThumbPrint')]
    [OutputType([Boolean])]
    param
    (
        # Prefix of the WCF SVC File
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $EndpointName,

        # Port number of the DSC Pull Server IIS Endpoint
        [Parameter()]
        [Uint32]
        $Port = 8080,

        # Physical path for the IIS Endpoint on the machine (usually under inetpub)
        [Parameter()]
        [String]
        $PhysicalPath = "$env:SystemDrive\inetpub\$EndpointName",

        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(ParameterSetName = 'CertificateThumbPrint')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateThumbPrint,

        # Subject of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(ParameterSetName = 'CertificateSubject')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateSubject,

        # Certificate Template Name of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(ParameterSetName = 'CertificateSubject')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateTemplateName = 'WebServer',

        [Parameter()]
        [ValidateSet("Present", "Absent")]
        [String]
        $Ensure = "Present",

        [Parameter()]
        [ValidateSet("Started", "Stopped")]
        [String]
        $State = "Started",

        # Location on the disk where the database is stored
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]
        $DatabasePath = "$env:PROGRAMFILES\WindowsPowerShell\DscService",

        # Location on the disk where the Modules are stored
        [Parameter()]
        [String]
        $ModulePath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules",

        # Location on the disk where the Configuration is stored
        [Parameter()]
        [String]
        $ConfigurationPath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration",

        # Location on the disk where the RegistrationKeys file is stored
        [Parameter()]
        [String]
        $RegistrationKeyPath,

        # Are self-signed certs being accepted for client auth.
        [Parameter()]
        [Boolean]
        $AcceptSelfSignedCertificates,

        # Required Field when user want to enable DSC to use SQL server as backend DB
        [Parameter()]
        [Boolean]
        $SqlProvider = $false,

        # User is required to provide the SQL Connection String with the ServerProvider , ServerName , UserID , and Passwords fields  to enable DSC to use SQL server as backend DB
        [Parameter()]
        [String]
        $SqlConnectionString,

        # Pull Server is created with the most secure practices
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Boolean]
        $UseSecurityBestPractices,

        # Exceptions of security best practices
        [Parameter()]
        [ValidateSet("SecureTLSProtocols")]
        [String[]]
        $DisableSecurityBestPractices,

        # When this property is set to true, Pull Server will run on a 32 bit process on a 64 bit machine
        [Parameter()]
        [Boolean]
        $Enable32BitAppOnWin64 = $false
    )

    # If Certificate Subject is not specified then a value for CertificateThumbprint must be explicitly set instead.
    # The Mof schema doesn't allow for a mandatory parameter in a parameter set.
    if ($PScmdlet.ParameterSetName -eq 'CertificateThumbPrint' -and $PSBoundParameters.ContainsKey('CertificateThumbPrint') -ne $true)
    {
        throw $LocalizedData.ThrowCertificateThumbprint
    }

    $desiredConfigurationMatch = $true

    $website = Get-Website -Name $EndpointName
    $stop = $true

    :WebSiteTests Do
    {
        Write-Verbose -Message "Check Ensure"
        if(($Ensure -eq "Present" -and $null -eq $website))
        {
            $desiredConfigurationMatch = $false
            Write-Verbose -Message "The Website $EndpointName is not present"
            break
        }
        if(($Ensure -eq "Absent" -and $null -ne $website))
        {
            $desiredConfigurationMatch = $false
            Write-Verbose -Message "The Website $EndpointName is present but should not be"
            break
        }
        if(($Ensure -eq "Absent" -and $null -eq $website))
        {
            $desiredConfigurationMatch = $true
            Write-Verbose -Message "The Website $EndpointName is not present as requested"
            break
        }
        # the other case is: Ensure and exist, we continue with more checks

        Write-Verbose -Message "Check Port"
        $actualPort = $website.bindings.Collection[0].bindingInformation.Split(":")[1]
        if ($Port -ne $actualPort)
        {
            $desiredConfigurationMatch = $false
            Write-Verbose -Message "Port for the Website $EndpointName does not match the desired state."
            break
        }

        Write-Verbose -Message 'Check Binding'
        $actualCertificateHash = $website.bindings.Collection[0].certificateHash
        $websiteProtocol       = $website.bindings.collection[0].Protocol

        switch ($PSCmdlet.ParameterSetName)
        {
            'CertificateThumbprint'
            {
#                # If a site had a binding and then has it removed then the certificateHash and certificteStoreName will still be populated

#                if ($CertificateThumbPrint -eq 'AllowUnencryptedTraffic' -and $actualCertificateHash -ne $null)
#                {
#                    $desiredConfigurationMatch = $false
#                    Write-Verbose -Message "Certificate Hash for the Website $EndpointName is not null."
#                    break
#                }

                if ($CertificateThumbPrint -eq 'AllowUnencryptedTraffic' -and $websiteProtocol -ne 'http')
                {
                    $desiredConfigurationMatch = $false
                    Write-Verbose -Message "Website $EndpointName is not configured for http and does not match the desired state."
                    break WebSiteTests
                }

#                if ($CertificateThumbPrint -ne $actualCertificateHash)
#                {
#                    $desiredConfigurationMatch = $false
#                    Write-Verbose -Message "Certificate Hash for the Website $EndpointName does not match the desired state."
#                    break
#                }

                if ($CertificateThumbPrint -ne 'AllowUnencryptedTraffic' -and $websiteProtocol -ne 'https')
                {
                    $desiredConfigurationMatch = $false
                    Write-Verbose -Message "Website $EndpointName is not configured for https and does not match the desired state."
                    break WebSiteTests
                }
            }
            'CertificateSubject'
            {
                $certificateThumbPrint = Find-CertificateThumbprintWithSubjectAndTemplateName -Subject $CertificateSubject -TemplateName $CertificateTemplateName

                if ($CertificateThumbPrint -ne $actualCertificateHash)
                {
                    $desiredConfigurationMatch = $false
                    Write-Verbose -Message "Certificate Hash for the Website $EndpointName does not match the desired state."
                    break WebSiteTests
                }
            }
        }

        Write-Verbose -Message "Check Physical Path property"
        if(Test-WebsitePath -EndpointName $EndpointName -PhysicalPath $PhysicalPath)
        {
            $desiredConfigurationMatch = $false
            Write-Verbose -Message "Physical Path of Website $EndpointName does not match the desired state."
            break
        }

        Write-Verbose -Message "Check State"
        if($website.state -ne $State -and $null -ne $State)
        {
            $desiredConfigurationMatch = $false
            Write-Verbose -Message "The state of Website $EndpointName does not match the desired state."
            break
        }

        Write-Verbose -Message "Get Full Path for Web.config file"
        $webConfigFullPath = Join-Path -Path $website.physicalPath -ChildPath "web.config"

        # Changed from -eq $false to -ne $true as $IsComplianceServer is never set. This section was always being skipped
        if ($IsComplianceServer -ne $true)
        {
            Write-Verbose -Message "Check DatabasePath"
            switch ((Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "dbprovider"))
            {
                "ESENT" {
                    $expectedConnectionString = "$DatabasePath\Devices.edb"
                }
                "System.Data.OleDb" {
                    $expectedConnectionString = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=$DatabasePath\Devices.mdb;"
                }
                default {
                    $expectedConnectionString = [String]::Empty
                }
            }
            if($SqlProvider)
            {
                $expectedConnectionString = $SqlConnectionString
            }

            if (([String]::IsNullOrEmpty($expectedConnectionString)))
            {
                $desiredConfigurationMatch = $false
                Write-Verbose -Message "The DB provider does not have a valid value: 'ESENT' or 'System.Data.OleDb'"
                break
            }

            if (-not (Test-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "dbconnectionstr" -ExpectedAppSettingValue $expectedConnectionString))
            {
                $desiredConfigurationMatch = $false
                break
            }

            Write-Verbose -Message "Check ModulePath"
            if ($ModulePath)
            {
                if (-not (Test-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ModulePath" -ExpectedAppSettingValue $ModulePath))
                {
                    $desiredConfigurationMatch = $false
                    break
                }
            }

            Write-Verbose -Message "Check ConfigurationPath"
            if ($ConfigurationPath)
            {
                if (-not (Test-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ConfigurationPath" -ExpectedAppSettingValue $configurationPath))
                {
                    $desiredConfigurationMatch = $false
                    break
                }
            }

            Write-Verbose -Message "Check RegistrationKeyPath"
            if ($RegistrationKeyPath)
            {
                if (-not (Test-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "RegistrationKeyPath" -ExpectedAppSettingValue $registrationKeyPath))
                {
                    $desiredConfigurationMatch = $false
                    break
                }
            }

            Write-Verbose -Message "Check AcceptSelfSignedCertificates"
            if ($AcceptSelfSignedCertificates)
            {
                Write-Verbose -Message "AcceptSelfSignedCertificates is enabled. Checking if module Selfsigned IIS module is configured for web site at [$webConfigFullPath]."
                if (Test-IISSelfSignedModuleInstalled)
                {
                    if (-not (Test-IISSelfSignedModuleEnabled -EndpointName $EndpointName))
                    {
                        Write-Verbose -Message 'Module not enabled in web site. Current configuration does not match the desired state.'
                        $desiredConfigurationMatch = $false
                        break
                    }
                    else
                    {
                        Write-Verbose -Message 'Module present in web site. Current configuration match the desired state.'
                    }
                }
                else
                {
                    Write-Verbose -Message 'Selfsigned module not installed in IIS. Current configuration does not match the desired state.'
                    $desiredConfigurationMatch = $false
                }
            }
            else
            {
                Write-Verbose -Message "AcceptSelfSignedCertificates is disabled. Checking if module Selfsigned IIS module is NOT configured for web site at [$webConfigFullPath]."
                if (Test-IISSelfSignedModuleInstalled)
                {
                    if (-not (Test-IISSelfSignedModuleEnabled -EndpointName $EndpointName))
                    {
                        Write-Verbose -Message 'Module not enabled in web site. Current configuration does match the desired state.'
                    }
                    else
                    {
                        Write-Verbose -Message 'Module present in web site. Current configuration does not match the desired state.'
                        $desiredConfigurationMatch = $false
                        break
                    }
                }
                else
                {
                    Write-Verbose -Message 'Selfsigned module not installed in IIS. Current configuration does match the desired state.'
                }
            }
        }

        Write-Verbose -Message 'Check UseSecurityBestPractices'
        if ($UseSecurityBestPractices)
        {
            if (-not (UseSecurityBestPractices\Test-UseSecurityBestPractice -DisableSecurityBestPractices $DisableSecurityBestPractices))
            {
                $desiredConfigurationMatch = $false
                Write-Verbose -Message 'The state of security settings does not match the desired state.'
                break
            }
        }
        $stop = $false
    }
    While($stop)

    $desiredConfigurationMatch
}

<#
    .SYNOPSIS
        The function returns the OS version string detected by .Net

    .DESCRIPTION
        The function returns the OS version which ahs been detected by .NET.
        The function is added so that the dectection of the OS is mockable in Pester tests.

    .OUTPUTS
        System.String. The operating system version
#>
function Get-OSVersion
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param ()

    # Moved to a function to allow for the behaviour to be mocked.
    return [System.Environment]::OSVersion.Version
}

#region IIS Utils

<#
    .SYNOPSIS
        Returns the configuration value for a module settings from web.config

    .PARAMETER WebConfigFullPath
        The full path to the web.config

    .PARAMETER ModuleName
        The name of the IIS module

    .OUTPUTS
        System.String. The configured value
#>
function Get-WebConfigModulesSetting
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $WebConfigFullPath,

        [Parameter(Mandatory = $true)]
        [String]
        $ModuleName
    )

    $moduleValue = ""
    if (Test-Path -Path $WebConfigFullPath)
    {
        $webConfigXml = [Xml] (Get-Content -Path $WebConfigFullPath)
        $root = $webConfigXml.get_DocumentElement()

        foreach ($item in $root."system.webServer".modules.add)
        {
            if( $item.name -eq $ModuleName )
            {
                $moduleValue = $item.name
                break
            }
        }
    }

    $moduleValue
}

<#
    .SYNOPSIS
        Unlocks a specifc authentication configuration section for a IIS website

    .PARAMETER WebSite
        The name of the website

    .PARAMETER Authentication
        The authentication section which should be unlocked

    .OUTPUTS
        System.String. The configured value
#>
function Update-LocationTagInApplicationHostConfigForAuthentication
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $WebSite,

        [Parameter(Mandatory = $true)]
        [ValidateSet('anonymous', 'basic', 'windows')]
        [String]
        $Authentication
    )

    $webAdminSrvMgr = Get-IISServerManager
    $appHostConfig = $webAdminSrvMgr.GetApplicationHostConfiguration()

    $authenticationType = $Authentication + 'Authentication'
    $appHostConfigSection = $appHostConfig.GetSection("system.webServer/security/authentication/$authenticationType", $WebSite)
    $appHostConfigSection.OverrideMode = 'Allow'
    $webAdminSrvMgr.CommitChanges()
}

<#
    .SYNOPSIS
        Returns an instance of the Microsoft.Web.Administration.ServerManager

    .OUTPUTS
        Microsoft.Web.Administration.ServerManager. The server manager
#>
function Get-IISServerManager
{
    [CmdletBinding()]
    [OutputType([System.Object])]
    param ()

    $iisInstallPath = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\INetStp' -Name InstallPath).InstallPath
    if (-not $iisInstallPath)
    {
        throw ($LocalizedData.IISInstallationPathNotFound)
    }

    $assyPath = Join-Path -Path $iisInstallPath -ChildPath 'Microsoft.Web.Administration.dll' -Resolve -ErrorAction:SilentlyContinue
    if (-not $assyPath)
    {
        throw ($LocalizedData.IISWebAdministrationAssemblyNotFound)
    }

    $assy = [System.Reflection.Assembly]::LoadFrom($assyPath)
    return [System.Activator]::CreateInstance($assy.FullName, 'Microsoft.Web.Administration.ServerManager').Unwrap()
}

<#
    .SYNOPSIS
        Tests if a module installation status is equal to an expected status.

    .PARAMETER WebConfigFullPath
        The full path to the web.config

    .PARAMETER ModuleName
        The name of the IIS module for which the state should be checked

    .PARAMETER ExpectedInstallationStatus
        Test if the module is installed ($true) or absent ($false)

    .OUTPUTS
        System.Boolean. true if the current installation status is equal to the expected installation status
#>
function Test-WebConfigModulesSetting
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $WebConfigFullPath,

        [Parameter(Mandatory = $true)]
        [String]
        $ModuleName,

        [Parameter(Mandatory = $true)]
        [Boolean]
        $ExpectedInstallationStatus
    )

    if (Test-Path -Path $WebConfigFullPath)
    {
        $webConfigXml = [Xml] (Get-Content -Path $WebConfigFullPath)
        $root = $webConfigXml.get_DocumentElement()

        foreach ($item in $root."system.webServer".modules.add)
        {
            if( $item.name -eq $ModuleName )
            {
                return $ExpectedInstallationStatus -eq $true
            }
        }
    }
    else
    {
        Write-Warning -Message "Test-WebConfigModulesSetting: web.config file not found at [$WebConfigFullPath]"
    }
    return $ExpectedInstallationStatus -eq $false
}

<#
    .SYNOPSIS
        Tests if a the currently configured path for a website is equal to a given path

    .PARAMETER EndpointName
        The endpoint name (website name) to test

    .PARAMETER PhysicalPath
        The full physical path to check

    .OUTPUTS
        System.Boolean. true if the current installation status is equal to the expected installation status
#>
function Test-WebsitePath
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $EndpointName,

        [Parameter(Mandatory = $true)]
        [String]
        $PhysicalPath
    )

    $pathNeedsUpdating = $false

    if((Get-ItemProperty -Path "IIS:\Sites\$EndpointName" -Name physicalPath) -ne $PhysicalPath)
    {
        $pathNeedsUpdating = $true
    }

    $pathNeedsUpdating
}

<#
    .SYNOPSIS
        Test if a currently configured app setting is equal to a given value

    .PARAMETER WebConfigFullPath
        The full path to the web.config

    .PARAMETER AppSettingName
        The app setting name to check

    .PARAMETER ExpectedAppSettingValue
        The expected value

    .OUTPUTS
        System.Boolean. true if the current value is equal to the expected value
#>
function Test-WebConfigAppSetting
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $WebConfigFullPath,

        [Parameter(Mandatory = $true)]
        [String]
        $AppSettingName,

        [Parameter(Mandatory = $true)]
        [String]
        $ExpectedAppSettingValue
    )

    $returnValue = $true

    if (Test-Path -Path $WebConfigFullPath)
    {
        $webConfigXml = [Xml] (Get-Content -Path $WebConfigFullPath)
        $root = $webConfigXml.get_DocumentElement()

        foreach ($item in $root.appSettings.add)
        {
            if( $item.key -eq $AppSettingName )
            {
                break
            }
        }

        if($item.value -ne $ExpectedAppSettingValue)
        {
            $returnValue = $false
            Write-Verbose -Message "The state of Web.Config AppSetting $AppSettingName does not match the desired state."
        }

    }
    $returnValue
}

<#
    .SYNOPSIS
        Helper function to Get the specified Web.Config App Setting

    .PARAMETER WebConfigFullPath
        The full path to the web.config

    .PARAMETER AppSettingName
        The app settings name to get the value for

    .OUTPUTS
        System.String. the current app settings value
#>
function Get-WebConfigAppSetting
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $WebConfigFullPath,

        [Parameter(Mandatory = $true)]
        [String]
        $AppSettingName
    )

    $appSettingValue = ""
    if (Test-Path -Path $WebConfigFullPath)
    {
        $webConfigXml = [Xml] (Get-Content -Path $WebConfigFullPath)
        $root = $webConfigXml.get_DocumentElement()

        foreach ($item in $root.appSettings.add)
        {
            if( $item.key -eq $AppSettingName )
            {
                $appSettingValue = $item.value
                break
            }
        }
    }

    $appSettingValue
}

#endregion

#region IIS Selfsigned Certficate Module

New-Variable -Name iisSelfSignedModuleAssemblyName -Value 'IISSelfSignedCertModule.dll' -Option ReadOnly -Scope Script
New-Variable -Name iisSelfSignedModuleName -Value 'IISSelfSignedCertModule(32bit)' -Option ReadOnly -Scope Script

<#
    .SYNOPSIS
        Get a powershell command instance for appcmd.exe

    .OUTPUTS
        System.Management.Automation.CommandInfo. The appcmd.exe
#>
function Get-IISAppCmd
{
    [CmdletBinding()]
    [OutputType([System.Management.Automation.CommandInfo])]
    param()

    Push-Location -Path "$env:windir\system32\inetsrv"
    $appCmd = Get-Command -Name '.\appcmd.exe' -CommandType 'Application' -ErrorAction:Stop
    Pop-Location
    $appCmd
}

<#
    .SYNOPSIS
        Tests if two files differ

    .PARAMETER SourceFilePath
        Path to the source file

    .PARAMETER DestinationFilePath
        Path to the destination file

    .OUTPUTS
        System.Boolean. true if the two files differ
#>
function Test-FilesDiffer
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory  = $true)]
        [ValidateScript({ Test-Path -PathType Leaf -LiteralPath $_ })]
        [String]
        $SourceFilePath,

        [Parameter()]
        [String]
        $DestinationFilePath
    )

    Write-Verbose -Message "Testing for file difference between $SourceFilePath and $DestinationFilePath"

    if (Test-Path -LiteralPath $DestinationFilePath)
    {
        if (Test-Path -LiteralPath $DestinationFilePath -PathType Container)
        {
            throw "$DestinationFilePath is a container (Directory) not a leaf (File)"
        }
        Write-Verbose -Message "Destination file already exists at $DestinationFilePath"

        $md5Dest = Get-FileHash -LiteralPath $destinationFilePath -Algorithm MD5
        $md5Src = Get-FileHash -LiteralPath $sourceFilePath -Algorithm MD5
        return $md5Src.Hash -ne $md5Dest.Hash
    }
    else
    {
        Write-Verbose -Message "Destination file does not exist at $DestinationFilePath"
        return $true
    }
}

<#
    .SYNOPSIS
        Tests if the IISSelfSignedModule module is installed

    .OUTPUTS
        System.Boolean. true if the module is installed
#>
function Test-IISSelfSignedModuleInstalled
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()

    ('' -ne ((& (Get-IISAppCmd) list config -section:system.webServer/globalModules) -like "*$iisSelfSignedModuleName*"))
}

<#
    .SYNOPSIS
        Install the IISSelfSignedModule module

    .PARAMETER Enable32BitAppOnWin64
        If set install the module as 32bit module
#>
function Install-IISSelfSignedModule
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [Switch]
        $Enable32BitAppOnWin64
    )

    if ($Enable32BitAppOnWin64)
    {
        Write-Verbose -Message "Install-IISSelfSignedModule: Providing $iisSelfSignedModuleAssemblyName to run in a 32 bit process"

        $sourceFilePath = Join-Path -Path "$env:windir\SysWOW64\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer" `
            -ChildPath $iisSelfSignedModuleAssemblyName
        $destinationFolderPath = "$env:windir\SysWOW64\inetsrv"

        Copy-Item -Path $sourceFilePath -Destination $destinationFolderPath -Force
    }

    if (Test-IISSelfSignedModuleInstalled)
    {
        Write-Verbose -Message "Install-IISSelfSignedModule: module $iisSelfSignedModuleName already installed"
    }
    else
    {
        Write-Verbose -Message "Install-IISSelfSignedModule: Installing module $iisSelfSignedModuleName"
        $sourceFilePath = Join-Path -Path "$env:windir\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer" `
            -ChildPath $iisSelfSignedModuleAssemblyName
        $destinationFolderPath = "$env:windir\System32\inetsrv"
        $destinationFilePath = Join-Path -Path $destinationFolderPath `
            -ChildPath $iisSelfSignedModuleAssemblyName

        if (Test-FilesDiffer -SourceFilePath $sourceFilePath -DestinationFilePath $destinationFilePath)
        {
            # Might fail if the DLL has already been loaded by the IIS from a former PullServer Deployment
            Copy-Item -Path $sourceFilePath -Destination $destinationFolderPath -Force
        }
        else
        {
            Write-Verbose -Message "Install-IISSelfSignedModule: module $iisSelfSignedModuleName already installed at $destinationFilePath with the correct version"
        }

        Write-Verbose -Message "Install-IISSelfSignedModule: globally activating module $iisSelfSignedModuleName"
        & (Get-IISAppCmd) install module /name:$iisSelfSignedModuleName /image:$destinationFilePath /add:false /lock:false
    }
}

<#
    .SYNOPSIS
        Enable the IISSelfSignedModule module for a specific website (endpoint)

    .PARAMETER EndpointName
        The endpoint (website) for which the module should be enabled

    .PARAMETER Enable32BitAppOnWin64
        If set enable the module as a 32bit module
#>
function Enable-IISSelfSignedModule
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $EndpointName,

        [Parameter()]
        [Switch]
        $Enable32BitAppOnWin64
    )

    Write-Verbose -Message "Enable-IISSelfSignedModule: EndpointName [$EndpointName]; Enable32BitAppOnWin64 [$Enable32BitAppOnWin64]"

    Install-IISSelfSignedModule -Enable32BitAppOnWin64:$Enable32BitAppOnWin64
    $preConditionBitnessArgumentFor32BitInstall=""
    if ($Enable32BitAppOnWin64)
    {
        $preConditionBitnessArgumentFor32BitInstall = "/preCondition:bitness32"
    }
    & (Get-IISAppCmd) add module /name:$iisSelfSignedModuleName /app.name:"$EndpointName/" $preConditionBitnessArgumentFor32BitInstall
}

<#
    .SYNOPSIS
        Disable the IISSelfSignedModule module for a specific website (endpoint)

    .PARAMETER EndpointName
        The endpoint (website) for which the module should be disabled
#>
function Disable-IISSelfSignedModule
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$EndpointName
    )
    Write-Verbose -Message "Disable-IISSelfSignedModule: EndpointName [$EndpointName]"

    & (Get-IISAppCmd) delete module /name:$iisSelfSignedModuleName  /app.name:"$EndpointName/"
}

<#
    .SYNOPSIS
        Tests if the IISSelfSignedModule module is enabled for a website (endpoint)

    .PARAMETER EndpointName
        The endpoint (website) for which the status should be checked

    .OUTPUTS
        System.Boolean. true if the module is enabled
#>
function Test-IISSelfSignedModuleEnabled
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $EndpointName
    )

    Write-Verbose -Message "Test-IISSelfSignedModuleEnabled: EndpointName [$EndpointName]"

    $webSite = Get-Website -Name $EndpointName

    if ($webSite)
    {
        $webConfigFullPath = Join-Path -Path $website.physicalPath -ChildPath "web.config"
        Write-Verbose -Message "Test-IISSelfSignedModuleEnabled: web.confg path [$webConfigFullPath]"
        Test-WebConfigModulesSetting -WebConfigFullPath $webConfigFullPath -ModuleName $iisSelfSignedModuleName -ExpectedInstallationStatus $true
    }
    else
    {
        Write-Error -Message "Website [$EndpointName] not found"
    }
}

#endregion

#region Certificate Utils

<#
    .SYNOPSIS
        Returns a certificate thumbprint from a certificate with a matching subject.

    .DESCRIPTION
        Retreives a list of certificates from the a certificate store.
        From this list all certificates will be checked to see if they match the supplied Subject and Template.
        If one certificate is found the thumbrpint is returned. Otherwise an error is thrown.

    .PARAMETER Subject
        The subject of the certificate to find the thumbprint of.

    .PARAMETER TemplateName
        The template used to create the certificate to find the subject of.

    .PARAMETER Store
        The certificate store to retrieve certificates from.
#>
function Find-CertificateThumbprintWithSubjectAndTemplateName
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Subject,

        [Parameter(Mandatory = $true)]
        [String]
        $TemplateName,

        [Parameter()]
        [String]
        $Store = 'Cert:\LocalMachine\My'
    )

    # 1.3.6.1.4.1.311.20.2 = Certificate Template Name
    # 1.3.6.1.4.1.311.21.7 = Certificate Template Information

    $filteredCertificates = @()

    foreach ($oidFriendlyName in 'Certificate Template Name', 'Certificate Template Information')
    {
        # Only get certificates created from a template otherwise filtering by subject and template name will cause errors
        [Array] $certificatesFromTemplates = (Get-ChildItem -Path $Store).Where{
            $_.Extensions.Oid.FriendlyName -contains $oidFriendlyName
        }

        switch ($oidFriendlyName)
        {
            'Certificate Template Name'        {$templateMatchString = $TemplateName}
            'Certificate Template Information' {$templateMatchString = '^Template={0}' -f $TemplateName}
        }

        $filteredCertificates += $certificatesFromTemplates.Where{
            $_.Subject -eq $Subject -and
            $_.Extensions.Where{
                $_.Oid.FriendlyName -eq $oidFriendlyName
            }.Format($false) -match $templateMatchString
        }
    }

    if ($filteredCertificates.Count -eq 1)
    {
        return $filteredCertificates.Thumbprint
    }
    elseif ($filteredCertificates.Count -gt 1)
    {
        throw ($LocalizedData.FindCertificateBySubjectMultiple -f $Subject, $TemplateName)
    }
    else
    {
        throw ($LocalizedData.FindCertificateBySubjectNotFound -f $Subject, $TemplateName)
    }
}

#endregion

Export-ModuleMember -Function *-TargetResource
