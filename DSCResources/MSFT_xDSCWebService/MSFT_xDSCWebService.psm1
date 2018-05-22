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

            $iisSelfSignedModuleName = "IISSelfSignedCertModule(32bit)"            
            $certNativeModule = Get-WebConfigModulesSetting -WebConfigFullPath $webConfigFullPath -ModuleName $iisSelfSignedModuleName
            if($certNativeModule)
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
        $certificate = ([Array](Get-ChildItem -Path 'Cert:\LocalMachine\My\')).Where{$_.Thumbprint -eq $webBinding.CertificateHash}
        
        $output.Add('CertificateThumbPrint',   $webBinding.CertificateHash)
        $output.Add('CertificateSubject',      $certificate.Subject)
        $output.Add('CertificateTemplateName', $certificate.Extensions.Where{$_.Oid.FriendlyName -eq 'Certificate Template Name'}.Format($false))
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
        [String]$CertificateThumbPrint,

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
    Push-Location -Path "$env:windir\system32\inetsrv"
    $script:appCmd = Get-Command -Name '.\appcmd.exe' -CommandType 'Application'
    Pop-Location
   
    $pathPullServer = "$pshome\modules\PSDesiredStateConfiguration\PullServer"
    $jet4provider = "System.Data.OleDb"
    $jet4database = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=$DatabasePath\Devices.mdb;"
    $eseprovider = "ESENT"
    $esedatabase = "$DatabasePath\Devices.edb"

    $language = (Get-Culture).TwoLetterISOLanguageName

    # the two letter iso languagename is not actually implemented in the source path, it's always 'en'
    if (-not (Test-Path -Path $pathPullServer\$language\Microsoft.Powershell.DesiredStateConfiguration.Service.Resources.dll)) {
        $language = 'en'
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
         if($website -ne $null)
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
                     -dependentMUIFiles  "$pathPullServer\$language\Microsoft.Powershell.DesiredStateConfiguration.Service.Resources.dll" `
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

    $iisSelfSignedModuleAssemblyName = "IISSelfSignedCertModule.dll"
    $iisSelfSignedModuleName = "IISSelfSignedCertModule(32bit)"
    if($AcceptSelfSignedCertificates)
    {        
        $preConditionBitnessArgumentFor32BitInstall=""
        if ($Enable32BitAppOnWin64 -eq $true)
        {
            Write-Verbose -Message "Enabling Pull Server to run in a 32 bit process"
            $sourceFilePath = Join-Path -Path "$env:windir\SysWOW64\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer" -ChildPath $iisSelfSignedModuleAssemblyName
            $destinationFolderPath = "$env:windir\SysWOW64\inetsrv"
            Copy-Item -Path $sourceFilePath -Destination $destinationFolderPath -Force
            $preConditionBitnessArgumentFor32BitInstall = "/preCondition:bitness32"
        }
        else {
            Write-Verbose -Message "Enabling Pull Server to run in a 64 bit process"
        }
        $sourceFilePath = Join-Path -Path "$env:windir\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer" -ChildPath $iisSelfSignedModuleAssemblyName
        $destinationFolderPath = "$env:windir\System32\inetsrv"
        $destinationFilePath = Join-Path -Path $destinationFolderPath -ChildPath $iisSelfSignedModuleAssemblyName
        Copy-Item -Path $sourceFilePath -Destination $destinationFolderPath -Force

        & $script:appCmd install module /name:$iisSelfSignedModuleName /image:$destinationFilePath /add:false /lock:false
        & $script:appCmd add module /name:$iisSelfSignedModuleName  /app.name:"PSDSCPullServer/" $preConditionBitnessArgumentFor32BitInstall
    }
    else
    {
        if(($null -ne $acceptSelfSignedCertificates) -and ($AcceptSelfSignedCertificates -eq $false))
        {
            & $script:appCmd delete module /name:$iisSelfSignedModuleName  /app.name:"PSDSCPullServer/"
        }
    }

    if($UseSecurityBestPractices)
    {
        UseSecurityBestPractices\Set-UseSecurityBestPractices -DisableSecurityBestPractices $DisableSecurityBestPractices
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
        if(($Ensure -eq "Present" -and $website -eq $null))
        {
            $desiredConfigurationMatch = $false            
            Write-Verbose -Message "The Website $EndpointName is not present"
            break       
        }
        if(($Ensure -eq "Absent" -and $website -ne $null))
        {
            $desiredConfigurationMatch = $false            
            Write-Verbose -Message "The Website $EndpointName is present but should not be"
            break       
        }
        if(($Ensure -eq "Absent" -and $website -eq $null))
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
        if($website.state -ne $State -and $State -ne $null)
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
                if (-not (Test-WebConfigModulesSetting -WebConfigFullPath $webConfigFullPath -ModuleName "IISSelfSignedCertModule(32bit)" -ExpectedInstallationStatus $acceptSelfSignedCertificates))
                {
                    $desiredConfigurationMatch = $false
                    break
                }
            }
        }

        Write-Verbose -Message "Check UseSecurityBestPractices"
        if ($UseSecurityBestPractices)
        {
            if (-not (UseSecurityBestPractices\Test-UseSecurityBestPractices -DisableSecurityBestPractices $DisableSecurityBestPractices))
            {
                $desiredConfigurationMatch = $false
                Write-Verbose -Message "The state of security settings does not match the desired state."
                break
            }
        }
        $stop = $false
    }
    While($stop)  

    $desiredConfigurationMatch
}

# Helper function used to validate website path
function Test-WebsitePath
{
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

# Helper function to Test the specified Web.Config App Setting
function Test-WebConfigAppSetting
{
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
        $webConfigXml = [Xml](Get-Content -Path $WebConfigFullPath)
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

# Helper function to Get the specified Web.Config App Setting
function Get-WebConfigAppSetting
{
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
        $webConfigXml = [Xml](Get-Content -Path $WebConfigFullPath)
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

# Helper function to Test the specified Web.Config Modules Setting
function Test-WebConfigModulesSetting
{
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
    
    $returnValue = $false

    if (Test-Path -Path $WebConfigFullPath)
    {
        $webConfigXml = [Xml](Get-Content -Path $WebConfigFullPath)
        $root = $webConfigXml.get_DocumentElement() 

        foreach ($item in $root."system.webServer".modules.add) 
        { 
            if( $item.name -eq $ModuleName ) 
            {
                return $ExpectedInstallationStatus -eq $true
            }
        }
    }

    return $ExpectedInstallationStatus -eq $false
}

# Helper function to Get the specified Web.Config Modules Setting
function Get-WebConfigModulesSetting
{
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
        $webConfigXml = [Xml](Get-Content -Path $WebConfigFullPath)
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

# Helper to get current script Folder
function Get-ScriptFolder
{
    [CmdletBinding()]
    param ()

    $invocation = (Get-Variable -Name MyInvocation -Scope 1).Value
    Split-Path -Path $invocation.MyCommand.Path
}

# Allow this Website to enable/disable specific Auth Schemes by adding <location> tag in applicationhost.config
function Update-LocationTagInApplicationHostConfigForAuthentication
{
    param
    (
        # Name of the WebSite        
        [Parameter(Mandatory = $true)]
        [String]
        $WebSite,

        # Authentication Type
        [Parameter(Mandatory = $true)]
        [ValidateSet('anonymous', 'basic', 'windows')]
        [String]
        $Authentication
    )

    $gacAssemblyVersion = Get-GacAssemblyVersion -AssemblyName 'Microsoft.Web.Administration'

    Add-Type -AssemblyName ($gacAssemblyVersion)

    $webAdminSrvMgr = New-Object -TypeName Microsoft.Web.Administration.ServerManager

    $appHostConfig = $webAdminSrvMgr.GetApplicationHostConfiguration()

    $authenticationType = $Authentication + "Authentication"
    $appHostConfigSection = $appHostConfig.GetSection("system.webServer/security/authentication/$authenticationType", $WebSite)
    $appHostConfigSection.OverrideMode="Allow"
    $webAdminSrvMgr.CommitChanges()
}

function Find-CertificateThumbprintWithSubjectAndTemplateName
{
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

function Get-GacAssemblyVersion
{
    [OutputType([String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $AssemblyName
    )

    return [String] [System.Reflection.Assembly]::LoadWithPartialName($AssemblyName)
}
function Get-OSVersion
{
    [CmdletBinding()]
    param ()

    # Moved to a function to allow for the behaviour to be mocked.
    return [System.Environment]::OSVersion.Version
}

Export-ModuleMember -Function *-TargetResource
