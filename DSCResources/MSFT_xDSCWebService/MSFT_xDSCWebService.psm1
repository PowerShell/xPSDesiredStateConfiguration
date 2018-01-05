# Import the helper functions
Import-Module $PSScriptRoot\PSWSIISEndpoint.psm1 -Verbose:$false
Import-Module $PSScriptRoot\UseSecurityBestPractices.psm1 -Verbose:$false

# The Get-TargetResource cmdlet.
function Get-TargetResource
{
    [OutputType([Hashtable])]
    param
    (
        # Prefix of the WCF SVC File
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointName,
            
        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server   
        [Parameter(ParameterSetName = 'CertificateThumbPrint')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbPrint,

        # Subject of the Certificate in CERT:\LocalMachine\MY\ for Pull Server   
        [Parameter(ParameterSetName = 'CertificateSubject')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateSubject,

        # Certificate Template Name of the Certificate in CERT:\LocalMachine\MY\ for Pull Server   
        [Parameter(ParameterSetName = 'CertificateSubject')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateTemplateName = 'WebServer',

        # Pull Server is created with the most secure practices
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [bool]$UseSecurityBestPractices,

        # Exceptions of security best practices
        [ValidateSet("SecureTLSProtocols")]
        [string[]] $DisableSecurityBestPractices,

        # When this property is set to true, Pull Server will run on a 32 bit process on a 64 bit machine
        [bool]$Enable32BitAppOnWin64 = $false
    )

    $webSite = Get-Website -Name $EndpointName

    if ($webSite)
    {
            $Ensure = 'Present'
            $AcceptSelfSignedCertificates = $false
                
            # Get Full Path for Web.config file    
            $webConfigFullPath = Join-Path $website.physicalPath "web.config"

            # Get module and configuration path
            $modulePath = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ModulePath"
            $ConfigurationPath = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ConfigurationPath"
            $RegistrationKeyPath = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "RegistrationKeyPath"

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
                }
            }

            $UrlPrefix = $website.bindings.Collection[0].protocol + "://"

            $fqdn = $env:COMPUTERNAME
            if ($env:USERDNSDOMAIN)
            {
                $fqdn = $env:COMPUTERNAME + "." + $env:USERDNSDOMAIN
            }

            $iisPort = $website.bindings.Collection[0].bindingInformation.Split(":")[1]
                        
            $svcFileName = (Get-ChildItem -Path $website.physicalPath -Filter "*.svc").Name

            $serverUrl = $UrlPrefix + $fqdn + ":" + $iisPort + "/" + $svcFileName

            $webBinding = Get-WebBinding -Name $EndpointName

            $iisSelfSignedModuleName = "IISSelfSignedCertModule(32bit)"            
            $certNativeModule = Get-WebConfigModulesSetting -WebConfigFullPath $webConfigFullPath -ModuleName $iisSelfSignedModuleName
            if($certNativeModule)
            {
                $AcceptSelfSignedCertificates = $true
            }
        }
    else
    {
        $Ensure = 'Absent'
    }

    $Output = @{
        EndpointName                    = $EndpointName
        Port                            = $iisPort
        PhysicalPath                    = $website.physicalPath
        State                           = $webSite.state
        DatabasePath                    = $databasePath
        ModulePath                      = $modulePath
        ConfigurationPath               = $ConfigurationPath
        DSCServerUrl                    = $serverUrl
        Ensure                          = $Ensure
        RegistrationKeyPath             = $RegistrationKeyPath
        AcceptSelfSignedCertificates    = $AcceptSelfSignedCertificates
        UseSecurityBestPractices        = $UseSecurityBestPractices
        DisableSecurityBestPractices    = $DisableSecurityBestPractices
        Enable32BitAppOnWin64           = $Enable32BitAppOnWin64
    }

    if ($CertificateThumbPrint -eq 'AllowUnencryptedTraffic')
    {
        $Output.Add('CertificateThumbPrint', $CertificateThumbPrint)
    }
    else
    {
        $Certificate = ([Array](Get-ChildItem -Path 'Cert:\LocalMachine\My\')).Where{$_.Thumbprint -eq $webBinding.CertificateHash}
        
        $Output.Add('CertificateThumbPrint',   $webBinding.CertificateHash)
        $Output.Add('CertificateSubject',      $Certificate.Subject)
        $Output.Add('CertificateTemplateName', $Certificate.Extensions.Where{$_.Oid.FriendlyName -eq 'Certificate Template Name'}.Format($false))
    }

    return $Output
}

# The Set-TargetResource cmdlet.
function Set-TargetResource
{
    param
    (
        # Prefix of the WCF SVC File
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointName,

        # Port number of the DSC Pull Server IIS Endpoint
        [Uint32]$Port = 8080,

        # Physical path for the IIS Endpoint on the machine (usually under inetpub)                            
        [string]$PhysicalPath = "$env:SystemDrive\inetpub\$EndpointName",

        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server   
        [Parameter(ParameterSetName = 'CertificateThumbPrint')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbPrint,

        # Subject of the Certificate in CERT:\LocalMachine\MY\ for Pull Server   
        [Parameter(ParameterSetName = 'CertificateSubject')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateSubject,

        # Certificate Template Name of the Certificate in CERT:\LocalMachine\MY\ for Pull Server   
        [Parameter(ParameterSetName = 'CertificateSubject')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateTemplateName = 'WebServer',

        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

        [ValidateSet("Started", "Stopped")]
        [string]$State = "Started",

        # Location on the disk where the database is stored
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DatabasePath = "$env:PROGRAMFILES\WindowsPowerShell\DscService",

        # Location on the disk where the Modules are stored            
        [string]$ModulePath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules",

        # Location on the disk where the Configuration is stored                    
        [string]$ConfigurationPath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration",

        # Location on the disk where the RegistrationKeys file is stored                    
        [string]$RegistrationKeyPath = "$env:PROGRAMFILES\WindowsPowerShell\DscService",

        # Add the IISSelfSignedCertModule native module to prevent self-signed certs being rejected.
        [boolean]$AcceptSelfSignedCertificates = $true,

        # Pull Server is created with the most secure practices
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [bool]$UseSecurityBestPractices,

        # Exceptions of security best practices
        [ValidateSet("SecureTLSProtocols")]
        [string[]] $DisableSecurityBestPractices,

        # When this property is set to true, Pull Server will run on a 32 bit process on a 64 bit machine
        [boolean]$Enable32BitAppOnWin64 = $false
    )

    # Find a certificate that matches the Subject and Template Name
    if ($PSCmdlet.ParameterSetName -eq 'CertificateSubject')
    {
        $CertificateThumbPrint = Find-CertificateThumbprintWithSubjectAndTemplateName -Subject $CertificateSubject -TemplateName $CertificateTemplateName
    }

    # Check parameter values
    if ($UseSecurityBestPractices -and ($CertificateThumbPrint -eq "AllowUnencryptedTraffic"))
    {
        throw "Error: Cannot use best practice security settings with unencrypted traffic. Please set UseSecurityBestPractices to `$false or use a certificate to encrypt pull server traffic."
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
    $eseprovider = "ESENT";
    $esedatabase = "$DatabasePath\Devices.edb";

    $culture = Get-Culture
    $language = $culture.TwoLetterISOLanguageName
    # the two letter iso languagename is not actually implemented in the source path, it's always 'en'
    if (-not (Test-Path $pathPullServer\$language\Microsoft.Powershell.DesiredStateConfiguration.Service.Resources.dll)) {
        $language = 'en'
    }

    #$os = [System.Environment]::OSVersion.Version
    $os = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property `
        @{N='Major'; E={$_.Version.Split('.')[0]}}, `
        @{N='Minor'; E={$_.Version.Split('.')[1]}}, `
        @{N='Build'; E={$_.Version.Split('.')[2]}}
    $IsBlue = $false;
    if($os.Major -eq 6 -and $os.Minor -eq 3)
    {
        $IsBlue = $true;
    }

    $isDownlevelOfBlue = $false;
    if($os.Major -eq 6 -and $os.Minor -lt 3)
    {
        $isDownlevelOfBlue= $true;
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
            Write-Verbose "Removing web site $EndpointName"
            PSWSIISEndpoint\Remove-PSWSEndpoint -SiteName $EndpointName
         }

         # we are done here, all stuff below is for 'Present'
         return 
    }
    # ===========================================================
                
    Write-Verbose "Create the IIS endpoint"    
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
                     -certificateThumbPrint $CertificateThumbPrint `
                     -EnableFirewallException $true `
                     -Enable32BitAppOnWin64 $Enable32BitAppOnWin64 `
                     -Verbose

    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "anonymous"
    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "basic"
    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "windows"
        
    if ($IsBlue)
    {
        Write-Verbose "Set values into the web.config that define the repository for BLUE OS"
        PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $eseprovider
        PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr"-value $esedatabase
        Set-BindingRedirectSettingInWebConfig -path $PhysicalPath
    }
    else
    {
        if($isDownlevelOfBlue)
        {
            Write-Verbose "Set values into the web.config that define the repository for non-BLUE Downlevel OS"
            $repository = Join-Path "$DatabasePath" "Devices.mdb"
            Copy-Item "$pathPullServer\Devices.mdb" $repository -Force

            PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $jet4provider
            PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr" -value $jet4database
        }
        else
        {
            Write-Verbose "Set values into the web.config that define the repository later than BLUE OS"
            Write-Verbose "Only ESENT is supported on Windows Server 2016"

            PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $eseprovider
            PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr"-value $esedatabase
        }
    }

    Write-Verbose "Pull Server: Set values into the web.config that indicate the location of repository, configuration, modules"

    # Create the application data directory calculated above
    $null = New-Item -path $DatabasePath -itemType "directory" -Force

    $null = New-Item -path "$ConfigurationPath" -itemType "directory" -Force

    PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "ConfigurationPath" -value $ConfigurationPath

    $null = New-Item -path "$ModulePath" -itemType "directory" -Force

    PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "ModulePath" -value $ModulePath

    $null = New-Item -path "$RegistrationKeyPath" -itemType "directory" -Force

    PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "RegistrationKeyPath" -value $RegistrationKeyPath

    $iisSelfSignedModuleAssemblyName = "IISSelfSignedCertModule.dll"
    $iisSelfSignedModuleName = "IISSelfSignedCertModule(32bit)"
    if($AcceptSelfSignedCertificates)
    {        
        $preConditionBitnessArgumentFor32BitInstall=""
        if ($Enable32BitAppOnWin64 -eq $true)
        {
            Write-Verbose "Enabling Pull Server to run in a 32 bit process"
            $sourceFilePath = Join-Path "$env:windir\SysWOW64\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer" $iisSelfSignedModuleAssemblyName
            $destinationFolderPath = "$env:windir\SysWOW64\inetsrv"
            Copy-Item $sourceFilePath $destinationFolderPath -Force
            $preConditionBitnessArgumentFor32BitInstall = "/preCondition:bitness32"
        }
        else {
            Write-Verbose "Enabling Pull Server to run in a 64 bit process"
        }
        $sourceFilePath = Join-Path "$env:windir\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer" $iisSelfSignedModuleAssemblyName
        $destinationFolderPath = "$env:windir\System32\inetsrv"
        $destinationFilePath = Join-Path $destinationFolderPath $iisSelfSignedModuleAssemblyName
        Copy-Item $sourceFilePath $destinationFolderPath -Force

        & $script:appCmd install module /name:$iisSelfSignedModuleName /image:$destinationFilePath /add:false /lock:false
        & $script:appCmd add module /name:$iisSelfSignedModuleName  /app.name:"PSDSCPullServer/" $preConditionBitnessArgumentFor32BitInstall
    }
    else
    {
        & $script:appCmd delete module /name:$iisSelfSignedModuleName  /app.name:"PSDSCPullServer/"
    }

    if($UseSecurityBestPractices)
    {
        UseSecurityBestPractices\Set-UseSecurityBestPractices -DisableSecurityBestPractices $DisableSecurityBestPractices
    }
}

# The Test-TargetResource cmdlet.
function Test-TargetResource
{
    [OutputType([Boolean])]
    param
    (
        # Prefix of the WCF SVC File
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointName,

        # Port number of the DSC Pull Server IIS Endpoint
        [Uint32]$Port = 8080,

        # Physical path for the IIS Endpoint on the machine (usually under inetpub)                            
        [string]$PhysicalPath = "$env:SystemDrive\inetpub\$EndpointName",

        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(ParameterSetName = 'CertificateThumbPrint')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbPrint = "AllowUnencryptedTraffic",

        # Subject of the Certificate in CERT:\LocalMachine\MY\ for Pull Server   
        [Parameter(ParameterSetName = 'CertificateSubject')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateSubject,

        # Certificate Template Name of the Certificate in CERT:\LocalMachine\MY\ for Pull Server   
        [Parameter(ParameterSetName = 'CertificateSubject')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateTemplateName = 'WebServer',

        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

        [ValidateSet("Started", "Stopped")]
        [string]$State = "Started",

        # Location on the disk where the database is stored
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DatabasePath = "$env:PROGRAMFILES\WindowsPowerShell\DscService",

        # Location on the disk where the Modules are stored            
        [string]$ModulePath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules",

        # Location on the disk where the Configuration is stored                    
        [string]$ConfigurationPath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration",

        # Location on the disk where the RegistrationKeys file is stored                    
        [string]$RegistrationKeyPath,

        # Are self-signed certs being accepted for client auth.
        [boolean]$AcceptSelfSignedCertificates,

        # Pull Server is created with the most secure practices
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [bool]$UseSecurityBestPractices,

        # Exceptions of security best practices
        [ValidateSet("SecureTLSProtocols")]
        [string[]] $DisableSecurityBestPractices,

        # When this property is set to true, Pull Server will run on a 32 bit process on a 64 bit machine
        [bool]$Enable32BitAppOnWin64 = $false
    )

    $desiredConfigurationMatch = $true;

    $website = Get-Website -Name $EndpointName
    $stop = $true

    :WebSiteTests Do
    {
        Write-Verbose "Check Ensure"
        if(($Ensure -eq "Present" -and $website -eq $null))
        {
            $DesiredConfigurationMatch = $false            
            Write-Verbose "The Website $EndpointName is not present"
            break       
        }
        if(($Ensure -eq "Absent" -and $website -ne $null))
        {
            $DesiredConfigurationMatch = $false            
            Write-Verbose "The Website $EndpointName is present but should not be"
            break       
        }
        if(($Ensure -eq "Absent" -and $website -eq $null))
        {
            $DesiredConfigurationMatch = $true            
            Write-Verbose "The Website $EndpointName is not present as requested"
            break       
        }
        # the other case is: Ensure and exist, we continue with more checks

        Write-Verbose "Check Port"
        $actualPort = $website.bindings.Collection[0].bindingInformation.Split(":")[1]
        if ($Port -ne $actualPort)
        {
            $DesiredConfigurationMatch = $false
            Write-Verbose "Port for the Website $EndpointName does not match the desired state."
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
#                    $DesiredConfigurationMatch = $false
#                    Write-Verbose -Message "Certificate Hash for the Website $EndpointName is not null."
#                    break
#                }

                if ($CertificateThumbPrint -eq 'AllowUnencryptedTraffic' -and $websiteProtocol -ne 'http')
                {
                    $DesiredConfigurationMatch = $false
                    Write-Verbose -Message "Website $EndpointName is not configured for http and does not match the desired state."
                    break WebSiteTests
                }

#                if ($CertificateThumbPrint -ne $actualCertificateHash)
#                {
#                    $DesiredConfigurationMatch = $false
#                    Write-Verbose -Message "Certificate Hash for the Website $EndpointName does not match the desired state."
#                    break       
#                }

                if ($CertificateThumbPrint -ne 'AllowUnencryptedTraffic' -and $websiteProtocol -ne 'https')
                {
                    $DesiredConfigurationMatch = $false
                    Write-Verbose -Message "Website $EndpointName is not configured for https and does not match the desired state."
                    break WebSiteTests
                }
            }
            'CertificateSubject'
            {
                $CertificateThumbPrint = Find-CertificateThumbprintWithSubjectAndTemplateName -Subject $CertificateSubject -TemplateName $CertificateTemplateName

                if ($CertificateThumbPrint -ne $actualCertificateHash)
                {
                    $DesiredConfigurationMatch = $false
                    Write-Verbose -Message "Certificate Hash for the Website $EndpointName does not match the desired state."
                    break WebSiteTests
                }
            }
        }

        Write-Verbose "Check Physical Path property"
        if(Test-WebsitePath -EndpointName $EndpointName -PhysicalPath $PhysicalPath)
        {
            $DesiredConfigurationMatch = $false
            Write-Verbose "Physical Path of Website $EndpointName does not match the desired state."
            break
        }

        Write-Verbose "Check State"
        if($website.state -ne $State -and $State -ne $null)
        {
            $DesiredConfigurationMatch = $false
            Write-Verbose "The state of Website $EndpointName does not match the desired state."
            break      
        }

        Write-Verbose "Get Full Path for Web.config file"
        $webConfigFullPath = Join-Path $website.physicalPath "web.config"
        if ($IsComplianceServer -ne $true)
        {
            Write-Verbose "Check DatabasePath"
            switch ((Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "dbprovider"))
            {
                "ESENT" {
                    $expectedConnectionString = "$DatabasePath\Devices.edb"
                }
                "System.Data.OleDb" {
                    $expectedConnectionString = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=$DatabasePath\Devices.mdb;"
                }
                default {
                    $expectedConnectionString = [System.String]::Empty
                }
            }
            if (([System.String]::IsNullOrEmpty($expectedConnectionString)))
            {
                $DesiredConfigurationMatch = $false
                Write-Verbose "The DB provider does not have a valid value: 'ESENT' or 'System.Data.OleDb'"
                break
            }

            if (-not (Test-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "dbconnectionstr" -ExpectedAppSettingValue $expectedConnectionString))
            {
                $DesiredConfigurationMatch = $false
                break
            }

            Write-Verbose "Check ModulePath"
            if ($ModulePath)
            {
                if (-not (Test-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ModulePath" -ExpectedAppSettingValue $ModulePath))
                {
                    $DesiredConfigurationMatch = $false
                    break
                }
            }    

            Write-Verbose "Check ConfigurationPath"
            if ($ConfigurationPath)
            {
                if (-not (Test-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ConfigurationPath" -ExpectedAppSettingValue $ConfigurationPath))
                {
                    $DesiredConfigurationMatch = $false
                    break
                }
            }

            Write-Verbose "Check RegistrationKeyPath"
            if ($RegistrationKeyPath)
            {
                if (-not (Test-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "RegistrationKeyPath" -ExpectedAppSettingValue $RegistrationKeyPath))
                {
                    $DesiredConfigurationMatch = $false
                    break
                }
            }

            Write-Verbose "Check AcceptSelfSignedCertificates"
            if ($AcceptSelfSignedCertificates)
            {
                if (-not (Test-WebConfigModulesSetting -WebConfigFullPath $webConfigFullPath -ModuleName "IISSelfSignedCertModule(32bit)" -ExpectedInstallationStatus $AcceptSelfSignedCertificates))
                {
                    $DesiredConfigurationMatch = $false
                    break
                }
            }
        }

        Write-Verbose "Check UseSecurityBestPractices"
        if ($UseSecurityBestPractices)
        {
            if (-not (UseSecurityBestPractices\Test-UseSecurityBestPractices -DisableSecurityBestPractices $DisableSecurityBestPractices))
            {
                $desiredConfigurationMatch = $false;
                Write-Verbose "The state of security settings does not match the desired state."
                break
            }
        }
        $stop = $false
    }
    While($stop)  

    $desiredConfigurationMatch;
}

# Helper function used to validate website path
function Test-WebsitePath
{
    param
    (
        [string] $EndpointName,
        [string] $PhysicalPath
    )

    $pathNeedsUpdating = $false

    if((Get-ItemProperty "IIS:\Sites\$EndpointName" -Name physicalPath) -ne $PhysicalPath)
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
        [string] $WebConfigFullPath,
        [string] $AppSettingName,
        [string] $ExpectedAppSettingValue
    )
    
    $returnValue = $true

    if (Test-Path $WebConfigFullPath)
    {
        $webConfigXml = [xml](get-content $WebConfigFullPath)
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
            Write-Verbose "The state of Web.Config AppSetting $AppSettingName does not match the desired state."
        }

    }
    $returnValue
}

# Helper function to Get the specified Web.Config App Setting
function Get-WebConfigAppSetting
{
    param
    (
        [string] $WebConfigFullPath,
        [string] $AppSettingName
    )
    
    $appSettingValue = ""
    if (Test-Path $WebConfigFullPath)
    {
        $webConfigXml = [xml](get-content $WebConfigFullPath)
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
        [string] $WebConfigFullPath,
        [string] $ModuleName,
        [boolean] $ExpectedInstallationStatus
    )
    
    $returnValue = $false

    if (Test-Path $WebConfigFullPath)
    {
        $webConfigXml = [xml](get-content $WebConfigFullPath)
        $root = $webConfigXml.get_DocumentElement() 

        foreach ($item in $root."system.webServer".modules.add) 
        { 
            if( $item.name -eq $ModuleName ) 
            {           
                if($ExpectedInstallationStatus -eq $true)
                {
                    $returnValue = $true                  
                }
                break
            } 
        }
    }

    if(($ExpectedInstallationStatus -eq $false) -and ($returnValue -eq $false))
    {
        $returnValue = $true
    }

    $returnValue
}

# Helper function to Get the specified Web.Config Modules Setting
function Get-WebConfigModulesSetting
{
    param
    (
        [string] $WebConfigFullPath,
        [string] $ModuleName
    )
    
    $moduleValue = ""
    if (Test-Path $WebConfigFullPath)
    {
        $webConfigXml = [xml](get-content $WebConfigFullPath)
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
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value
    Split-Path $Invocation.MyCommand.Path
}

# Allow this Website to enable/disable specific Auth Schemes by adding <location> tag in applicationhost.config
function Update-LocationTagInApplicationHostConfigForAuthentication
{
    param (
        # Name of the WebSite        
        [String] $WebSite,

        # Authentication Type
        [ValidateSet('anonymous', 'basic', 'windows')]
        [String] $Authentication
    )

    Add-Type -AssemblyName "Microsoft.Web.Administration, Version=7.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35, processorArchitecture=MSIL"

    $webAdminSrvMgr = New-Object -TypeName Microsoft.Web.Administration.ServerManager

    $appHostConfig = $webAdminSrvMgr.GetApplicationHostConfiguration()

    $authenticationType = $Authentication + "Authentication"
    $appHostConfigSection = $appHostConfig.GetSection("system.webServer/security/authentication/$authenticationType", $WebSite)
    $appHostConfigSection.OverrideMode="Allow"
    $webAdminSrvMgr.CommitChanges()
}

function Find-CertificateThumbprintWithSubjectAndTemplateName
{
    param
    (
        [Parameter(Mandatory)]
        [String]
        $Subject,

        [Parameter(Mandatory)]
        [String]
        $TemplateName,

        [String]
        $Store = 'Cert:\LocalMachine\My'
    )

    [Array] $CertificatesFromTemplates = (Get-ChildItem -Path $Store).Where{$_.Extensions.Oid.Value -contains '1.3.6.1.4.1.311.20.2'}

    $Certificate = $CertificatesFromTemplates.Where{
        $_.Subject -match $Subject -and
        $_.Extensions.Where{
            $_.Oid.FriendlyName -eq 'Certificate Template Name'
        }.Format($false) -eq $TemplateName
    } | Sort-Object -Property 'NotAfter' -Descending | Select-Object -First 1

    if ($Certificate)
    {
        return $Certificate.Thumbprint
    }
    else
    {
        # Should execution stop if no certificate is found?
        throw "Certificate not found with subject containing $Subject and using template $TemplateName."
    }
}

Export-ModuleMember -Function *-TargetResource
