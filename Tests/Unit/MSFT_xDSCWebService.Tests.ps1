$script:testsFolderFilePath = Split-Path $PSScriptRoot -Parent
$script:commonTestHelperFilePath = Join-Path -Path $testsFolderFilePath -ChildPath 'CommonTestHelper.psm1'
Import-Module -Name $commonTestHelperFilePath

$script:dscModuleName   = 'xPSDesiredStateConfiguration'
$script:dscResourceName = 'MSFT_xDSCWebService'

if (Test-SkipContinuousIntegrationTask -Type 'Unit')
{
    return
}

#region HEADER
# Integration Test Template Version: 1.1.0
[System.String] $script:moduleRoot = Split-Path -Parent -Path (Split-Path -Parent -Path $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git.exe @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$testEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:dscModuleName `
    -DSCResourceName $script:dscResourceName `
    -TestType Unit
#endregion

# Begin Testing
try
{
    #region Pester Tests
    InModuleScope -ModuleName $script:dscResourceName -ScriptBlock {

        $dscResourceName = 'MSFT_xDSCWebService'

        #region Test Data
        $testParameters = @{
            CertificateThumbPrint    = 'AllowUnencryptedTraffic'
            EndpointName             = 'PesterTestSite'
            UseSecurityBestPractices = $false
        }

        $serviceData = @{
            ServiceName         = 'PesterTest'
            ModulePath          = 'C:\Program Files\WindowsPowerShell\DscService\Modules'
            ConfigurationPath   = 'C:\Program Files\WindowsPowerShell\DscService\Configuration'
            RegistrationKeyPath = 'C:\Program Files\WindowsPowerShell\DscService'
            dbprovider          = 'ESENT'
            dbconnectionstr     = 'C:\Program Files\WindowsPowerShell\DscService\Devices.edb'
            oleDbConnectionstr  = 'Data Source=TestDrive:\inetpub\PesterTestSite\Devices.mdb'
        }

        $websiteDataHTTP  = [System.Management.Automation.PSObject] @{
            bindings     = [System.Management.Automation.PSObject] @{
                collection = @(
                    @{
                        protocol           = 'http'
                        bindingInformation = '*:8080:'
                        certificateHash    = ''
                    }
                )
            }
            physicalPath = 'TestDrive:\inetpub\PesterTestSite'
            state        = 'Started'
        }

        $websiteDataHTTPS = [System.Management.Automation.PSObject] @{
            bindings     = [System.Management.Automation.PSObject] @{
                collection = @(
                    @{
                        protocol           = 'https'
                        bindingInformation = '*:8080:'
                        certificateHash    = 'AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTT'
                    }
                )
            }
            physicalPath = 'TestDrive:\inetpub\PesterTestSite'
            state        = 'Started'
        }

        $certificateData  = @(
            [System.Management.Automation.PSObject] @{
                Thumbprint = 'AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTT'
                Subject    = 'PesterTestCertificate'
                Extensions = [System.Array] @(
                    [System.Management.Automation.PSObject] @{
                        Oid = [System.Management.Automation.PSObject] @{
                            FriendlyName = 'Certificate Template Name'
                            Value        = '1.3.6.1.4.1.311.20.2'
                        }
                    }
                    [System.Management.Automation.PSObject] @{}
                )
                NotAfter   = Get-Date
            }
            [System.Management.Automation.PSObject] @{
                Thumbprint = 'AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTT'
                Subject    = 'PesterTestDuplicateCertificate'
                Extensions = [System.Array] @(
                    [System.Management.Automation.PSObject] @{
                        Oid = [System.Management.Automation.PSObject] @{
                            FriendlyName = 'Certificate Template Name'
                            Value        = '1.3.6.1.4.1.311.20.2'
                        }
                    }
                    [System.Management.Automation.PSObject] @{}
                )
                NotAfter   = Get-Date
            }
            [System.Management.Automation.PSObject] @{
                Thumbprint = 'AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTT'
                Subject    = 'PesterTestDuplicateCertificate'
                Extensions = [System.Array] @(
                    [System.Management.Automation.PSObject] @{
                        Oid = [System.Management.Automation.PSObject] @{
                            FriendlyName = 'Certificate Template Name'
                            Value        = '1.3.6.1.4.1.311.20.2'
                        }
                    }
                    [System.Management.Automation.PSObject] @{}
                )
                NotAfter   = Get-Date
            }
        )
        $certificateData.ForEach{
            Add-Member -InputObject $_.Extensions[0] -MemberType ScriptMethod -Name Format -Value {'WebServer'}
        }

        $webConfig = @'
<?xml version="1.0"?>
<configuration>
  <appSettings>
    <add key="dbprovider" value="ESENT" />
    <add key="dbconnectionstr" value="TestDrive:\DatabasePath\Devices.edb" />
    <add key="ModulePath" value="TestDrive:\ModulePath" />
  </appSettings>
  <system.webServer>
    <modules>
      <add name="IISSelfSignedCertModule(32bit)" />
    </modules>
  </system.webServer>
</configuration>
'@
        #endregion

        Describe -Name "$dscResourceName\Get-TargetResource" -Fixture {

            function Get-Website {}
            function Get-WebBinding {}

            Mock -CommandName Get-WebSite

            $webConfigPath = 'TestDrive:\inetpub\PesterTestSite\Web.config'
            $null = New-Item -ItemType Directory -Path (Split-Path -Parent $webConfigPath)
            $null = New-Item -Path $webConfigPath -Value $webConfig

            Context -Name 'DSC Web Service is not installed' -Fixture {
                $script:result = $null

                It 'Should not throw' {
                    {$script:result = Get-TargetResource @testParameters} | Should -Not -Throw
                }

                It 'Should return Ensure set to Absent' {
                    $script:result.Ensure | Should -Be 'Absent'
                }
            }

            #region Mocks
            Mock -CommandName Get-WebSite -MockWith {return $websiteDataHTTP}
            Mock -CommandName Get-WebBinding -MockWith {return @{CertificateHash = $websiteDataHTTPS.bindings.collection[0].certificateHash}}
            Mock -CommandName Get-ChildItem -ParameterFilter {$Path -eq $websiteDataHTTP.physicalPath -and $Filter -eq '*.svc'} -MockWith {return @{Name = $serviceData.ServiceName}}
            Mock -CommandName Get-WebConfigAppSetting -ParameterFilter {$AppSettingName -eq 'ModulePath'}          -MockWith {return $serviceData.ModulePath}
            Mock -CommandName Get-WebConfigAppSetting -ParameterFilter {$AppSettingName -eq 'ConfigurationPath'}   -MockWith {return $serviceData.ConfigurationPath}
            Mock -CommandName Get-WebConfigAppSetting -ParameterFilter {$AppSettingName -eq 'RegistrationKeyPath'} -MockWith {return $serviceData.RegistrationKeyPath}
            Mock -CommandName Get-WebConfigAppSetting -ParameterFilter {$AppSettingName -eq 'dbprovider'}          -MockWith {return $serviceData.dbprovider}
            Mock -CommandName Get-WebConfigAppSetting -ParameterFilter {$AppSettingName -eq 'dbconnectionstr'}     -MockWith {return $serviceData.dbconnectionstr}
            Mock -CommandName Get-WebConfigModulesSetting `
                -ParameterFilter {$webConfigFullPath.StartsWith($websiteDataHTTP.physicalPath) -and $ModuleName -eq 'IISSelfSignedCertModule(32bit)'} `
                -MockWith {return 'IISSelfSignedCertModule(32bit)'}
            <#
            Mock -CommandName Test-WebConfigModulesSetting `
                -ParameterFilter {$ModuleName -eq 'IISSelfSignedCertModule(32bit)'}  `
                -MockWith { param ($ExpectedInstallationStatus)
                    Write-Verbose -Message 'Test-WebConfigAppSetting - IISSelfSignedCertModule';
                    $acceptSelfSignedCertificates -eq $ExpectedInstallationStatus
                }
            #>
            #endregion

            Context -Name 'DSC Web Service is installed without certificate' -Fixture {

                $script:result = $null

                $ipProperties = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()

                if ($ipProperties.DomainName)
                {
                    $fqdnComputerName = '{0}.{1}' -f $ipProperties.HostName, $ipProperties.DomainName
                }
                else
                {
                    $fqdnComputerName = $ipProperties.HostName
                }

                $testData = @(
                    @{
                        Variable = 'EndpointName'
                        Data     = $testParameters.EndpointName
                    }
                     @{
                        Variable = 'Port'
                        Data     = ($websiteDataHTTP.bindings.collection[0].bindingInformation -split ':')[1]
                    }
                    @{
                        Variable = 'PhysicalPath'
                        Data     = $websiteDataHTTP.physicalPath
                    }
                    @{
                        Variable = 'State'
                        Data     = $websiteDataHTTP.state
                    }
                    @{
                        Variable = 'DatabasePath'
                        Data     = Split-Path -Path $serviceData.dbconnectionstr -Parent
                    }
                    @{
                        Variable = 'ModulePath'
                        Data     = $serviceData.ModulePath
                    }
                    @{
                        Variable = 'ConfigurationPath'
                        Data     = $serviceData.ConfigurationPath
                    }
                    @{
                        Variable = 'DSCServerURL'
                        Data     = '{0}://{1}:{2}/{3}' -f $websiteDataHTTP.bindings.collection[0].protocol,
                                                              $fqdnComputerName,
                                                              ($websiteDataHTTP.bindings.collection[0].bindingInformation -split ':')[1],
                                                              $serviceData.ServiceName
                    }
                    @{
                        Variable = 'Ensure'
                        Data     = 'Present'
                    }
                    @{
                        Variable = 'RegistrationKeyPath'
                        Data     = $serviceData.RegistrationKeyPath
                    }
                    @{
                        Variable = 'AcceptSelfSignedCertificates'
                        Data     = $true
                    }
                    @{
                        Variable = 'UseSecurityBestPractices'
                        Data     = $false
                    }
                    @{
                        Variable = 'Enable32BitAppOnWin64'
                        Data     = $false
                    }
               )

                It 'Should not throw' {
                    {$script:result = Get-TargetResource @testParameters} | Should -Not -Throw
                }

                It 'Should return <Variable> set to <Data>' -TestCases $testData {
                    param
                    (
                        [Parameter(Mandatory = $true)]
                        [System.String]
                        $Variable,

                        [Parameter(Mandatory = $true)]
                        [System.Management.Automation.PSObject]
                        $Data
                    )

                    if ($Data -ne $null)
                    {
                        $script:result.$Variable  | Should -Be $Data
                    }
                    else
                    {
                         $script:result.$Variable  | Should -Be Null
                    }
                }
                It 'Should return ''DisableSecurityBestPractices'' set to $null' {
                    $script:result.DisableSecurityBestPractices | Should -BeNullOrEmpty
                }
                It 'Should call expected mocks' {
                    Assert-MockCalled -Exactly -Times 2 -CommandName Get-WebSite
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-ChildItem
                    Assert-MockCalled -Exactly -Times 5 -CommandName Get-WebConfigAppSetting
                    Assert-MockCalled -Exactly -Times 0 -CommandName Get-WebConfigModulesSetting
                }
            }

            Mock -CommandName Get-WebConfigAppSetting -ParameterFilter {$AppSettingName -eq 'dbconnectionstr'} -MockWith {return $serviceData.oleDbConnectionstr}

            Context -Name 'DSC Web Service is installed and using OleDb' -Fixture {
                $serviceData.dbprovider = 'System.Data.OleDb'
                $script:result = $null

                $testData = @(
                    @{
                        Variable = 'DatabasePath'
                        Data     = $serviceData.oleDbConnectionstr
                    }
                )

                It 'Should not throw' {
                    {$script:result = Get-TargetResource @testParameters} | Should -Not -Throw
                }

                It 'Should return <Variable> set to <Data>' -TestCases $testData {
                    param
                    (
                        [Parameter(Mandatory = $true)]
                        [System.String]
                        $Variable,

                        [Parameter(Mandatory = $true)]
                        [System.Management.Automation.PSObject]
                        $Data
                    )

                    $script:result.$Variable | Should -Be $Data
                }
                It 'Should call expected mocks' {
                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-WebConfigAppSetting -ParameterFilter {$AppSettingName -eq 'dbconnectionstr'}
                }
            }

            #region Mocks
            Mock -CommandName Get-WebSite -MockWith {return $websiteDataHTTPS}
            Mock -CommandName Get-WebBinding -MockWith {return $websiteDataHTTPS.bindings.collection}
            Mock -CommandName Get-ChildItem -ParameterFilter {$Path -eq 'Cert:\LocalMachine\My\'} -MockWith {return $certificateData[0]}
            #endregion

            Context -Name 'DSC Web Service is installed with certificate using thumbprint' -Fixture {
                $altTestParameters = $testParameters.Clone()
                $altTestParameters.CertificateThumbPrint = $certificateData[0].Thumbprint
                $script:result = $null

                $testData = @(
                    @{
                        Variable = 'CertificateThumbPrint'
                        Data     = $certificateData[0].Thumbprint
                    }
                     @{
                        Variable = 'CertificateSubject'
                        Data     = $certificateData[0].Subject
                    }
                    @{
                        Variable = 'CertificateTemplateName'
                        Data     = $certificateData[0].Extensions.Where{$_.Oid.FriendlyName -eq 'Certificate Template Name'}.Format($false)
                    }
               )

                It 'Should not throw' {
                    {$script:result = Get-TargetResource @altTestParameters} | Should -Not -Throw
                }

                It 'Should return <Variable> set to <Data>' -TestCases $testData {
                    param
                    (
                        [Parameter(Mandatory = $true)]
                        [System.String]
                        $Variable,

                        [Parameter(Mandatory = $true)]
                        [System.Management.Automation.PSObject]
                        $Data
                    )

                    if ($Data -ne $null)
                    {
                        $script:result.$Variable  | Should -Be $Data
                    }
                    else
                    {
                         $script:result.$Variable  | Should -Be Null
                    }
                }
                It 'Should call expected mocks' {
                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 2 -CommandName Get-WebSite
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-WebBinding
                    Assert-MockCalled -Exactly -Times 2 -CommandName Get-ChildItem
                }
            }

            Context -Name 'DSC Web Service is installed with certificate using subject' -Fixture {
                $altTestParameters = $testParameters.Clone()
                $altTestParameters.Remove('CertificateThumbPrint')
                $altTestParameters.Add('CertificateSubject', $certificateData[0].Subject)
                $script:result = $null

                $testData = @(
                    @{
                        Variable = 'CertificateThumbPrint'
                        Data     = $certificateData[0].Thumbprint
                    }
                     @{
                        Variable = 'CertificateSubject'
                        Data     = $certificateData[0].Subject
                    }
                    @{
                        Variable = 'CertificateTemplateName'
                        Data     = $certificateData[0].Extensions.Where{$_.Oid.FriendlyName -eq 'Certificate Template Name'}.Format($false)
                    }
               )

                It 'Should not throw' {
                    {$script:result = Get-TargetResource @altTestParameters} | Should -Not -Throw
                }

                It 'Should return <Variable> set to <Data>' -TestCases $testData {
                    param
                    (
                        [Parameter(Mandatory = $true)]
                        [System.String]
                        $Variable,

                        [Parameter(Mandatory = $true)]
                        [System.Management.Automation.PSObject]
                        $Data
                    )

                    if ($Data -ne $null)
                    {
                        $script:result.$Variable  | Should -Be $Data
                    }
                    else
                    {
                         $script:result.$Variable  | Should -Be Null
                    }
                }
                It 'Should call expected mocks' {
                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 2 -CommandName Get-WebSite
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-WebBinding
                    Assert-MockCalled -Exactly -Times 2 -CommandName Get-ChildItem
                }
            }

            Context -Name 'Function parameters contain invalid data' -Fixture {
                It 'Should throw if CertificateThumbprint and CertificateSubject are not specifed' {
                    $altTestParameters = $testParameters.Clone()
                    $altTestParameters.Remove('CertificateThumbPrint')

                    {$script:result = Get-TargetResource @altTestParameters} | Should -Throw
                }
                It 'Should throw if CertificateThumbprint and CertificateSubject are both specifed' {
                    $altTestParameters = $testParameters.Clone()
                    $altTestParameters.Add('CertificateSubject', $certificateData[0].Subject)

                    {$script:result = Get-TargetResource @altTestParameters} | Should -Throw
                }
            }
        }
        Describe -Name "$dscResourceName\Set-TargetResource" -Fixture {

            function Get-Website {}
            function Get-WebBinding {}

            #region Mocks
            $testArguments = 'if ($allowedArgs -notcontains $MyInvocation.Line.Trim()) {throw ''Mock test failed.''}'

            Mock -CommandName Get-IISAppCmd -MockWith {[ScriptBlock]::Create($testArguments)} -ModuleName IISSelfSignedModule
            Mock -CommandName Get-OSVersion -MockWith {@{Major = 6; Minor = 3}}
            Mock -CommandName Get-Website
            #endregion

            Context -Name 'DSC Service is not installed and Ensure is Absent' -Fixture {
                It 'Should call expected mocks' {
                    Set-TargetResource @testParameters -Ensure Absent

                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-Website
                    ##FIXME: Assert-MockCalled -Exactly -Times 1 -CommandName Get-Command
                }
            }

            Context -Name 'DSC Service is installed and Ensure is Absent' -Fixture {
                #region Mocks
                Mock -CommandName Get-Website -MockWith {'Website'}
                Mock -CommandName Remove-PSWSEndpoint
                #endregion

                It 'Should call expected mocks' {
                    Set-TargetResource @testParameters -Ensure Absent

                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-Website
                    ##FIXME: Assert-MockCalled -Exactly -Times 1 -CommandName Get-Command
                    Assert-MockCalled -Exactly -Times 1 -CommandName Remove-PSWSEndpoint
                }
            }

            #region Mocks
            Mock -CommandName Get-Culture -MockWith {@{TwoLetterISOLanguageName = 'en'}}
            Mock -CommandName Test-Path -MockWith {$true}
            Mock -CommandName New-PSWSEndpoint
            Mock -CommandName Update-LocationTagInApplicationHostConfigForAuthentication
            Mock -CommandName Set-AppSettingsInWebconfig
            Mock -CommandName Set-BindingRedirectSettingInWebConfig
            Mock -CommandName Copy-Item
            Mock -CommandName Test-IISSelfSignedModuleInstalled
            Mock -CommandName Enable-IISSelfSignedModule
            Mock -CommandName Disable-IISSelfSignedModule
            #endregion

            Context -Name 'Ensure is Present' -Fixture {
                $setTargetPaths = @{
                    DatabasePath        = 'TestDrive:\Database'
                    ConfigurationPath   = 'TestDrive:\Configuration'
                    ModulePath          = 'TestDrive:\Module'
                    RegistrationKeyPath = 'TestDrive:\RegistrationKey'
                }

                It 'Should call expected mocks' {
                    Set-TargetResource @testParameters @setTargetPaths -Ensure Present

                    ##FIXME: Assert-MockCalled -Exactly -Times 1 -CommandName Get-Command
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-Culture
                    Assert-MockCalled -Exactly -Times 0 -CommandName Get-Website
                    Assert-MockCalled -Exactly -Times 1 -CommandName Test-Path
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-OSVersion
                    Assert-MockCalled -Exactly -Times 1 -CommandName New-PSWSEndpoint
                    Assert-MockCalled -Exactly -Times 3 -CommandName Update-LocationTagInApplicationHostConfigForAuthentication
                    Assert-MockCalled -Exactly -Times 5 -CommandName Set-AppSettingsInWebconfig
                    Assert-MockCalled -Exactly -Times 1 -CommandName Set-BindingRedirectSettingInWebConfig
                    Assert-MockCalled -Exactly -Times 0 -CommandName Copy-Item
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled
                    Assert-MockCalled -Exactly -Times 1 -CommandName Enable-IISSelfSignedModule
                    Assert-MockCalled -Exactly -Times 0 -CommandName Disable-IISSelfSignedModule
                }

                $testCases = $setTargetPaths.Keys.ForEach{@{Name = $_; Value = $setTargetPaths.$_}}

                It 'Should create the <Name> directory' -TestCases $testCases {
                    param
                    (
                        [Parameter(Mandatory = $true)]
                        [System.String]
                        $Name,

                        [Parameter(Mandatory = $true)]
                        [System.String]
                        $Value
                    )

                    Set-TargetResource @testParameters @setTargetPaths -Ensure Present

                    Test-Path -Path $Value | Should -Be $true
                }
            }

            Context -Name 'Ensure is Present - isDownLevelOfBlue' -Fixture {

                #region Mocks
                Mock -CommandName Get-OSVersion -MockWith {@{Major = 6; Minor = 2}}
                #endregion

                $setTargetPaths = @{
                    DatabasePath        = 'TestDrive:\Database'
                    ConfigurationPath   = 'TestDrive:\Configuration'
                    ModulePath          = 'TestDrive:\Module'
                    RegistrationKeyPath = 'TestDrive:\RegistrationKey'
                }

                It 'Should call expected mocks' {
                    Set-TargetResource @testParameters @setTargetPaths -Ensure Present

                    ##FIXME: Assert-MockCalled -Exactly -Times 1 -CommandName Get-Command
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-Culture
                    Assert-MockCalled -Exactly -Times 0 -CommandName Get-Website
                    Assert-MockCalled -Exactly -Times 1 -CommandName Test-Path
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-OSVersion
                    Assert-MockCalled -Exactly -Times 1 -CommandName New-PSWSEndpoint
                    Assert-MockCalled -Exactly -Times 3 -CommandName Update-LocationTagInApplicationHostConfigForAuthentication
                    Assert-MockCalled -Exactly -Times 5 -CommandName Set-AppSettingsInWebconfig
                    Assert-MockCalled -Exactly -Times 0 -CommandName Set-BindingRedirectSettingInWebConfig
                    Assert-MockCalled -Exactly -Times 1 -CommandName Copy-Item
                    Assert-MockCalled -Exactly -Times 1 -CommandName Enable-IISSelfSignedModule
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled
                    Assert-MockCalled -Exactly -Times 0 -CommandName Disable-IISSelfSignedModule
                }
            }

            Context -Name 'Ensure is Present - isUpLevelOfBlue' -Fixture {

                #region Mocks
                Mock -CommandName Get-OSVersion -MockWith {@{Major = 10; Minor = 0}}
                #endregion

                $setTargetPaths = @{
                    DatabasePath        = 'TestDrive:\Database'
                    ConfigurationPath   = 'TestDrive:\Configuration'
                    ModulePath          = 'TestDrive:\Module'
                    RegistrationKeyPath = 'TestDrive:\RegistrationKey'
                }

                It 'Should call expected mocks' {
                    Set-TargetResource @testParameters @setTargetPaths -Ensure Present

                    ##FIXME: Assert-MockCalled -Exactly -Times 1 -CommandName Get-Command
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-Culture
                    Assert-MockCalled -Exactly -Times 0 -CommandName Get-Website
                    Assert-MockCalled -Exactly -Times 1 -CommandName Test-Path
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-OSVersion
                    Assert-MockCalled -Exactly -Times 1 -CommandName New-PSWSEndpoint
                    Assert-MockCalled -Exactly -Times 3 -CommandName Update-LocationTagInApplicationHostConfigForAuthentication
                    Assert-MockCalled -Exactly -Times 5 -CommandName Set-AppSettingsInWebconfig
                    Assert-MockCalled -Exactly -Times 0 -CommandName Set-BindingRedirectSettingInWebConfig
                    Assert-MockCalled -Exactly -Times 0 -CommandName Copy-Item
                    Assert-MockCalled -Exactly -Times 1 -CommandName Enable-IISSelfSignedModule
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled
                    Assert-MockCalled -Exactly -Times 0 -CommandName Disable-IISSelfSignedModule
                }
            }

            Context -Name 'Ensure is Present - Enable32BitAppOnWin64' -Fixture {
                $setTargetPaths = @{
                    DatabasePath        = 'TestDrive:\Database'
                    ConfigurationPath   = 'TestDrive:\Configuration'
                    ModulePath          = 'TestDrive:\Module'
                    RegistrationKeyPath = 'TestDrive:\RegistrationKey'
                }

                It 'Should call expected mocks' {
                    Set-TargetResource @testParameters @setTargetPaths -Ensure Present -Enable32BitAppOnWin64 $true

                    ##FIXME: Assert-MockCalled -Exactly -Times 1 -CommandName Get-Command
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-Culture
                    Assert-MockCalled -Exactly -Times 0 -CommandName Get-Website
                    Assert-MockCalled -Exactly -Times 1 -CommandName Test-Path
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-OSVersion
                    Assert-MockCalled -Exactly -Times 1 -CommandName New-PSWSEndpoint
                    Assert-MockCalled -Exactly -Times 3 -CommandName Update-LocationTagInApplicationHostConfigForAuthentication
                    Assert-MockCalled -Exactly -Times 5 -CommandName Set-AppSettingsInWebconfig
                    Assert-MockCalled -Exactly -Times 1 -CommandName Set-BindingRedirectSettingInWebConfig
                    Assert-MockCalled -Exactly -Times 0 -CommandName Copy-Item
                    Assert-MockCalled -Exactly -Times 1 -CommandName Enable-IISSelfSignedModule
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled
                    Assert-MockCalled -Exactly -Times 0 -CommandName Disable-IISSelfSignedModule
                }
            }

            Context -Name 'Ensure is Present - AcceptSelfSignedCertificates is $false' -Fixture {
                $setTargetPaths = @{
                    DatabasePath        = 'TestDrive:\Database'
                    ConfigurationPath   = 'TestDrive:\Configuration'
                    ModulePath          = 'TestDrive:\Module'
                    RegistrationKeyPath = 'TestDrive:\RegistrationKey'
                }


                It 'Should call expected mocks' {
                    Set-TargetResource @testParameters @setTargetPaths -Ensure Present -AcceptSelfSignedCertificates $false

                    ##FIXME: Assert-MockCalled -Exactly -Times 1 -CommandName Get-Command
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-Culture
                    Assert-MockCalled -Exactly -Times 0 -CommandName Get-Website
                    Assert-MockCalled -Exactly -Times 1 -CommandName Test-Path
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-OSVersion
                    Assert-MockCalled -Exactly -Times 1 -CommandName New-PSWSEndpoint
                    Assert-MockCalled -Exactly -Times 3 -CommandName Update-LocationTagInApplicationHostConfigForAuthentication
                    Assert-MockCalled -Exactly -Times 5 -CommandName Set-AppSettingsInWebconfig
                    Assert-MockCalled -Exactly -Times 1 -CommandName Set-BindingRedirectSettingInWebConfig
                    Assert-MockCalled -Exactly -Times 0 -CommandName Copy-Item
                    Assert-MockCalled -Exactly -Times 0 -CommandName Enable-IISSelfSignedModule
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled
                    Assert-MockCalled -Exactly -Times 1 -CommandName Disable-IISSelfSignedModule
                }
            }

            Context -Name 'Ensure is Present - UseSecurityBestPractices is $true' -Fixture {
                $altTestParameters = $testParameters.Clone()
                $altTestParameters.UseSecurityBestPractices = $true

                It 'Should throw an error because no certificate specified' {
                    $message = "Error: Cannot use best practice security settings with unencrypted traffic. Please set UseSecurityBestPractices to `$false or use a certificate to encrypt pull server traffic."
                    {Set-TargetResource @altTestParameters -Ensure Present} | Should -Throw -ExpectedMessage $message
                }
            }

            #region Mocks
            Mock -CommandName Find-CertificateThumbprintWithSubjectAndTemplateName -MockWith {$certificateData[0].Thumbprint}
            #endregion

            Context -Name 'Ensure is Present - CertificateSubject' -Fixture {
                $altTestParameters = $testParameters.Clone()
                $altTestParameters.Remove('CertificateThumbPrint')

                $setTargetPaths = @{
                    DatabasePath        = 'TestDrive:\Database'
                    ConfigurationPath   = 'TestDrive:\Configuration'
                    ModulePath          = 'TestDrive:\Module'
                    RegistrationKeyPath = 'TestDrive:\RegistrationKey'
                }

                It 'Should call expected mocks' {
                    Set-TargetResource @altTestParameters @setTargetPaths -Ensure Present -CertificateSubject 'PesterTestCertificate'

                    Assert-MockCalled -Exactly -Times 1 -CommandName Find-CertificateThumbprintWithSubjectAndTemplateName
                }
            }

            Context -Name 'Ensure is Present - CertificateThumbprint and UseSecurityBestPractices is $true' -Fixture {
                #region Mocks
                Mock -CommandName Set-UseSecurityBestPractice
                #endregion

                $altTestParameters = $testParameters.Clone()
                $altTestParameters.UseSecurityBestPractices = $true
                $altTestParameters.CertificateThumbPrint = $certificateData[0].Thumbprint

                $setTargetPaths = @{
                    DatabasePath        = 'TestDrive:\Database'
                    ConfigurationPath   = 'TestDrive:\Configuration'
                    ModulePath          = 'TestDrive:\Module'
                    RegistrationKeyPath = 'TestDrive:\RegistrationKey'
                }

                It 'Should not throw an error' {
                    {Set-TargetResource @altTestParameters @setTargetPaths -Ensure Present} | Should -Not -throw
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -Exactly -Times 0 -CommandName Find-CertificateThumbprintWithSubjectAndTemplateName
                    Assert-MockCalled -Exactly -Times 1 -CommandName Set-UseSecurityBestPractice
                }
            }

            Context -Name 'Function parameters contain invalid data' -Fixture {
                It 'Should throw if CertificateThumbprint and CertificateSubject are not specifed' {
                    $altTestParameters = $testParameters.Clone()
                    $altTestParameters.Remove('CertificateThumbPrint')

                    {$result = Set-TargetResource @altTestParameters} | Should -Throw
                }
            }
        }
        Describe -Name "$dscResourceName\Test-TargetResource" -Fixture {

            function Get-Website {}
            function Get-WebBinding {}

            #region Mocks
            $testArguments = 'if ($allowedArgs -notcontains $MyInvocation.Line.Trim()) {throw ''Mock test failed.''}'

            Mock -CommandName Get-IISAppCmd -MockWith {[ScriptBlock]::Create($testArguments)} -ModuleName IISSelfSignedModule
            Mock -CommandName Test-IISSelfSignedModuleInstalled
            #endregion

            Context -Name 'DSC Service is not installed' -Fixture {
                Mock -CommandName Get-Website

                It 'Should return $true when Ensure is Absent' {
                    Test-TargetResource @testParameters -Ensure Absent | Should -Be $true
                }
                It 'Should return $false when Ensure is Present' {
                    Test-TargetResource @testParameters -Ensure Present | Should -Be $false
                }
            }

            Context -Name 'DSC Web Service is installed as HTTP' -Fixture {
                Mock -CommandName Get-Website -MockWith {$WebsiteDataHTTP}

                It 'Should return $false when Ensure is Absent' {
                    Test-TargetResource @testParameters -Ensure Absent | Should -Be $false

                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }
                It 'Should return $false if Port doesn''t match' {
                    Test-TargetResource @testParameters -Ensure Present -Port 8081 | Should -Be $false

                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }
                It 'Should return $false if Certificate Thumbprint is set' {
                    $altTestParameters = $testParameters.Clone()
                    $altTestParameters.CertificateThumbprint = $certificateData[0].Thumbprint

                    Test-TargetResource @altTestParameters -Ensure Present | Should -Be $false
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }
                It 'Should return $false if Physical Path doesn''t match' {
                    Mock -CommandName Test-WebsitePath -MockWith {$true} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present | Should -Be $false

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }

                Mock -CommandName Get-WebBinding -MockWith {return @{CertificateHash = $websiteDataHTTPS.bindings.collection[0].certificateHash}}
                Mock -CommandName Test-WebsitePath -MockWith {$false} -Verifiable

                It 'Should return $false when State is set to Stopped' {
                    Test-TargetResource @testParameters -Ensure Present -State Stopped | Should -Be $false

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }
                It 'Should return $false when dbProvider is not set' {
                    Mock -CommandName Get-WebConfigAppSetting -MockWith {''} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present | Should -Be $false

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }

                Mock -CommandName Test-WebConfigAppSetting -MockWith {Write-Verbose -Message 'Test-WebConfigAppSetting'; $true}

                It 'Should return $true when dbProvider is set to ESENT and ConnectionString does not match the value in web.config' {
                    $DatabasePath = 'TestDrive:\DatabasePath'

                    Mock -CommandName Get-WebConfigAppSetting -MockWith {'ESENT'} -Verifiable
                    Mock -CommandName Test-WebConfigAppSetting -MockWith {param ($ExpectedAppSettingValue) Write-Verbose -Message 'Test-WebConfigAppSetting - dbconnectionstr (ESENT)'; ('{0}\Devices.edb' -f $DatabasePath) -eq $ExpectedAppSettingValue} -ParameterFilter {$AppSettingName -eq 'dbconnectionstr'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -DatabasePath $DatabasePath  | Should -Be $true

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }

                It 'Should return $false when dbProvider is set to ESENT and ConnectionString does match the value in web.config' {
                    Mock -CommandName Get-WebConfigAppSetting -MockWith {'ESENT'} -Verifiable
                    Mock -CommandName Test-WebConfigAppSetting -MockWith {Write-Verbose -Message 'Test-WebConfigAppSetting - dbconnectionstr (ESENT)'; $false} -ParameterFilter {$AppSettingName -eq 'dbconnectionstr'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present | Should -Be $false

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }

                It 'Should return $true when dbProvider is set to System.Data.OleDb and ConnectionString does not match the value in web.config' {
                    $DatabasePath = 'TestDrive:\DatabasePath'

                    Mock -CommandName Get-WebConfigAppSetting -MockWith {'System.Data.OleDb'} -Verifiable
                    Mock -CommandName Test-WebConfigAppSetting -MockWith {param ($ExpectedAppSettingValue) Write-Verbose -Message 'Test-WebConfigAppSetting - dbconnectionstr (OLE)'; ('Provider=Microsoft.Jet.OLEDB.4.0;Data Source={0}\Devices.mdb;' -f $DatabasePath) -eq $ExpectedAppSettingValue} -ParameterFilter {$AppSettingName -eq 'dbconnectionstr'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -DatabasePath $DatabasePath | Should -Be $true

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }

                It 'Should return $false when dbProvider is set to System.Data.OleDb and ConnectionString does match the value in web.config' {
                    Mock -CommandName Get-WebConfigAppSetting -MockWith {'System.Data.OleDb'} -Verifiable
                    Mock -CommandName Test-WebConfigAppSetting -MockWith {Write-Verbose -Message 'Test-WebConfigAppSetting - dbconnectionstr (OLE)'; $false} -ParameterFilter {$AppSettingName -eq 'dbconnectionstr'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present | Should -Be $false

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }

                Mock -CommandName Get-WebConfigAppSetting -MockWith {'ESENT'} -Verifiable
                Mock -CommandName Test-WebConfigAppSetting -MockWith {$true} -ParameterFilter {$AppSettingName -eq 'dbconnectionstr'} -Verifiable

                It 'Should return $true when ModulePath is set the same as in web.config' {
                    $modulePath = 'TestDrive:\ModulePath'

                    Mock -CommandName Test-WebConfigAppSetting -MockWith {param ($ExpectedAppSettingValue) Write-Verbose -Message 'Test-WebConfigAppSetting - ModulePath'; $modulePath -eq $ExpectedAppSettingValue} -ParameterFilter {$AppSettingName -eq 'ModulePath'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -ModulePath $modulePath | Should -Be $true

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }

                It 'Should return $false when ModulePath is not set the same as in web.config' {
                    Mock -CommandName Test-WebConfigAppSetting -MockWith {Write-Verbose -Message 'Test-WebConfigAppSetting - ModulePath'; $false} -ParameterFilter {$AppSettingName -eq 'ModulePath'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present | Should -Be $false

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }

                Mock -CommandName Test-WebConfigAppSetting -MockWith {$true} -ParameterFilter {$AppSettingName -eq 'ModulePath'} -Verifiable

                It 'Should return $true when ConfigurationPath is set the same as in web.config' {
                    $configurationPath = 'TestDrive:\ConfigurationPath'

                    Mock -CommandName Test-WebConfigAppSetting -MockWith {param ($ExpectedAppSettingValue) Write-Verbose -Message 'Test-WebConfigAppSetting - ConfigurationPath';  $configurationPath -eq $ExpectedAppSettingValue} -ParameterFilter {$AppSettingName -eq 'ConfigurationPath'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -ConfigurationPath $configurationPath | Should -Be $true

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }

                It 'Should return $false when ConfigurationPath is not set the same as in web.config' {
                    $configurationPath = 'TestDrive:\ConfigurationPath'

                    Mock -CommandName Test-WebConfigAppSetting -MockWith {Write-Verbose -Message 'Test-WebConfigAppSetting - ConfigurationPath'; $false} -ParameterFilter {$AppSettingName -eq 'ConfigurationPath'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -ConfigurationPath $configurationPath | Should -Be $false

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }

                Mock -CommandName Test-WebConfigAppSetting -MockWith {$true} -ParameterFilter {$AppSettingName -eq 'ConfigurationPath'} -Verifiable

                It 'Should return $true when RegistrationKeyPath is set the same as in web.config' {
                    $registrationKeyPath = 'TestDrive:\RegistrationKeyPath'

                    Mock -CommandName Test-WebConfigAppSetting -MockWith {param ($ExpectedAppSettingValue) Write-Verbose -Message 'Test-WebConfigAppSetting - RegistrationKeyPath';  $registrationKeyPath -eq $ExpectedAppSettingValue} -ParameterFilter {$AppSettingName -eq 'RegistrationKeyPath'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -RegistrationKeyPath $registrationKeyPath | Should -Be $true

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }

                It 'Should return $false when RegistrationKeyPath is not set the same as in web.config' {
                    $registrationKeyPath = 'TestDrive:\RegistrationKeyPath'

                    Mock -CommandName Test-WebConfigAppSetting -MockWith {Write-Verbose -Message 'Test-WebConfigAppSetting - RegistrationKeyPath'; $false} -ParameterFilter {$AppSettingName -eq 'RegistrationKeyPath'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -RegistrationKeyPath $registrationKeyPath | Should -Be $false

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }

                It 'Should return $true when AcceptSelfSignedCertificates is set the same as in web.config' {
                    $acceptSelfSignedCertificates = $true

                    Mock -CommandName Test-IISSelfSignedModuleInstalled -MockWith { $true }
                    Mock -CommandName Test-WebConfigModulesSetting -MockWith {param ($ExpectedInstallationStatus) Write-Verbose -Message 'Test-WebConfigAppSetting - IISSelfSignedCertModule'; $acceptSelfSignedCertificates -eq $ExpectedInstallationStatus} -ParameterFilter {$ModuleName -eq 'IISSelfSignedCertModule(32bit)'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -AcceptSelfSignedCertificates $acceptSelfSignedCertificates | Should -Be $true

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 1 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }

                It 'Should return $false when AcceptSelfSignedCertificates is not set the same as in web.config' {
                    $acceptSelfSignedCertificates = $true

                    Mock -CommandName Test-IISSelfSignedModuleInstalled -MockWith { $true }
                    Mock -CommandName Test-WebConfigModulesSetting -MockWith {Write-Verbose -Message 'Test-WebConfigAppSetting - IISSelfSignedCertModule'; $false} -ParameterFilter {$ModuleName -eq 'IISSelfSignedCertModule(32bit)'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -AcceptSelfSignedCertificates $acceptSelfSignedCertificates | Should -Be $false

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 1 -CommandName Test-IISSelfSignedModuleInstalled -Scope It
                }
            }

            Context -Name 'DSC Web Service is installed as HTTPS' -Fixture {
                #region Mocks
                Mock -CommandName Get-Website -MockWith {$websiteDataHTTPS}
                #endregion

                It 'Should return $false if Certificate Thumbprint is set to AllowUnencryptedTraffic' {
                    Test-TargetResource @testParameters -Ensure Present | Should -Be $false

                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled
                }

                It 'Should return $false if Certificate Subject does not match the current certificate' {
                    $altTestParameters = $testParameters.Clone()
                    $altTestParameters.Remove('CertificateThumbprint')

                    Mock -CommandName Find-CertificateThumbprintWithSubjectAndTemplateName -MockWith {'ZZYYXXWWVVUUTTSSRRQQPPOONNMMLLKKJJIIHHGG'}

                    Test-TargetResource @altTestParameters -Ensure Present -CertificateSubject 'Invalid Certifcate' | Should -Be $false

                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled
                }

                Mock -CommandName Test-WebsitePath -MockWith {$false} -Verifiable

                It 'Should return $false when UseSecurityBestPractices and insecure protocols are enabled' {
                    $altTestParameters = $testParameters.Clone()
                    $altTestParameters.UseSecurityBestPractices = $true
                    $altTestParameters.CertificateThumbprint    = $certificateData[0].Thumbprint

                    Mock -CommandName Get-WebConfigAppSetting -MockWith {'ESENT'} -Verifiable
                    Mock -CommandName Test-WebConfigAppSetting -MockWith {$true} -ParameterFilter {$AppSettingName -eq 'dbconnectionstr'} -Verifiable
                    Mock -CommandName Test-WebConfigAppSetting -MockWith {$true} -ParameterFilter {$AppSettingName -eq 'ModulePath'} -Verifiable
                    Mock -CommandName Test-UseSecurityBestPractice -MockWith {$false} -Verifiable

                    Test-TargetResource @altTestParameters -Ensure Present | Should -Be $false

                    Assert-VerifiableMock
                    Assert-MockCalled -Exactly -Times 0 -CommandName Test-IISSelfSignedModuleInstalled
                }

            }

            Context -Name 'Function parameters contain invalid data' -Fixture {
                It 'Should throw if CertificateThumbprint and CertificateSubject are not specifed' {
                    $altTestParameters = $testParameters.Clone()
                    $altTestParameters.Remove('CertificateThumbPrint')

                    {$result = Test-TargetResource @altTestParameters} | Should -Throw
                }
            }
        }
        Describe -Name "$dscResourceName\Test-WebsitePath" -Fixture {

            function Get-Website {}
            function Get-WebBinding {}

            $endpointPhysicalPath = 'TestDrive:\SitePath1'
            Mock -CommandName Get-ItemProperty -MockWith {$endpointPhysicalPath}

            It 'Should return $true if Endpoint PhysicalPath doesn''t match PhysicalPath' {
                Test-WebsitePath -EndpointName 'PesterSite' -PhysicalPath 'TestDrive:\SitePath2' | Should -Be $true

                Assert-VerifiableMock
            }
            It 'Should return $true if Endpoint PhysicalPath doesn''t match PhysicalPath' {
                Test-WebsitePath -EndpointName 'PesterSite' -PhysicalPath $endpointPhysicalPath | Should -Be $false

                Assert-VerifiableMock
            }
        }
        Describe -Name "$dscResourceName\Test-WebConfigAppSetting" -Fixture {

            function Get-Website {}
            function Get-WebBinding {}

            $webConfigPath = 'TestDrive:\Web.config'
            $null = New-Item -Path $webConfigPath -Value $webConfig

            $testCases = @(
                @{
                    Key   = 'dbprovider'
                    Value = 'ESENT'
                }
                @{
                    Key   = 'dbconnectionstr'
                    Value = 'TestDrive:\DatabasePath\Devices.edb'
                }
                @{
                    Key   = 'ModulePath'
                    Value = 'TestDrive:\ModulePath'
                }
            )

            It 'Should return $true when ExpectedAppSettingValue is <Value> for <Key>.' -TestCases $testCases {
                param
                (
                    [Parameter(Mandatory = $true)]
                    [System.String]
                    $Key,

                    [Parameter(Mandatory = $true)]
                    [System.String]
                    $Value
                )
                Test-WebConfigAppSetting -WebConfigFullPath $webConfigPath -AppSettingName $Key -ExpectedAppSettingValue $Value | Should -Be $true
            }
            It 'Should return $false when ExpectedAppSettingValue is not <Value> for <Key>.' -TestCases $testCases {
                param
                (
                    [Parameter(Mandatory = $true)]
                    [System.String]
                    $Key,

                    [Parameter(Mandatory = $true)]
                    [System.String]
                    $Value
                )
                Test-WebConfigAppSetting -WebConfigFullPath $webConfigPath -AppSettingName $Key -ExpectedAppSettingValue 'InvalidValue' | Should -Be $false
            }
        }
        Describe -Name "$dscResourceName\Get-WebConfigAppSetting" -Fixture {

            function Get-Website {}
            function Get-WebBinding {}

            $webConfigPath = 'TestDrive:\Web.config'
            $null = New-Item -Path $webConfigPath -Value $webConfig

            $testCases = @(
                @{
                    Key   = 'dbprovider'
                    Value = 'ESENT'
                }
                @{
                    Key   = 'dbconnectionstr'
                    Value = 'TestDrive:\DatabasePath\Devices.edb'
                }
                @{
                    Key   = 'ModulePath'
                    Value = 'TestDrive:\ModulePath'
                }
            )

            It 'Should return <Value> when Key is <Key>.' -TestCases $testCases {
                param
                (
                    [Parameter(Mandatory = $true)]
                    [System.String]
                    $Key,

                    [Parameter(Mandatory = $true)]
                    [System.String]
                    $Value
                )
                Get-WebConfigAppSetting -WebConfigFullPath $webConfigPath -AppSettingName $Key | Should -Be $Value
            }
            It 'Should return Null if Key is not found' {
                Get-WebConfigAppSetting -WebConfigFullPath $webConfigPath -AppSettingName 'InvalidKey' | Should -BeNullOrEmpty
            }
        }
        Describe -Name "$dscResourceName\Test-WebConfigModulesSetting" -Fixture {

            function Get-Website {}
            function Get-WebBinding {}

            $webConfigPath = 'TestDrive:\Web.config'
            $null = New-Item -Path $webConfigPath -Value $webConfig

            It 'Should return $true if Module is present in Web.config and expected to be installed.' {
                Test-WebConfigModulesSetting -WebConfigFullPath $webConfigPath -ModuleName 'IISSelfSignedCertModule(32bit)' -ExpectedInstallationStatus $true | Should -Be $true
            }
            It 'Should return $false if Module is present in Web.config and not expected to be installed.' {
                Test-WebConfigModulesSetting -WebConfigFullPath $webConfigPath -ModuleName 'IISSelfSignedCertModule(32bit)' -ExpectedInstallationStatus $false | Should -Be $false
            }
            It 'Should return $true if Module is not present in Web.config and not expected to be installed.' {
                Test-WebConfigModulesSetting -WebConfigFullPath $webConfigPath -ModuleName 'FakeModule' -ExpectedInstallationStatus $false | Should -Be $true
            }
            It 'Should return $false if Module is not present in Web.config and expected to be installed.' {
                Test-WebConfigModulesSetting -WebConfigFullPath $webConfigPath -ModuleName 'FakeModule' -ExpectedInstallationStatus $true | Should -Be $false
            }
        }
        Describe -Name "$dscResourceName\Get-WebConfigModulesSetting" -Fixture {

            function Get-Website {}
            function Get-WebBinding {}

            $webConfigPath = 'TestDrive:\Web.config'
            $null = New-Item -Path $webConfigPath -Value $webConfig

            It 'Should return the Module name if it is present in Web.config.' {
                Get-WebConfigModulesSetting -WebConfigFullPath $webConfigPath -ModuleName 'IISSelfSignedCertModule(32bit)' | Should -Be 'IISSelfSignedCertModule(32bit)'
            }
            It 'Should return an empty string if the module is not present in Web.config.' {
                Get-WebConfigModulesSetting -WebConfigFullPath $webConfigPath -ModuleName 'FakeModule' | Should -Be ''
            }
        }

        Describe -Name "$dscResourceName\Update-LocationTagInApplicationHostConfigForAuthentication" -Fixture {

            function Get-Website {}
            function Get-WebBinding {}

            $appHostConfigSection = [System.Management.Automation.PSObject] @{OverrideMode = ''}
            $appHostConfig        = [System.Management.Automation.PSObject] @{}
            $webAdminSrvMgr       = [System.Management.Automation.PSObject] @{}

            Add-Member -InputObject $appHostConfig  -MemberType ScriptMethod -Name GetSection -Value {$appHostConfigSection}
            Add-Member -InputObject $webAdminSrvMgr -MemberType ScriptMethod -Name GetApplicationHostConfiguration -Value {$appHostConfig}
            Add-Member -InputObject $webAdminSrvMgr -MemberType ScriptMethod -Name CommitChanges -Value {}

            Mock -CommandName Get-IISServerManager -MockWith {$webAdminSrvMgr} -Verifiable

            Update-LocationTagInApplicationHostConfigForAuthentication -Website 'PesterSite' -Authentication 'Basic'

            It 'Should call expected mocks' {
                Assert-VerifiableMock
                Assert-MockCalled Get-IISServerManager -Exactly 1
            }
        }
        Describe -Name "$dscResourceName\Find-CertificateThumbprintWithSubjectAndTemplateName" -Fixture {

            function Get-Website {}
            function Get-WebBinding {}

            Mock -CommandName Get-ChildItem -MockWith {,@($certificateData)}
            It 'Should return the certificate thumbprint when the certificate is found' {
                Find-CertificateThumbprintWithSubjectAndTemplateName -Subject $certificateData[0].Subject -TemplateName 'WebServer' | Should -Be $certificateData[0].Thumbprint
            }
            It 'Should throw an error when the certificate is not found' {
                $subject      = $certificateData[0].Subject
                $templateName = 'Invalid Template Name'

                $errorMessage = 'Certificate not found with subject containing {0} and using template "{1}".' -f $subject, $templateName
                {Find-CertificateThumbprintWithSubjectAndTemplateName -Subject $subject -TemplateName $templateName} | Should -Throw -ExpectedMessage $errorMessage
            }
            It 'Should throw an error when the more than one certificate is found' {
                $subject      = $certificateData[1].Subject
                $templateName = 'WebServer'

                $errorMessage = 'More than one certificate found with subject containing {0} and using template "{1}".' -f $subject, $templateName
                {Find-CertificateThumbprintWithSubjectAndTemplateName -Subject $subject -TemplateName $templateName} | Should -Throw -ExpectedMessage $errorMessage
            }
        }
        Describe -Name "$dscResourceName\Get-OSVersion" -Fixture {
            It 'Should return a System.Version object' {
                Get-OSVersion | Should -BeOfType System.Version
            }
        }
    }
    #endregion
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $testEnvironment
    #endregion
}
