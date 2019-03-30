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
            [PSCustomObject] @{
                Thumbprint = 'AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTT'
                Subject    = 'PesterTestCertificate'
                Extensions = [System.Array] @(
                    [PSCustomObject] @{
                        Oid = [PSCustomObject] @{
                            FriendlyName = 'Certificate Template Name'
                            Value        = '1.3.6.1.4.1.311.20.2'
                        }
                    }
                    [PSCustomObject] @{}
                )
                NotAfter   = Get-Date
            }
            [PSCustomObject] @{
                Thumbprint = 'AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTT'
                Subject    = 'PesterTestDuplicateCertificate'
                Extensions = [System.Array] @(
                    [PSCustomObject] @{
                        Oid = [PSCustomObject] @{
                            FriendlyName = 'Certificate Template Name'
                            Value        = '1.3.6.1.4.1.311.20.2'
                        }
                    }
                    [PSCustomObject] @{}
                )
                NotAfter   = Get-Date
            }
            [PSCustomObject] @{
                Thumbprint = 'AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTT'
                Subject    = 'PesterTestDuplicateCertificate'
                Extensions = [System.Array] @(
                    [PSCustomObject] @{
                        Oid = [PSCustomObject] @{
                            FriendlyName = 'Certificate Template Name'
                            Value        = '1.3.6.1.4.1.311.20.2'
                        }
                    }
                    [PSCustomObject] @{}
                )
                NotAfter   = Get-Date
            }
        )
        $certificateData.ForEach{
            Add-Member -InputObject $_.Extensions[0] -MemberType ScriptMethod -Name Format -Value {'WebServer'}
        }
        $cerFileWithSan = "
            -----BEGIN CERTIFICATE-----
            MIIGJDCCBAygAwIBAgITewAAAAqQ+bxgiZZPtgAAAAAACjANBgkqhkiG9w0BAQsF
            ADBDMRMwEQYKCZImiZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHY29udG9z
            bzETMBEGA1UEAwwKTGFiUm9vdENBMTAeFw0xNzA1MDkxNTM5NTJaFw0xOTA1MDkx
            NTM5NTJaMBYxFDASBgNVBAMMC3NvbWVtYWNoaW5lMIIBIjANBgkqhkiG9w0BAQEF
            AAOCAQ8AMIIBCgKCAQEA0Id9FC2vq90HPWraZnAouit8MZI/p/DeucFiCb6mieuP
            017DPCiQKuMQFQmx5VWvv82mpddxmTPtV6zfda0E5R12a11KHJ2mJrK5oR2iuI/I
            P2SJBlNAkLTsvd96zUqQcWCCE/Q2nSrK7nx3oBq4Dd5+wLfUvAMKR45RXK58J4z5
            h3mLxF+ryKnQzQHKXDC4x92hMIPJVwvPym8C3067Ry6kLHhFOk5IoJjiRmS6P1TT
            48aHipWeiK9G/aLgKTS4UEbUMooAPfeHQXGRfS4fIEQmaaeY0wqQAVYGau2oDn6m
            31SiNEA+NmAmHZFvM2kXf63L58lJASFqRnXquVCw9QIDAQABo4ICPDCCAjgwIQYJ
            KwYBBAGCNxQCBBQeEgBXAGUAYgBTAGUAcgB2AGUAcjATBgNVHSUEDDAKBggrBgEF
            BQcDATAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0OBBYEFGFGkDLulJ3m1Bx3DIa1BosB
            WpOXMCgGA1UdEQQhMB+CCGZpcnN0c2FugglzZWNvbmRzYW6CCHRoaXJkc2FuMB8G
            A1UdIwQYMBaAFN75yc566Q03FdJ4ZQ/6Kn8dohYVMIHEBgNVHR8Egbwwgbkwgbag
            gbOggbCGga1sZGFwOi8vL0NOPUxhYlJvb3RDQTEsQ049Q0ExLENOPUNEUCxDTj1Q
            dWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0
            aW9uLERDPWNvbnRvc28sREM9Y29tP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/
            YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvAYIKwYBBQUH
            AQEEga8wgawwgakGCCsGAQUFBzAChoGcbGRhcDovLy9DTj1MYWJSb290Q0ExLENO
            PUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
            b25maWd1cmF0aW9uLERDPWNvbnRvc28sREM9Y29tP2NBQ2VydGlmaWNhdGU/YmFz
            ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MA0GCSqGSIb3DQEB
            CwUAA4ICAQBUkvBdMgZsUHDEaVyBuHzALExcEflkvCq1AmJ1U2nixnfcqc5Wb3df
            W+gauW+YbOA9EfQrwPqMXvo0dhsjLn3H5tTWe0VVT5H8pgsdcXS/5cYDjoC6N3pd
            NZGCDN/oHAm8BgcNPPYyG8VDMxR+atp8Iv12nCDGQlpPkANK+nUHR8Nu66l/wDqF
            G8ftnQ7C3mSu4/baAFOAx91rXDbrs1ewrqfcBWxRQn4CZbZs9LMg+NQjrAM8WtQX
            DZd96IMY6m8DeVbIQQiHytpjpQr8aJs6s5Cd5XzRWPXb4lDMOe/4KwpyQAHjtFPY
            mYhUfaInXtna/li9MKLK+j641FnBJv6bjWhw1Jp++wHdjef+1RTtG1hslHQXsH48
            +n+jHZ5A5DKgOYUJWq3NhYvQwtQmDlBNe5aJbTmAFz7qpsPFWjoOqX8RXCE3Mt+R
            EhwMvEGNZHdsgMVXeJsqVssG2FfM7cqcslaUL/vULRWJ6LmJerjmSBRXcEHL6uTe
            IJPSLdUdPx7uvm+P4qpuIuzZ2bdHXqiFbL6yPyWi8lTaApzT/K7Y0Q3oRWYOuThK
            P2l4M+F7l346gaIDDZOXdrSsrPghSgkS4Xp3QtE6NnKq+V0pX2YHnns+JO97hEXt
            2EvKX3TnKnUPPrsl/CffTBpJEsD7xugu6OAn4KnEzzVTNYqzDbYx6g==
            -----END CERTIFICATE-----
            "
        $cerFileWithoutSan = "
            -----BEGIN CERTIFICATE-----
            MIIDBjCCAe6gAwIBAgIQRQyErZRGrolI5DfZCJDaTTANBgkqhkiG9w0BAQsFADAW
            MRQwEgYDVQQDDAtTb21lU2VydmVyMjAeFw0xNzA1MDkxNjI0MTZaFw0xODA1MDkx
            NjQ0MTZaMBYxFDASBgNVBAMMC1NvbWVTZXJ2ZXIyMIIBIjANBgkqhkiG9w0BAQEF
            AAOCAQ8AMIIBCgKCAQEA2x7gR/yQYSiqszd0+e3ZMX2b/mK3XwwEHhoXARoC/Jv/
            rmOmESB6AYabIheGmDv2qUESx6r8KtO4afunVEyoxeThQ8LffgduSo0YIUVgqyg9
            o+HUOaV4MX5cGutgov62MCs+HO2AYcl2QvmbJ9CF/nyGOigoLNOX1pLPHHM1vIFQ
            euBCX8KGK02kgl629QVckiUKrn5bCjboxx7JvSsb2UTcCDjR7x1FcGkxwj069koq
            VdtmwzC3ibYSxQ2UQo1rShol8FPTMkpf8NIZmApY3RGddnAl+r0fznbqqdwzRPjp
            1zXuNwYiG/cL/OOt50TQqCKA7CrD9m8Y3yWKK1ilOQIDAQABo1AwTjAOBgNVHQ8B
            Af8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQW
            BBSfthQiQydgIs0dXquThRhnkj78HTANBgkqhkiG9w0BAQsFAAOCAQEAuaACrNbE
            clIxVjSsJA4kT7z+ajTD7EmT3iX+h1sOABTuiSjR+fBCF/7AgViK24+xdLzuptCH
            MnoLW7epdP1tRXjs0vb5xwXRsTruwlIzCbvkH8/xkrc6YGw5LzdvxtFPYV+vSsx3
            uUmNlrD7ElllzRVzyGBd2VBm8hCAI0297Ls9zJlWDPYTMpedleO2D9vZBAxg3iY7
            yiMbficleMbVEE3LTNjK6iYuENZ4KOBkOJU936+lqfcVnOFTvWhLJKxTEMZ7XW4k
            pP3LiEhYnnxMfm7OyNHL+MnQhq8OV7tY3pZofPdImEeG13qcV8EBYhefFgsSxQRe
            JqptPVHBXySjMg==
            -----END CERTIFICATE-----
            "
        $cerFileWithAltTemplateName = "
            -----BEGIN CERTIFICATE-----
            MIIDVjCCAj6gAwIBAgIQIA9TO/nfla5FrjJZIiI6nzANBgkqhkiG9w0BAQsFADAW
            MRQwEgYDVQQDDAtzb21lbWFjaGluZTAeFw0xOTAyMTUxNjI3NDVaFw0yMDAyMTUx
            NjQ3NDVaMBYxFDASBgNVBAMMC3NvbWVtYWNoaW5lMIIBIjANBgkqhkiG9w0BAQEF
            AAOCAQ8AMIIBCgKCAQEAuwr0qT/ekYvp4RIHfEqsZyabdWUIR842P/1+t2b0W5bn
            LqxER+mUuBOrbdNcekjQjTnq5rYy1WsIwjeuJ7zgmVINvL8KeYna750M5ngAZsqO
            QoRR9xbQAeht2H1Q9vj/GHbakOKUW45It/0EvZLmF/FJ2+WdIGQMuqQVdr4N+w0f
            DPIVjDCjRLT5USZOHWJGrKYDSaWSf5tEQAp/6RW3JnFkE2biWsYQ3FGZtVgRxjLS
            4+602xnLTyjakQiXBosE0AuW36jiFPeW3WVVF1pdinPpIbtzE0CkoeEwPMfWNJaA
            BfIVmkEKL8HeQGk4kSEvZ/zfNbPr7RfY3S925SeR5QIDAQABo4GfMIGcMA4GA1Ud
            DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwKAYDVR0R
            BCEwH4IIZmlyc3RzYW6CCXNlY29uZHNhboIIdGhpcmRzYW4wIgYJKwYBBAGCNxQC
            BBUeEgBXAGUAYgBTAGUAcgB2AGUAcgAwHQYDVR0OBBYEFNzXV7OE2NNKgKeLPTbT
            +YBIcPJXMA0GCSqGSIb3DQEBCwUAA4IBAQBigwVwGdmE/RekuKY++7oxIrnWkQ0L
            VN+ps5pVLM3+P1XaHdtRUVAHErBuRaqZMTHc4REzSE6PNozrznQJknEnMc6d4y4+
            IZ5pfPl8eyuPs6nBAP5aA3KhC9lW72csjXqe+EJNHfCP0k3AOkBb1A6Cja36h8Ef
            lJiPqE2bRualoz6iqcHftilLCF+8s7q1sW12730PK1BD+gqQo0o8N0fZrXhWU4/I
            0nuuz7F7VEaNcpZD7leBPCiNdsyDkLIfkb2cj4R39Fbs0yuuG6Bv1jQ+adXXprCG
            ZMCE85eAK5et3yur0hVcUHppM6oDPOyoCYnUhDthiO3rwnfRCr/1f3IB
            -----END CERTIFICATE-----
            "
        $cerFileWithAltTemplateInformation = "
            -----BEGIN CERTIFICATE-----
            MIIDazCCAlOgAwIBAgIQJx7ZH+jq5YZLy436X4Li3TANBgkqhkiG9w0BAQsFADAW
            MRQwEgYDVQQDDAtzb21lbWFjaGluZTAeFw0xODA4MDcwOTEwNDVaFw0xOTA4MDcw
            OTMwNDVaMBYxFDASBgNVBAMMC3NvbWVtYWNoaW5lMIIBIjANBgkqhkiG9w0BAQEF
            AAOCAQ8AMIIBCgKCAQEA98nll0sk4LiGTJcbZ+jIY86ongKRNE6CH+LZ0gp4mzUY
            FRufTwmWqqoTjg6Q/Ri+CvofX1CbeaHCSdvI76/vIzF0ij+Y3wGg4Ot8YljbTjsF
            aig3hGaWp+/Q345+O+sTlppwipcmdlp8vS8PNWx+FRbPFyPYSNTHbdFQXGjlz7Lu
            s1gFe9VGbBqditYhvYPJeHjUSBWVDve2vd+E9ECRKssxn3UME74yuRSzEq30ly44
            LPZYRYd8maypJERcMAkRz19bXZ1BNYp1kesxoi0KK7LLodSSzPG01Pls/K51KhZA
            6NuFe14kA+jsAnstWQ2lIofUZxHrQ4IfykmgmP3NmQIDAQABo4G0MIGxMA4GA1Ud
            DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwKAYDVR0R
            BCEwH4IIZmlyc3RzYW6CCXNlY29uZHNhboIIdGhpcmRzYW4wNwYJKwYBBAGCNxUH
            BCowKAYgKwYBBAGCNxUIgt3/eIL6kR6HjYUJhpmDKIHSoVI+ARACAWQCAQUwHQYD
            VR0OBBYEFNt1uNJH8KG4/X0Gzh4rnAPR5lBfMA0GCSqGSIb3DQEBCwUAA4IBAQBI
            MyZvohjsm1wbxJvowp5QrKXvGs8XVl+97zY79h8QqtcZALtIHkZd8rj2Bvkd+qyU
            o01rPj7+LS7HzkdqfmDRUxbAnDclOkUTCMskzxon9CzEsizomFyTq4khWh/p+7fE
            mR2Rq/kA95aupS4Dm7HcncHn89nw9BKcP7WLgIzjRC3ZBzplEGCCL7aKDv66+dv/
            HM2uI47A8kHCFMvaq6O0bjlJfmXvrX8OgVQlRDItiuM+pu9LMkWc0t8U4ekRRQdj
            kVIXdpdvNQmud6JHv3OI0HrjtL7Da1dK7Q8qye3qHBzHwva6SMVbMmFC3ACxukBU
            v+M0WvuaEOEmAQoYaY6K
            -----END CERTIFICATE-----
            "

        $cerBytes = [System.Text.Encoding]::ASCII.GetBytes($cerFileWithSan)
        $cerBytesWithoutSan = [System.Text.Encoding]::ASCII.GetBytes($cerFileWithoutSan)
        $cerBytesWithAltTemplateName = [System.Text.Encoding]::ASCII.GetBytes($cerFileWithAltTemplateName)
        $cerBytesWithAltTemplateInformation = [System.Text.Encoding]::ASCII.GetBytes($cerFileWithAltTemplateInformation)

        $testCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerBytes)
        $testCertificateWithoutSan = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerBytesWithoutSan)
        $testCertificateWithAltTemplateName = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerBytesWithAltTemplateName)
        $testCertificateWithAltTemplateInformation = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cerBytesWithAltTemplateInformation)

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

            <# Create dummy functions so that Pester is able to mock them #>
            function Get-Website {}
            function Get-WebBinding {}

            $webConfigPath = 'TestDrive:\inetpub\PesterTestSite\Web.config'
            $null = New-Item -ItemType Directory -Path (Split-Path -Parent $webConfigPath)
            $null = New-Item -Path $webConfigPath -Value $webConfig

            Context -Name 'DSC Web Service is not installed' -Fixture {
                Mock -CommandName Get-WebSite -MockWith {}

                $script:result = $null

                It 'Should not throw' {
                    {$script:result = Get-TargetResource @testParameters} | Should -Not -Throw

                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-WebSite -Scope It
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
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-WebBinding
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-ChildItem
                    Assert-MockCalled -Exactly -Times 5 -CommandName Get-WebConfigAppSetting
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
            Mock -CommandName Get-CertificateTemplateName -MockWith {'WebServer'}
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

            <# Create dummy functions so that Pester is able to mock them #>
            function Get-Website {}
            function Get-WebBinding {}

            #region Mocks
            Mock -CommandName Get-Command -ParameterFilter {$Name -eq '.\appcmd.exe'} -MockWith {
                <#
                    We return a ScriptBlock here, so that the ScriptBlock is called with the parameters which are actually passed to appcmd.exe.
                    To verify the arguments which are passed to appcmd.exe the property UnboundArguments of $MyInvocation can be used. But
                    here's a catch: when Powershell parses the arguments into the UnboundArguments it splits arguments which start with -section:
                    into TWO separate array elements. So -section:system.webServer/globalModules ends up in [-section:, system.webServer/globalModules]
                    and not as [-section:system.webServer/globalModules]. If the arguments should later be verified in this mock this should be considered.
                #>
                {
                    $allowedArgs = @(
                        '('''' -ne ((& (Get-IISAppCmd) list config -section:system.webServer/globalModules) -like "*$iisSelfSignedModuleName*"))'
                        '& (Get-IISAppCmd) install module /name:$iisSelfSignedModuleName /image:$destinationFilePath /add:false /lock:false'
                        '& (Get-IISAppCmd) add module /name:$iisSelfSignedModuleName /app.name:"$EndpointName/" $preConditionBitnessArgumentFor32BitInstall'
                        '& (Get-IISAppCmd) delete module /name:$iisSelfSignedModuleName /app.name:"$EndpointName/"'
                    )
                    $line = $MyInvocation.Line.Trim() -replace '\s+', ' '
                    if ($allowedArgs -notcontains $line)
                    {
                        throw "Mock test failed. Invalid parameters [$line]"
                    }
                }
            }
            Mock -CommandName Get-OSVersion -MockWith {@{Major = 6; Minor = 3}}
            Mock -CommandName Get-Website
            #endregion

            Context -Name 'DSC Service is not installed and Ensure is Absent' -Fixture {
                It 'Should call expected mocks' {
                    Set-TargetResource @testParameters -Ensure Absent

                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-OSVersion
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-Website
                    Assert-MockCalled -Exactly -Times 0 -CommandName Get-Command
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
                    Assert-MockCalled -Exactly -Times 0 -CommandName Get-Command
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
            Mock -CommandName Test-FilesDiffer -MockWith { $false }
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

                    Assert-MockCalled -Exactly -Times 3 -CommandName Get-Command
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-Culture
                    Assert-MockCalled -Exactly -Times 0 -CommandName Get-Website
                    Assert-MockCalled -Exactly -Times 2 -CommandName Test-Path
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-OSVersion
                    Assert-MockCalled -Exactly -Times 1 -CommandName New-PSWSEndpoint
                    Assert-MockCalled -Exactly -Times 3 -CommandName Update-LocationTagInApplicationHostConfigForAuthentication
                    Assert-MockCalled -Exactly -Times 5 -CommandName Set-AppSettingsInWebconfig
                    Assert-MockCalled -Exactly -Times 1 -CommandName Set-BindingRedirectSettingInWebConfig
                    Assert-MockCalled -Exactly -Times 0 -CommandName Copy-Item
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

                    Assert-MockCalled -Exactly -Times 3 -CommandName Get-Command
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-Culture
                    Assert-MockCalled -Exactly -Times 0 -CommandName Get-Website
                    Assert-MockCalled -Exactly -Times 2 -CommandName Test-Path
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-OSVersion
                    Assert-MockCalled -Exactly -Times 1 -CommandName New-PSWSEndpoint
                    Assert-MockCalled -Exactly -Times 3 -CommandName Update-LocationTagInApplicationHostConfigForAuthentication
                    Assert-MockCalled -Exactly -Times 5 -CommandName Set-AppSettingsInWebconfig
                    Assert-MockCalled -Exactly -Times 0 -CommandName Set-BindingRedirectSettingInWebConfig
                    Assert-MockCalled -Exactly -Times 1 -CommandName Copy-Item
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

                    Assert-MockCalled -Exactly -Times 3 -CommandName Get-Command
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-Culture
                    Assert-MockCalled -Exactly -Times 0 -CommandName Get-Website
                    Assert-MockCalled -Exactly -Times 2 -CommandName Test-Path
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-OSVersion
                    Assert-MockCalled -Exactly -Times 1 -CommandName New-PSWSEndpoint
                    Assert-MockCalled -Exactly -Times 3 -CommandName Update-LocationTagInApplicationHostConfigForAuthentication
                    Assert-MockCalled -Exactly -Times 5 -CommandName Set-AppSettingsInWebconfig
                    Assert-MockCalled -Exactly -Times 0 -CommandName Set-BindingRedirectSettingInWebConfig
                    Assert-MockCalled -Exactly -Times 0 -CommandName Copy-Item
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

                    Assert-MockCalled -Exactly -Times 3 -CommandName Get-Command
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-Culture
                    Assert-MockCalled -Exactly -Times 0 -CommandName Get-Website
                    Assert-MockCalled -Exactly -Times 2 -CommandName Test-Path
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-OSVersion
                    Assert-MockCalled -Exactly -Times 1 -CommandName New-PSWSEndpoint
                    Assert-MockCalled -Exactly -Times 3 -CommandName Update-LocationTagInApplicationHostConfigForAuthentication
                    Assert-MockCalled -Exactly -Times 5 -CommandName Set-AppSettingsInWebconfig
                    Assert-MockCalled -Exactly -Times 1 -CommandName Set-BindingRedirectSettingInWebConfig
                    Assert-MockCalled -Exactly -Times 1 -CommandName Copy-Item
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

                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-Command
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-Culture
                    Assert-MockCalled -Exactly -Times 0 -CommandName Get-Website
                    Assert-MockCalled -Exactly -Times 1 -CommandName Test-Path
                    Assert-MockCalled -Exactly -Times 1 -CommandName Get-OSVersion
                    Assert-MockCalled -Exactly -Times 1 -CommandName New-PSWSEndpoint
                    Assert-MockCalled -Exactly -Times 3 -CommandName Update-LocationTagInApplicationHostConfigForAuthentication
                    Assert-MockCalled -Exactly -Times 5 -CommandName Set-AppSettingsInWebconfig
                    Assert-MockCalled -Exactly -Times 1 -CommandName Set-BindingRedirectSettingInWebConfig
                    Assert-MockCalled -Exactly -Times 0 -CommandName Copy-Item
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

                    {Set-TargetResource @altTestParameters} | Should -Throw
                }
            }
        }
        Describe -Name "$dscResourceName\Test-TargetResource" -Fixture {

            function Get-Website {}
            function Get-WebBinding {}

            #region Mocks
            Mock -CommandName Get-Command -ParameterFilter {$Name -eq '.\appcmd.exe'} -MockWith {
                {
                    $allowedArgs = @(
                        '('''' -ne ((& (Get-IISAppCmd) list config -section:system.webServer/globalModules) -like "*$iisSelfSignedModuleName*"))'
                    )

                    $line = $MyInvocation.Line.Trim() -replace '\s+', ' '
                    if ($allowedArgs -notcontains $line)
                    {
                        throw "Mock test failed. Invalid parameters [$line]"
                    }
                }
            }
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
                }
                It 'Should return $false if Port doesn''t match' {
                    Test-TargetResource @testParameters -Ensure Present -Port 8081 | Should -Be $false
                }
                It 'Should return $false if Certificate Thumbprint is set' {
                    $altTestParameters = $testParameters.Clone()
                    $altTestParameters.CertificateThumbprint = $certificateData[0].Thumbprint

                    Test-TargetResource @altTestParameters -Ensure Present | Should -Be $false
                }
                It 'Should return $false if Physical Path doesn''t match' {
                    Mock -CommandName Test-WebsitePath -MockWith {$true} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present | Should -Be $false

                    Assert-VerifiableMock
                }

                Mock -CommandName Get-WebBinding -MockWith {return @{CertificateHash = $websiteDataHTTPS.bindings.collection[0].certificateHash}}
                Mock -CommandName Test-WebsitePath -MockWith {$false} -Verifiable

                It 'Should return $false when State is set to Stopped' {
                    Test-TargetResource @testParameters -Ensure Present -State Stopped | Should -Be $false

                    Assert-VerifiableMock
                }
                It 'Should return $false when dbProvider is not set' {
                    Mock -CommandName Get-WebConfigAppSetting -MockWith {''} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present | Should -Be $false

                    Assert-VerifiableMock
                }

                Mock -CommandName Test-WebConfigAppSetting -MockWith {Write-Verbose -Message 'Test-WebConfigAppSetting'; $true}

                It 'Should return $true when dbProvider is set to ESENT and ConnectionString does not match the value in web.config' {
                    $DatabasePath = 'TestDrive:\DatabasePath'

                    Mock -CommandName Get-WebConfigAppSetting -MockWith {'ESENT'} -Verifiable
                    Mock -CommandName Test-WebConfigAppSetting -MockWith {param ($ExpectedAppSettingValue) Write-Verbose -Message 'Test-WebConfigAppSetting - dbconnectionstr (ESENT)'; ('{0}\Devices.edb' -f $DatabasePath) -eq $ExpectedAppSettingValue} -ParameterFilter {$AppSettingName -eq 'dbconnectionstr'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -DatabasePath $DatabasePath  | Should -Be $true

                    Assert-VerifiableMock
                }

                It 'Should return $false when dbProvider is set to ESENT and ConnectionString does match the value in web.config' {
                    Mock -CommandName Get-WebConfigAppSetting -MockWith {'ESENT'} -Verifiable
                    Mock -CommandName Test-WebConfigAppSetting -MockWith {Write-Verbose -Message 'Test-WebConfigAppSetting - dbconnectionstr (ESENT)'; $false} -ParameterFilter {$AppSettingName -eq 'dbconnectionstr'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present | Should -Be $false

                    Assert-VerifiableMock
                }

                It 'Should return $true when dbProvider is set to System.Data.OleDb and ConnectionString does not match the value in web.config' {
                    $DatabasePath = 'TestDrive:\DatabasePath'

                    Mock -CommandName Get-WebConfigAppSetting -MockWith {'System.Data.OleDb'} -Verifiable
                    Mock -CommandName Test-WebConfigAppSetting -MockWith {param ($ExpectedAppSettingValue) Write-Verbose -Message 'Test-WebConfigAppSetting - dbconnectionstr (OLE)'; ('Provider=Microsoft.Jet.OLEDB.4.0;Data Source={0}\Devices.mdb;' -f $DatabasePath) -eq $ExpectedAppSettingValue} -ParameterFilter {$AppSettingName -eq 'dbconnectionstr'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -DatabasePath $DatabasePath | Should -Be $true

                    Assert-VerifiableMock
                }

                It 'Should return $false when dbProvider is set to System.Data.OleDb and ConnectionString does match the value in web.config' {
                    Mock -CommandName Get-WebConfigAppSetting -MockWith {'System.Data.OleDb'} -Verifiable
                    Mock -CommandName Test-WebConfigAppSetting -MockWith {Write-Verbose -Message 'Test-WebConfigAppSetting - dbconnectionstr (OLE)'; $false} -ParameterFilter {$AppSettingName -eq 'dbconnectionstr'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present | Should -Be $false

                    Assert-VerifiableMock
                }

                Mock -CommandName Get-WebConfigAppSetting -MockWith {'ESENT'} -Verifiable
                Mock -CommandName Test-WebConfigAppSetting -MockWith {$true} -ParameterFilter {$AppSettingName -eq 'dbconnectionstr'} -Verifiable

                It 'Should return $true when ModulePath is set the same as in web.config' {
                    $modulePath = 'TestDrive:\ModulePath'

                    Mock -CommandName Test-WebConfigAppSetting -MockWith {param ($ExpectedAppSettingValue) Write-Verbose -Message 'Test-WebConfigAppSetting - ModulePath'; $modulePath -eq $ExpectedAppSettingValue} -ParameterFilter {$AppSettingName -eq 'ModulePath'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -ModulePath $modulePath | Should -Be $true

                    Assert-VerifiableMock
                }

                It 'Should return $false when ModulePath is not set the same as in web.config' {
                    Mock -CommandName Test-WebConfigAppSetting -MockWith {Write-Verbose -Message 'Test-WebConfigAppSetting - ModulePath'; $false} -ParameterFilter {$AppSettingName -eq 'ModulePath'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present | Should -Be $false

                    Assert-VerifiableMock
                }

                Mock -CommandName Test-WebConfigAppSetting -MockWith {$true} -ParameterFilter {$AppSettingName -eq 'ModulePath'} -Verifiable

                It 'Should return $true when ConfigurationPath is set the same as in web.config' {
                    $configurationPath = 'TestDrive:\ConfigurationPath'

                    Mock -CommandName Test-WebConfigAppSetting -MockWith {param ($ExpectedAppSettingValue) Write-Verbose -Message 'Test-WebConfigAppSetting - ConfigurationPath';  $configurationPath -eq $ExpectedAppSettingValue} -ParameterFilter {$AppSettingName -eq 'ConfigurationPath'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -ConfigurationPath $configurationPath | Should -Be $true

                    Assert-VerifiableMock
                }

                It 'Should return $false when ConfigurationPath is not set the same as in web.config' {
                    $configurationPath = 'TestDrive:\ConfigurationPath'

                    Mock -CommandName Test-WebConfigAppSetting -MockWith {Write-Verbose -Message 'Test-WebConfigAppSetting - ConfigurationPath'; $false} -ParameterFilter {$AppSettingName -eq 'ConfigurationPath'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -ConfigurationPath $configurationPath | Should -Be $false

                    Assert-VerifiableMock
                }

                Mock -CommandName Test-WebConfigAppSetting -MockWith {$true} -ParameterFilter {$AppSettingName -eq 'ConfigurationPath'} -Verifiable

                It 'Should return $true when RegistrationKeyPath is set the same as in web.config' {
                    $registrationKeyPath = 'TestDrive:\RegistrationKeyPath'

                    Mock -CommandName Test-WebConfigAppSetting -MockWith {param ($ExpectedAppSettingValue) Write-Verbose -Message 'Test-WebConfigAppSetting - RegistrationKeyPath';  $registrationKeyPath -eq $ExpectedAppSettingValue} -ParameterFilter {$AppSettingName -eq 'RegistrationKeyPath'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -RegistrationKeyPath $registrationKeyPath | Should -Be $true

                    Assert-VerifiableMock
                }

                It 'Should return $false when RegistrationKeyPath is not set the same as in web.config' {
                    $registrationKeyPath = 'TestDrive:\RegistrationKeyPath'

                    Mock -CommandName Test-WebConfigAppSetting -MockWith {Write-Verbose -Message 'Test-WebConfigAppSetting - RegistrationKeyPath'; $false} -ParameterFilter {$AppSettingName -eq 'RegistrationKeyPath'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -RegistrationKeyPath $registrationKeyPath | Should -Be $false

                    Assert-VerifiableMock
                }

                It 'Should return $true when AcceptSelfSignedCertificates is set the same as in web.config' {
                    $acceptSelfSignedCertificates = $true

                    Mock -CommandName Test-IISSelfSignedModuleInstalled -MockWith { $true }
                    Mock -CommandName Test-WebConfigModulesSetting -MockWith {param ($ExpectedInstallationStatus) Write-Verbose -Message 'Test-WebConfigAppSetting - IISSelfSignedCertModule'; $acceptSelfSignedCertificates -eq $ExpectedInstallationStatus} -ParameterFilter {$ModuleName -eq 'IISSelfSignedCertModule(32bit)'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -AcceptSelfSignedCertificates $acceptSelfSignedCertificates | Should -Be $true

                    Assert-VerifiableMock
                }

                It 'Should return $false when AcceptSelfSignedCertificates is not set the same as in web.config' {
                    $acceptSelfSignedCertificates = $true

                    Mock -CommandName Test-IISSelfSignedModuleInstalled -MockWith { $true }
                    Mock -CommandName Test-WebConfigModulesSetting -MockWith {Write-Verbose -Message 'Test-WebConfigAppSetting - IISSelfSignedCertModule'; $false} -ParameterFilter {$ModuleName -eq 'IISSelfSignedCertModule(32bit)'} -Verifiable

                    Test-TargetResource @testParameters -Ensure Present -AcceptSelfSignedCertificates $acceptSelfSignedCertificates | Should -Be $false

                    Assert-VerifiableMock
                }
            }

            Context -Name 'DSC Web Service is installed as HTTPS' -Fixture {
                #region Mocks
                Mock -CommandName Get-Website -MockWith {$websiteDataHTTPS}
                #endregion

                It 'Should return $false if Certificate Thumbprint is set to AllowUnencryptedTraffic' {
                    Test-TargetResource @testParameters -Ensure Present | Should -Be $false
                }

                It 'Should return $false if Certificate Subject does not match the current certificate' {
                    $altTestParameters = $testParameters.Clone()
                    $altTestParameters.Remove('CertificateThumbprint')

                    Mock -CommandName Find-CertificateThumbprintWithSubjectAndTemplateName -MockWith {'ZZYYXXWWVVUUTTSSRRQQPPOONNMMLLKKJJIIHHGG'}

                    Test-TargetResource @altTestParameters -Ensure Present -CertificateSubject 'Invalid Certifcate' | Should -Be $false
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
                }

            }

            Context -Name 'Function parameters contain invalid data' -Fixture {
                It 'Should throw if CertificateThumbprint and CertificateSubject are not specifed' {
                    $altTestParameters = $testParameters.Clone()
                    $altTestParameters.Remove('CertificateThumbPrint')

                    {Test-TargetResource @altTestParameters} | Should -Throw
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
        Describe -Name "$dscResourceName\Get-CertificateTemplateName" -Fixture {
            Mock -CommandName Get-CertificateTemplatesFromActiveDirectory -MockWith {
                @(
                    [PSCustomObject] @{
                        'Name'                    = 'WebServer'
                        'DisplayName'             = 'Web Server'
                        'mspki-cert-template-oid' = '1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.1.16'
                    }
                )
            }

            Context 'When a certificate with the extension "Certificate Template Name" is used' {
                It 'Should return the template name' {
                    Get-CertificateTemplateName -Certificate $testCertificate | Should -Be 'WebServer'
                }
            }

            Context 'When a certificate with the extension "Certificate Template Information" is used.' {
                It 'Should return the template name when there is no display name' {
                    Get-CertificateTemplateName -Certificate $testCertificateWithAltTemplateInformation | Should -Be 'WebServer'
                }

                Mock -CommandName Get-CertificateTemplateExtensionText -MockWith {
@'
Template=Web Server(1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.1.16)
Major Version Number=100
Minor Version Number=5
'@
                }

                It 'Should return the template name when there is a display name' {
                    Get-CertificateTemplateName -Certificate $testCertificateWithAltTemplateInformation | Should -Be 'WebServer'
                }
            }

            Context 'When a certificate with no template name is used' {
                It 'Should return null' {
                    Get-CertificateTemplateName -Certificate $testCertificateWithoutSan | Should -BeNullOrEmpty
                }
            }
        }

        Describe -Name "$dscResourceName\Get-CertificateTemplatesFromActiveDirectory" -Fixture {
            $MockSearchResults = @(
                @{
                    Properties = @(
                        @{
                            Name  = 'name'
                            Value = 'MockData1'
                        }
                        @{
                            Name  = 'displayName'
                            Value = 'Mock Data 1'
                        }
                    )
                }
                @{
                    Properties = @(
                        @{
                            Name  = 'name'
                            Value = 'MockData2'
                        }
                        @{
                            Name  = 'displayName'
                            Value = 'Mock Data 2'
                        }
                    )
                }
                @{
                    Properties = @(
                        @{
                            Name  = 'name'
                            Value = 'MockData3'
                        }
                        @{
                            Name  = 'displayName'
                            Value = 'Mock Data 3'
                        }
                    )
                }
            )

            $newObject_parameterFilter = {
                $TypeName  -eq 'DirectoryServices.DirectorySearcher'
            }

            $newObject_mock = {
                [PSCustomObject] @{
                    Filter     = $null
                    SearchRoot = $null
                } | Add-Member -MemberType ScriptMethod -Name FindAll -Value {
                        $MockSearchResults
                    } -PassThru
            }

            Mock -CommandName New-Object -ParameterFilter $newObject_parameterFilter -MockWith $newObject_mock
            Mock -CommandName Get-DirectoryEntry

            Context 'When certificate templates are retrieved from Active Directory successfully' {
                It 'Should get 3 mocked search results' {
                    $SearchResults = Get-CertificateTemplatesFromActiveDirectory

                    Assert-MockCalled -CommandName Get-DirectoryEntry -Exactly -Times 1
                    Assert-MockCalled -CommandName New-Object         -Exactly -Times 1

                    $SearchResults.Count | Should -Be 3
                }
            }

            Context 'When certificate templates are not retrieved from Active Directory successfully' {
                Mock -CommandName Get-DirectoryEntry -MockWith {
                    throw 'Mock: Function failed to retrieve templates from Active Directory'
                }

                It 'Should display a warning message' {
                    $Message = 'Failed to get the certificate templates from Active Directory.'

                    (Get-CertificateTemplatesFromActiveDirectory -Verbose 3>&1).Message | Should -Be $Message
                }

                It 'Should display a verbose message' {
                    $Message = 'Mock: Function failed to retrieve templates from Active Directory'

                    (Get-CertificateTemplatesFromActiveDirectory -Verbose 4>&1).Message | Should -Be $Message
                }
            }
        }

        Describe -Name "$dscResourceName\Get-CertificateTemplateInformation" -Fixture {

            $mockADTemplates = @(
                @{
                    'Name'                    = 'DisplayName1'
                    'DisplayName'             = 'Display Name 1'
                    'msPKI-Cert-Template-OID' = '1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.1234567'
                }
                @{
                    'Name'                    = 'DisplayName2'
                    'DisplayName'             = 'Display Name 2'
                    'msPKI-Cert-Template-OID' = '1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.2345678'
                }
            )

            $certificateTemplateExtensionFormattedText1 = @'
Template=Display Name 1(1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.1234567)
Major Version Number=100
Minor Version Number=5
'@

            $certificateTemplateExtensionFormattedText1NoDisplayName = @'
Template=1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.1234567
Major Version Number=100
Minor Version Number=5
'@

            $certificateTemplateExtensionFormattedText2 = @'
Template=Display Name 2(1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.2345678)
Major Version Number=100
Minor Version Number=5
'@

            $certificateTemplateExtensionFormattedText2NoDisplayName = @'
Template=1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.2345678
Major Version Number=100
Minor Version Number=5
'@

            $certificateTemplateExtensionFormattedText3 = @'
Template=Display Name 3(1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.3456789)
Major Version Number=100
Minor Version Number=5
'@

            $certificateTemplateExtensionFormattedText3NoDisplayName = @'
Template=1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.3384218.3456789
Major Version Number=100
Minor Version Number=5
'@

            $RegexTemplatePattern = '^\w+=(?<Name>.*)\((?<Oid>[\.\d]+)\)'

            Mock -CommandName Get-CertificateTemplatesFromActiveDirectory -MockWith {$mockADTemplates}

            Context 'When FormattedTemplate contains a Template OID with a Template Display Name' {

                It 'Should return the Template Name "DisplayName1"' {
                    $params =  @{
                        FormattedTemplate = $certificateTemplateExtensionFormattedText1
                    }

                    (Get-CertificateTemplateInformation @params).Name | Should -Be 'DisplayName1'
                }
                It 'Should return the Template Name "DisplayName2"' {
                    $params =  @{
                        FormattedTemplate = $certificateTemplateExtensionFormattedText2
                    }

                    (Get-CertificateTemplateInformation @params).Name | Should -Be 'DisplayName2'
                }
                It 'Should write a warning when there is no match in Active Directory' {
                    $templateValues = [Regex]::Match($certificateTemplateExtensionFormattedText3, $RegexTemplatePattern)

                    $templateText = '{0}({1})' -f $templateValues.Groups['Name'].Value, $templateValues.Groups['Oid'].Value

                    $warningMessage = $localizedData.TemplateNameResolutionError -f $templateText

                    $params =  @{
                        FormattedTemplate = $certificateTemplateExtensionFormattedText3
                    }

                    (Get-CertificateTemplateInformation @params 3>&1)[0].Message | Should -Be $warningMessage
                }
            }

            Context 'When FormattedTemplate contains a Template OID without a Template Display Name' {
                It 'Should return the Template Name "DisplayName1"' {
                    $params =  @{
                        FormattedTemplate = $certificateTemplateExtensionFormattedText1NoDisplayName
                    }

                    (Get-CertificateTemplateInformation @params).Name | Should -Be 'DisplayName1'
                }
                It 'Should return the Template Name "DisplayName2"' {
                    $params =  @{
                        FormattedTemplate = $certificateTemplateExtensionFormattedText2NoDisplayName
                    }

                    (Get-CertificateTemplateInformation @params).Name | Should -Be 'DisplayName2'
                }
                It 'Should write a warning when there is no match in Active Directory' {
                    $templateValues = [Regex]::Match($certificateTemplateExtensionFormattedText3, $RegexTemplatePattern)

                    $templateText = '{0}({1})' -f $templateValues.Groups['Name'].Value, $templateValues.Groups['Oid'].Value

                    $warningMessage = $localizedData.TemplateNameResolutionError -f $templateText

                    $params =  @{
                        FormattedTemplate = $certificateTemplateExtensionFormattedText3
                    }

                    (Get-CertificateTemplateInformation @params 3>&1)[0].Message | Should -Be $warningMessage
                }
            }

            Context 'When FormattedTemplate contains a the Template Name' {
                It 'Should return the FormattedText' {
                    $templateName  = 'TemplateName'

                    (Get-CertificateTemplateInformation -FormattedTemplate $templateName).Name | Should -Be $templateName
                }
                It 'Should return the FormattedText Without a Trailing Carriage Return' {
                    $templateName  = 'TemplateName' + [Char] 13

                    (Get-CertificateTemplateInformation -FormattedTemplate $templateName).Name | Should -Be $templateName.TrimEnd([Char] 13)
                }
            }

            Context 'When FormattedTemplate does not contain a recognised format' {
                It 'Should write a warning when there is no match in Active Directory' {
                    $formattedTemplate = 'Unrecognized Format'

                    $warningMessage = $localizedData.TemplateNameNotFound -f $formattedTemplate

                    (Get-CertificateTemplateInformation -FormattedTemplate $formattedTemplate 3>&1)[0].Message | Should -Be $warningMessage
                }
            }
        }

        Describe -Name "$dscResourceName\Get-CertificateTemplateExtensionText" -Fixture {
            Context 'When a certificate contains Certificate Template Name extension' {
                It 'Should return the Name of the Certificate Template' {
                    $params = @{
                        TemplateExtensions = $testCertificateWithAltTemplateName.Extensions
                    }

                    # Template Names have a trailing carriage return and linefeed.
                    Get-CertificateTemplateExtensionText @params | Should -Be ('WebServer' + [Char] 13 + [Char] 10)
                }
            }

            Context 'When a certificate contains Certificate Template Information extension' {
                It 'Should return the Oid, Major and Minor Version of the Certificate Template' {
                    $CertificateTemplateInformation = @'
Template=1.3.6.1.4.1.311.21.8.5734392.6195358.14893705.12992936.3444946.62.1.16
Major Version Number=100
Minor Version Number=5

'@
                    
                    $params = @{
                        TemplateExtensions = $testCertificateWithAltTemplateInformation.Extensions
                    }

                    # Template Names have a trailing carriage return and linefeed.
                    Get-CertificateTemplateExtensionText @params | Should -Be $CertificateTemplateInformation
                }
            }

            Context 'When a certificate does not contain a Certificate Template extension' {
                It 'Should not return anything' {
                    $params = @{
                        TemplateExtensions = $testCertificateWithoutSan.Extensions
                    }

                    # Template Names have a trailing carriage return and linefeed.
                    Get-CertificateTemplateExtensionText @params | Should -Be $null
                }
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
