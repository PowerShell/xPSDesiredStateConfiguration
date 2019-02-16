$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

# Import CommonTestHelper for Enter-DscResourceTestEnvironment, Exit-DscResourceTestEnvironment
$script:testsFolderFilePath = Split-Path $PSScriptRoot -Parent
$script:commonTestHelperFilePath = Join-Path -Path $testsFolderFilePath -ChildPath 'CommonTestHelper.psm1'
Import-Module -Name $commonTestHelperFilePath

if (Test-SkipContinuousIntegrationTask -Type 'Integration')
{
    return
}

$script:testEnvironment = Enter-DscResourceTestEnvironment `
    -DscResourceModuleName 'xPSDesiredStateConfiguration' `
    -DscResourceName 'xFileUpload.schema' `
    -TestType 'Integration'

try
{
    Describe 'xFileUpload Integration Tests' {
        BeforeAll {
            $script:configurationName = 'xFileUpload_Integration_Test'
            $script:confgurationFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'xFileUpload.config.ps1'

            # Create a folder to be used as the destination SMB Share
            $script:smbShareName = 'xFileUploadSMBShare'
            $script:smbSharePath = Join-Path -Path $TestDrive -ChildPath 'xFileUploadFolder'
            $null = New-Item -Path $script:smbSharePath -ItemType Directory -ErrorAction SilentlyContinue
            $null = New-SmbShare -Name $script:smbShareName -Path $script:smbSharePath -FullAccess 'Everyone' -Temporary
            $script:destinationPath = "\\localhost\$script:smbShareName\"

            # Create a file to be used as the source
            $script:sourceFileName = 'testfile.txt'
            $script:sourcePathFile = Join-Path -Path $TestDrive -ChildPath $script:sourceFileName
            $null = Set-Content -Path $script:sourcePathFile -Value 'TestContent' -Force

            # Create a folder and file to be used as the source
            $script:sourceFolderName = 'testfolder'
            $script:sourcePathFolder = Join-Path -Path $TestDrive -ChildPath $script:sourceFolderName
            $null = New-Item -Path $script:sourcePathFolder -ItemType Directory -ErrorAction SilentlyContinue
            $script:sourcePathFolderFile = Join-Path -Path $script:sourcePathFolder -ChildPath $script:sourceFileName
            $null = Set-Content -Path $script:sourcePathFolderFile -Value 'TestContent' -Force
        }

        AfterAll {
            $null = Remove-SmbShare -Name $script:smbShareName -Force
        }

        Context 'When uploading a single file to an SMB file share' {
            It 'Should compile and run configuration' {
                {
                    . $script:confgurationFilePath -ConfigurationName $script:configurationName
                    & $script:configurationName `
                        -OutputPath $TestDrive `
                        -DestinationPath $script:destinationPath `
                        -SourcePath $script:sourcePathFile

                    Start-DscConfiguration `
                        -Path $TestDrive `
                        -ErrorAction 'Stop' `
                        -Wait `
                        -Force `
                        -Verbose
                } | Should -Not -Throw
            }

            It 'Should have copied the file to the destination' {
                $uploadedFilePath = Join-Path -Path $script:smbSharePath -ChildPath $script:sourceFileName
                Test-Path -Path $uploadedFilePath | Should -Be $true
                Get-Content -Path $uploadedFilePath | Should -Be 'TestContent'
            }
        }

        Context 'When uploading a folder to an SMB file share' {
            It 'Should compile and run configuration' {
                {
                    . $script:confgurationFilePath -ConfigurationName $script:configurationName
                    & $script:configurationName `
                        -OutputPath $TestDrive `
                        -DestinationPath $script:destinationPath `
                        -SourcePath $script:sourcePathFolder

                    Start-DscConfiguration `
                        -Path $TestDrive `
                        -ErrorAction 'Stop' `
                        -Wait `
                        -Force `
                        -Verbose
                } | Should -Not -Throw
            }

            It 'Should have copied the folder to the destination' {
                $uploadedFolderPath = Join-Path -Path $script:smbSharePath -ChildPath $script:sourceFolderName
                $uploadedFilePath = Join-Path -Path $uploadedFolderPath -ChildPath $script:sourceFileName
                Test-Path -Path $uploadedFolderPath | Should -Be $true
                Test-Path -Path $uploadedFilePath | Should -Be $true
                Get-Content -Path $uploadedFilePath | Should -Be 'TestContent'
            }
        }
    }
}
finally
{
    Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
}
