$errorActionPreference = 'Stop'
Set-StrictMode -Version 'Latest'

Describe 'xArchive End to End Tests' {
    BeforeAll {
        # Import CommonTestHelper for Enter-DscResourceTestEnvironment, Exit-DscResourceTestEnvironment
        $script:testsFolderFilePath = Split-Path $PSScriptRoot -Parent
        $script:commonTestHelperFilePath = Join-Path -Path $testsFolderFilePath -ChildPath 'CommonTestHelper.psm1'
        Import-Module -Name $commonTestHelperFilePath

        $script:testEnvironment = Enter-DscResourceTestEnvironment `
            -DscResourceModuleName 'xPSDesiredStateConfiguration' `
            -DscResourceName 'MSFT_xArchive' `
            -TestType 'Integration'

        # Import Archive resource module for Get-TargetResource, Test-TargetResource, Set-TargetResource
        $moduleRootFilePath = Split-Path -Path $script:testsFolderFilePath -Parent
        $dscResourcesFolderFilePath = Join-Path -Path $moduleRootFilePath -ChildPath 'DscResources'
        $archiveResourceFolderFilePath = Join-Path -Path $dscResourcesFolderFilePath -ChildPath 'MSFT_xArchive'
        $archiveResourceModuleFilePath = Join-Path -Path $archiveResourceFolderFilePath -ChildPath 'MSFT_xArchive.psm1'
        Import-Module -Name $archiveResourceModuleFilePath -Force

        # Force is specified as true for both of these configurations
        $script:confgurationFilePathValidateOnly = Join-Path -Path $PSScriptRoot -ChildPath 'MSFT_xArchive_ValidateOnly.config.ps1'
        $script:confgurationFilePathValidateAndChecksum = Join-Path -Path $PSScriptRoot -ChildPath 'MSFT_xArchive_ValidateAndChecksum.config.ps1'
        $script:confgurationFilePathCredentialOnly = Join-Path -Path $PSScriptRoot -ChildPath 'MSFT_xArchive_CredentialOnly.config.ps1'

        # Import the Archive test helper for New-ZipFileFromHashtable and Test-FileStructuresMatch
        $archiveTestHelperFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'MSFT_xArchive.TestHelper.psm1'
        Import-Module -Name $archiveTestHelperFilePath -Force

        # Create the test source archive
        $script:testArchiveName = 'TestArchive1'

        $testArchiveFileStructure = @{
            Folder1 = @{}
            Folder2 = @{
                Folder21 = @{
                    Folder22 = @{
                        Folder23 = @{}
                    }
                }
            }
            Folder3 = @{
                Folder31 = @{
                    Folder31 = @{
                        Folder33 = @{
                            Folder34 = @{
                                File31 = 'Fake file contents'
                            }
                        }
                    }
                }
            }
            Folder4 = @{
                Folder41 = @{
                    Folder42 = @{
                        Folder43 = @{
                            Folder44 = @{}
                        }
                    }
                }
            }
            File1 = 'Fake file contents'
            File2 = 'Fake file contents'
        }

        $script:testArchiveFilePath = New-ZipFileFromHashtable -Name $script:testArchiveName -ParentPath $TestDrive -ZipFileStructure $testArchiveFileStructure
        $script:testArchiveFilePathWithoutExtension = $script:testArchiveFilePath.Replace('.zip', '')

        $script:testArchiveWithDifferentFileContentName = $script:testArchiveName

        $testArchiveFileWithDifferentFileContentStructure = @{
            Folder1 = @{}
            Folder2 = @{
                Folder21 = @{
                    Folder22 = @{
                        Folder23 = @{}
                    }
                }
            }
            Folder3 = @{
                Folder31 = @{
                    Folder31 = @{
                        Folder33 = @{
                            Folder34 = @{
                                File31 = 'Different fake file contents'
                            }
                        }
                    }
                }
            }
            Folder4 = @{
                Folder41 = @{
                    Folder42 = @{
                        Folder43 = @{
                            Folder44 = @{}
                        }
                    }
                }
            }
            File1 = 'Different fake file contents'
            File2 = 'Different fake file contents'
        }

        $testArchiveFileWithDifferentFileContentParentPath = Join-Path -Path $TestDrive -ChildPath 'MismatchingArchive'
        $null = New-Item -Path $testArchiveFileWithDifferentFileContentParentPath -ItemType 'Directory'

        $script:testArchiveFileWithDifferentFileContentPath = New-ZipFileFromHashtable -Name $script:testArchiveWithDifferentFileContentName -ParentPath $testArchiveFileWithDifferentFileContentParentPath -ZipFileStructure $testArchiveFileWithDifferentFileContentStructure
        $script:testArchiveFileWithDifferentFileContentPathWithoutExtension = $script:testArchiveFileWithDifferentFileContentPath.Replace('.zip', '')
    }

    AfterAll {
        Exit-DscResourceTestEnvironment -TestEnvironment $script:testEnvironment
    }

    Context 'Expand an archive to a destination that does not yet exist' {
        $configurationName = 'ExpandArchiveToEmptyDestination'

        $emptyDestination = Join-Path -Path $TestDrive -ChildPath 'NonExistantDestination'

        It 'Destination should not exist before configuration' {
            Test-Path -Path $emptyDestination | Should Be $false
        }

        $archiveParameters = @{
            Path = $script:testArchiveFilePath
            Destination = $emptyDestination
            Ensure = 'Present'
        }

        It 'Should return false from Test-TargetResource with the same parameters before configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $false
        }

        It 'Should compile and run configuration' {
            { 
                . $script:confgurationFilePathValidateOnly -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @archiveParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Destination should exist after configuration' {
            Test-Path -Path $emptyDestination | Should Be $true
        }

        It 'File structure of destination should match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $emptyDestination | Should Be $true
        }

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }
    }

    Context 'Expand an archive to an existing destination with items that are not in the archive' {
        $configurationName = 'ExpandArchiveToDestinationWithOtherItems'

        $destinationWithOtherItems = Join-Path -Path $TestDrive -ChildPath 'DestinationWithOtherItems'
        $null = New-Item -Path $destinationWithOtherItems -ItemType 'Directory'

        # Keys are the paths to the items. Values are the items' contents with an empty string denoting a directory
        $otherItems = @{}

        $otherDirectoryPath = Join-Path -Path $destinationWithOtherItems -ChildPath 'OtherDirectory'
        $null = New-Item -Path $otherDirectoryPath -ItemType 'Directory'
        $otherItems[$otherDirectoryPath] = ''

        $otherSubDirectoryPath = Join-Path -Path $otherDirectoryPath -ChildPath 'OtherSubDirectory'
        $null = New-Item -Path $otherSubDirectoryPath -ItemType 'Directory'
        $otherItems[$otherSubDirectoryPath] = ''

        $otherFilePath = Join-Path $otherSubDirectoryPath -ChildPath 'OtherFile'
        $otherFileContent = 'Other file content'
        $null = New-Item -Path $otherFilePath -ItemType 'File'
        $null = Set-Content -Path $otherFilePath -Value $otherFileContent
        $otherItems[$otherFilePath] = $otherFileContent

        It 'Destination should exist before configuration' {
            Test-Path -Path $destinationWithOtherItems | Should Be $true
        }

        foreach ($otherItemPath in $otherItems.Keys)
        {
            $otherItemName = Split-Path -Path $otherItemPath -Leaf
            $otherItemExpectedContent = $otherItems[$otherItemPath]
            $otherItemIsDirectory = [String]::IsNullOrEmpty($otherItemExpectedContent)

            if ($otherItemIsDirectory)
            {
                It "Other item under destination $otherItemName should exist as a directory before configuration" {
                    Test-Path -Path $otherItemPath -PathType 'Container' | Should Be $true
                }
            }
            else
            {
                It "Other item under destination $otherItemName should exist as a file before configuration" {
                    Test-Path -Path $otherItemPath -PathType 'Leaf' | Should Be $true
                }

                It "Other file under destination $otherItemName should have the expected content before configuration" {
                    Get-Content -Path $otherItemPath -Raw -ErrorAction 'SilentlyContinue' | Should Be ($otherItemExpectedContent + "`r`n")
                }
            }
        }

        $archiveParameters = @{
            Path = $script:testArchiveFilePath
            Destination = $destinationWithOtherItems
            Ensure = 'Present'
        }

        It 'Should return false from Test-TargetResource with the same parameters before configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $false
        }

        It 'Should compile and run configuration' {
            { 
                . $script:confgurationFilePathValidateOnly -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @archiveParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Destination should exist after configuration' {
            Test-Path -Path $destinationWithOtherItems | Should Be $true
        }

        It 'File structure of destination should match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithOtherItems | Should Be $true
        }

        foreach ($otherItemPath in $otherItems.Keys)
        {
            $otherItemName = Split-Path -Path $otherItemPath -Leaf
            $otherItemExpectedContent = $otherItems[$otherItemPath]
            $otherItemIsDirectory = [String]::IsNullOrEmpty($otherItemExpectedContent)

            if ($otherItemIsDirectory)
            {
                It "Other item under destination $otherItemName should exist as a directory after configuration" {
                    Test-Path -Path $otherItemPath -PathType 'Container' | Should Be $true
                }
            }
            else
            {
                It "Other item under destination $otherItemName should exist as a file after configuration" {
                    Test-Path -Path $otherItemPath -PathType 'Leaf' | Should Be $true
                }

                It "Other file under destination $otherItemName should have the expected after before configuration" {
                    Get-Content -Path $otherItemPath -Raw -ErrorAction 'SilentlyContinue' | Should Be ($otherItemExpectedContent + "`r`n")
                }
            }
        }

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }
    }
    
    Context 'Expand an archive to an existing destination that already contains the same archive files' {
        $configurationName = 'ExpandArchiveToDestinationWithArchive'

        $destinationWithArchive = Join-Path -Path $TestDrive -ChildPath 'DestinationWithOtherItems'
        $null = New-Item -Path $destinationWithArchive -ItemType 'Directory'

        $null = Expand-Archive -Path $script:testArchiveFilePath -DestinationPath $destinationWithArchive -Force

        It 'Destination should exist before configuration' {
            Test-Path -Path $destinationWithArchive | Should Be $true
        }

        It 'File structure of destination should match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithArchive | Should Be $true
        }

        $archiveParameters = @{
            Path = $script:testArchiveFilePath
            Destination = $destinationWithArchive
            Ensure = 'Present'
        }

        It 'Should return true from Test-TargetResource with the same parameters before configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }

        It 'Should compile and run configuration' {
            { 
                . $script:confgurationFilePathValidateOnly -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @archiveParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Destination should exist after configuration' {
            Test-Path -Path $destinationWithArchive | Should Be $true
        }

        It 'File structure of destination should match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithArchive | Should Be $true
        }

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }
    }

    Context 'Expand an archive to a destination that contains archive files that do not match by the specified SHA Checksum without Force specified' {
        $configurationName = 'ExpandArchiveToDestinationWithMismatchingArchive'

        $destinationWithMismatchingArchive = Join-Path -Path $TestDrive -ChildPath 'DestinationWithMismatchingArchive'
        $null = New-Item -Path $destinationWithMismatchingArchive -ItemType 'Directory'

        $null = Expand-Archive -Path $script:testArchiveFileWithDifferentFileContentPath -DestinationPath $destinationWithMismatchingArchive -Force

        It 'Destination should exist before configuration' {
            Test-Path -Path $destinationWithMismatchingArchive | Should Be $true
        }

        It 'File structure of destination should match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMismatchingArchive | Should Be $true
        }

        It 'File contents of destination should not match the file contents of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMismatchingArchive -CheckContents | Should Be $false
        }

        $archiveParameters = @{
            Path = $script:testArchiveFilePath
            Destination = $destinationWithMismatchingArchive
            Ensure = 'Present'
            Validate = $true
            Checksum = 'SHA-256'
            Force = $false
        }

        It 'Should return false from Test-TargetResource with the same parameters before configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $false
        }

        It 'Should compile and run configuration and throw an error for attempting to overwrite files without Force specified' {
            # We don't know which file will throw the error, so we will only check that an error was thrown rather than checking the specific error message
            { 
                . $script:confgurationFilePathValidateAndChecksum -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @archiveParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Throw
        }

        It 'Destination should exist after configuration' {
            Test-Path -Path $destinationWithMismatchingArchive | Should Be $true
        }

        It 'File structure of destination should match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMismatchingArchive | Should Be $true
        }

        It 'File contents of destination should not match the file contents of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMismatchingArchive -CheckContents | Should Be $false
        }

        It 'Should return false from Test-TargetResource with the same parameters after configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $false
        }
    }

    Context 'Expand an archive to a destination that contains archive files that do not match by the specified SHA Checksum with Force specified' {
        $configurationName = 'ExpandArchiveToDestinationWithMismatchingArchive'

        $destinationWithMismatchingArchive = Join-Path -Path $TestDrive -ChildPath 'DestinationWithMismatchingArchive'
        $null = New-Item -Path $destinationWithMismatchingArchive -ItemType 'Directory'

        $null = Expand-Archive -Path $script:testArchiveFileWithDifferentFileContentPath -DestinationPath $destinationWithMismatchingArchive -Force

        It 'Destination should exist before configuration' {
            Test-Path -Path $destinationWithMismatchingArchive | Should Be $true
        }

        It 'File structure of destination should match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMismatchingArchive | Should Be $true
        }

        It 'File contents of destination should not match the file contents of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMismatchingArchive -CheckContents | Should Be $false
        }

        $archiveParameters = @{
            Path = $script:testArchiveFilePath
            Destination = $destinationWithMismatchingArchive
            Ensure = 'Present'
            Validate = $true
            Checksum = 'SHA-256'
            Force = $true
        }

        It 'Should return false from Test-TargetResource with the same parameters before configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $false
        }

        It 'Should compile and run configuration' {
            { 
                . $script:confgurationFilePathValidateAndChecksum -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @archiveParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Destination should exist after configuration' {
            Test-Path -Path $destinationWithMismatchingArchive | Should Be $true
        }

        It 'File structure of destination should match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMismatchingArchive | Should Be $true
        }

        It 'File contents of destination should match the file contents of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMismatchingArchive -CheckContents | Should Be $true
        }

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }
    }

    Context 'Expand an archive to a destination that contains archive files that match by the specified SHA Checksum' {
        $configurationName = 'ExpandArchiveToDestinationWithMatchingArchive'

        $destinationWithMatchingArchive = Join-Path -Path $TestDrive -ChildPath 'DestinationWithMatchingArchive'
        $null = New-Item -Path $destinationWithMatchingArchive -ItemType 'Directory'

        $null = Expand-Archive -Path $script:testArchiveFilePath -DestinationPath $destinationWithMatchingArchive -Force

        It 'Destination should exist before configuration' {
            Test-Path -Path $destinationWithMatchingArchive | Should Be $true
        }

        It 'File structure of destination should match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMatchingArchive | Should Be $true
        }

        It 'File contents of destination should match the file contents of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMatchingArchive -CheckContents | Should Be $true
        }

        $archiveParameters = @{
            Path = $script:testArchiveFilePath
            Destination = $destinationWithMatchingArchive
            Ensure = 'Present'
            Validate = $true
            Checksum = 'SHA-256'
            Force = $true
        }

        It 'Should return true from Test-TargetResource with the same parameters before configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }

        It 'Should compile and run configuration' {
            { 
                . $script:confgurationFilePathValidateAndChecksum -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @archiveParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Destination should exist after configuration' {
            Test-Path -Path $destinationWithMatchingArchive | Should Be $true
        }

        It 'File structure of destination should match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMatchingArchive | Should Be $true
        }

        It 'File contents of destination should match the file contents of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMatchingArchive -CheckContents | Should Be $true
        }

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }
    }
    
    Context 'Remove an expanded archive from an existing destination that contains only the expanded archive' {
        $configurationName = 'RemoveArchiveAtDestinationWithArchive'

        $destinationWithArchive = Join-Path -Path $TestDrive -ChildPath 'DestinationWithArchiveForRemove'
        $null = New-Item -Path $destinationWithArchive -ItemType 'Directory'

        $null = Expand-Archive -Path $script:testArchiveFilePath -DestinationPath $destinationWithArchive -Force

        It 'Destination should exist before configuration' {
            Test-Path -Path $destinationWithArchive | Should Be $true
        }

        It 'File structure of destination should match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithArchive | Should Be $true
        }

        $archiveParameters = @{
            Path = $script:testArchiveFilePath
            Destination = $destinationWithArchive
            Ensure = 'Absent'
        }

        It 'Should return false from Test-TargetResource with the same parameters before configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $false
        }

        It 'Should compile and run configuration' {
            { 
                . $script:confgurationFilePathValidateOnly -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @archiveParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Destination should exist after configuration' {
            Test-Path -Path $destinationWithArchive | Should Be $true
        }

        It 'File structure of destination should not match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithArchive | Should Be $false
        }

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }
    }

    Context 'Remove an expanded archive from an existing destination that contains the expanded archive and other files' {
        $configurationName = 'RemoveArchiveAtDestinationWithArchiveAndOtherFiles'

        $destinationWithArchiveAndOtherFiles = Join-Path -Path $TestDrive -ChildPath 'DestinationWithArchiveAndOtherFilesForRemove'
        $null = New-Item -Path $destinationWithArchiveAndOtherFiles -ItemType 'Directory'

        $null = Expand-Archive -Path $script:testArchiveFilePath -DestinationPath $destinationWithArchiveAndOtherFiles -Force

        # Keys are the paths to the items. Values are the items' contents with an empty string denoting a directory
        $otherItems = @{}

        $otherDirectoryPath = Join-Path -Path $destinationWithArchiveAndOtherFiles -ChildPath 'OtherDirectory'
        $null = New-Item -Path $otherDirectoryPath -ItemType 'Directory'
        $otherItems[$otherDirectoryPath] = ''

        $otherSubDirectoryPath = Join-Path -Path $otherDirectoryPath -ChildPath 'OtherSubDirectory'
        $null = New-Item -Path $otherSubDirectoryPath -ItemType 'Directory'
        $otherItems[$otherSubDirectoryPath] = ''

        $otherFilePath = Join-Path $otherSubDirectoryPath -ChildPath 'OtherFile'
        $otherFileContent = 'Other file content'
        $null = New-Item -Path $otherFilePath -ItemType 'File'
        $null = Set-Content -Path $otherFilePath -Value $otherFileContent
        $otherItems[$otherFilePath] = $otherFileContent

        It 'Destination should exist before configuration' {
            Test-Path -Path $destinationWithArchiveAndOtherFiles | Should Be $true
        }

        foreach ($otherItemPath in $otherItems.Keys)
        {
            $otherItemName = Split-Path -Path $otherItemPath -Leaf
            $otherItemExpectedContent = $otherItems[$otherItemPath]
            $otherItemIsDirectory = [String]::IsNullOrEmpty($otherItemExpectedContent)

            if ($otherItemIsDirectory)
            {
                It "Other item under destination $otherItemName should exist as a directory before configuration" {
                    Test-Path -Path $otherItemPath -PathType 'Container' | Should Be $true
                }
            }
            else
            {
                It "Other item under destination $otherItemName should exist as a file before configuration" {
                    Test-Path -Path $otherItemPath -PathType 'Leaf' | Should Be $true
                }

                It "Other file under destination $otherItemName should have the expected content before configuration" {
                    Get-Content -Path $otherItemPath -Raw -ErrorAction 'SilentlyContinue' | Should Be ($otherItemExpectedContent + "`r`n")
                }
            }
        }

        # Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $emptyDestination

        $archiveParameters = @{
            Path = $script:testArchiveFilePath
            Destination = $destinationWithArchiveAndOtherFiles
            Ensure = 'Absent'
        }

        It 'Should return false from Test-TargetResource with the same parameters before configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $false
        }

        It 'Should compile and run configuration' {
            { 
                . $script:confgurationFilePathValidateOnly -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @archiveParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Destination should exist after configuration' {
            Test-Path -Path $destinationWithArchiveAndOtherFiles | Should Be $true
        }

        foreach ($otherItemPath in $otherItems.Keys)
        {
            $otherItemName = Split-Path -Path $otherItemPath -Leaf
            $otherItemExpectedContent = $otherItems[$otherItemPath]
            $otherItemIsDirectory = [String]::IsNullOrEmpty($otherItemExpectedContent)

            if ($otherItemIsDirectory)
            {
                It "Other item under destination $otherItemName should exist as a directory before configuration" {
                    Test-Path -Path $otherItemPath -PathType 'Container' | Should Be $true
                }
            }
            else
            {
                It "Other item under destination $otherItemName should exist as a file before configuration" {
                    Test-Path -Path $otherItemPath -PathType 'Leaf' | Should Be $true
                }

                It "Other file under destination $otherItemName should have the expected content before configuration" {
                    Get-Content -Path $otherItemPath -Raw -ErrorAction 'SilentlyContinue' | Should Be ($otherItemExpectedContent + "`r`n")
                }
            }
        }

        # Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $emptyDestination

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }
    }

    Context 'Remove an expanded archive from an existing destination that does not contain any archive files' {
        $configurationName = 'RemoveArchiveAtDestinationWithoutArchive'

        $destinationWithoutArchive = Join-Path -Path $TestDrive -ChildPath 'DestinationWithoutArchiveForRemove'
        $null = New-Item -Path $destinationWithoutArchive -ItemType 'Directory'

        It 'Destination should exist before configuration' {
            Test-Path -Path $destinationWithoutArchive | Should Be $true
        }

        # Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $emptyDestination

        $archiveParameters = @{
            Path = $script:testArchiveFilePath
            Destination = $destinationWithoutArchive
            Ensure = 'Absent'
        }

        It 'Should return true from Test-TargetResource with the same parameters before configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }

        It 'Should compile and run configuration' {
            { 
                . $script:confgurationFilePathValidateOnly -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @archiveParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Destination should exist after configuration' {
            Test-Path -Path $destinationWithoutArchive | Should Be $true
        }

        # Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $emptyDestination

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }
    }

    Context 'Remove an expanded archive from a destination that does not exist' {
        $configurationName = 'RemoveArchiveFromMissingDestination'

        $destinationMissing = Join-Path -Path $TestDrive -ChildPath 'MissingDestinationForRemove'

        It 'Destination should not exist before configuration' {
            Test-Path -Path $destinationMissing | Should Be $false
        }

        # Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $emptyDestination

        $archiveParameters = @{
            Path = $script:testArchiveFilePath
            Destination = $destinationMissing
            Ensure = 'Absent'
        }

        It 'Should return true from Test-TargetResource with the same parameters before configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }

        It 'Should compile and run configuration' {
            { 
                . $script:confgurationFilePathValidateOnly -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @archiveParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Destination should not exist after configuration' {
            Test-Path -Path $destinationMissing | Should Be $false
        }

        # Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $emptyDestination

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }
    }

    Context 'Remove an archive from a destination that contains archive files that do not match by the specified SHA Checksum' {
        $configurationName = 'RemoveArchiveFromDestinationWithMismatchingArchiveWithSHA'

        $destinationWithMismatchingArchive = Join-Path -Path $TestDrive -ChildPath 'DestinationWithMismatchingArchive'
        $null = New-Item -Path $destinationWithMismatchingArchive -ItemType 'Directory'

        $null = Expand-Archive -Path $script:testArchiveFileWithDifferentFileContentPath -DestinationPath $destinationWithMismatchingArchive -Force

        It 'Destination should exist before configuration' {
            Test-Path -Path $destinationWithMismatchingArchive | Should Be $true
        }

        It 'File structure of destination should match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMismatchingArchive | Should Be $true
        }

        It 'File contents of destination should not match the file contents of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMismatchingArchive -CheckContents | Should Be $false
        }

        $archiveParameters = @{
            Path = $script:testArchiveFilePath
            Destination = $destinationWithMismatchingArchive
            Ensure = 'Absent'
            Validate = $true
            Checksum = 'SHA-256'
            Force = $true
        }

        It 'Should return true from Test-TargetResource with the same parameters before configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }

        It 'Should compile and run configuration' {
            { 
                . $script:confgurationFilePathValidateAndChecksum -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @archiveParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Destination should exist after configuration' {
            Test-Path -Path $destinationWithMismatchingArchive | Should Be $true
        }

        It 'File structure of destination should match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMismatchingArchive | Should Be $true
        }

        It 'File contents of destination should not match the file contents of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMismatchingArchive -CheckContents | Should Be $false
        }

        It 'Should return true from Test-TargetResource with the same parameters after configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }
    }

    Context 'Remove an archive from a destination that contains archive files that match by the specified SHA Checksum' {
        $configurationName = 'RemoveArchiveFromDestinationWithMatchingArchiveWithSHA'

        $destinationWithMatchingArchive = Join-Path -Path $TestDrive -ChildPath 'DestinationWithMatchingArchive'
        $null = New-Item -Path $destinationWithMatchingArchive -ItemType 'Directory'

        $null = Expand-Archive -Path $script:testArchiveFilePath -DestinationPath $destinationWithMatchingArchive -Force

        It 'Destination should exist before configuration' {
            Test-Path -Path $destinationWithMatchingArchive | Should Be $true
        }

        It 'File structure and contents of destination should match the file contents of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMatchingArchive -CheckContents | Should Be $true
        }

        $archiveParameters = @{
            Path = $script:testArchiveFilePath
            Destination = $destinationWithMatchingArchive
            Ensure = 'Absent'
            Validate = $true
            Checksum = 'SHA-256'
            Force = $true
        }

        It 'Should return false from Test-TargetResource with the same parameters before configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $false
        }

        It 'Should compile and run configuration' {
            { 
                . $script:confgurationFilePathValidateAndChecksum -ConfigurationName $configurationName
                & $configurationName -OutputPath $TestDrive @archiveParameters
                Start-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' -Wait -Force
            } | Should Not Throw
        }

        It 'Destination should exist after configuration' {
            Test-Path -Path $destinationWithMatchingArchive | Should Be $true
        }

        It 'File structure of destination should not match the file structure of the archive' {
            Test-FileStructuresMatch -SourcePath $script:testArchiveFilePathWithoutExtension -DestinationPath $destinationWithMatchingArchive | Should Be $false
        }

        It 'Should return false from Test-TargetResource with the same parameters after configuration' {
            MSFT_xArchive\Test-TargetResource @archiveParameters | Should Be $true
        }
    }
}
