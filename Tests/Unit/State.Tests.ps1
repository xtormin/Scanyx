# State.Tests.ps1
# Unit tests for state management functions

BeforeAll {
    # Load the main script
    . $PSScriptRoot\..\..\scanyx.ps1
}

Describe "Save-StateFile" -Tag "Unit", "State" {
    Context "Saving state successfully" {
        BeforeEach {
            $testStateFile = Join-Path $TestDrive "test-state.json"
            $testState = @{
                "192.168.1.1" = "completed"
                "192.168.1.2" = "pending"
                "192.168.1.3" = "failed"
            }
        }

        It "Creates new state file" {
            Save-StateFile -StateFile $testStateFile -State $testState
            Test-Path $testStateFile | Should -Be $true
        }

        It "Saves state as valid JSON" {
            Save-StateFile -StateFile $testStateFile -State $testState
            $content = Get-Content $testStateFile -Raw
            { $content | ConvertFrom-Json } | Should -Not -Throw
        }

        It "Preserves all state entries" {
            Save-StateFile -StateFile $testStateFile -State $testState
            $loaded = Get-Content $testStateFile -Raw | ConvertFrom-Json
            @($loaded.PSObject.Properties).Count | Should -Be 3
        }

        It "Overwrites existing state file" {
            # First save
            Save-StateFile -StateFile $testStateFile -State $testState

            # Second save with different data
            $newState = @{
                "10.0.0.1" = "completed"
            }
            Save-StateFile -StateFile $testStateFile -State $newState

            $loaded = Get-Content $testStateFile -Raw | ConvertFrom-Json
            $loaded.PSObject.Properties.Count | Should -Be 1
        }
    }

    Context "Edge cases" {
        It "Handles empty state" {
            $testStateFile = Join-Path $TestDrive "empty-state.json"
            $emptyState = @{}

            Save-StateFile -StateFile $testStateFile -State $emptyState
            Test-Path $testStateFile | Should -Be $true
        }

        It "Creates parent directory if needed" {
            $deepPath = Join-Path $TestDrive "deep\nested\path\state.json"
            $testState = @{ "test" = "value" }

            Save-StateFile -StateFile $deepPath -State $testState
            Test-Path $deepPath | Should -Be $true
        }
    }
}

Describe "Load-StateFile" -Tag "Unit", "State" {
    Context "Loading existing state" {
        BeforeEach {
            $testStateFile = Join-Path $TestDrive "existing-state.json"
            $testState = @{
                "192.168.1.1" = "completed"
                "192.168.1.2" = "pending"
                "192.168.1.3" = "failed"
            }
            $testState | ConvertTo-Json | Out-File $testStateFile
        }

        It "Loads state successfully" {
            $loaded = Load-StateFile -StateFile $testStateFile
            $loaded | Should -Not -BeNullOrEmpty
        }

        It "Returns hashtable" {
            $loaded = Load-StateFile -StateFile $testStateFile
            $loaded.GetType().Name | Should -Match "Hashtable|Dictionary"
        }

        It "Preserves all entries" {
            $loaded = Load-StateFile -StateFile $testStateFile
            $loaded.Count | Should -Be 3
        }

        It "Preserves correct values" {
            $loaded = Load-StateFile -StateFile $testStateFile
            $loaded["192.168.1.1"] | Should -Be "completed"
            $loaded["192.168.1.2"] | Should -Be "pending"
            $loaded["192.168.1.3"] | Should -Be "failed"
        }
    }

    Context "Non-existing state file" {
        It "Returns empty hashtable for non-existing file" {
            $nonExistingFile = Join-Path $TestDrive "non-existing.json"
            $loaded = Load-StateFile -StateFile $nonExistingFile

            $loaded -ne $null | Should -Be $true
            $loaded -is [hashtable] | Should -Be $true
            $loaded.Count | Should -Be 0
        }
    }

    Context "Corrupted state file" {
        It "Handles corrupted JSON gracefully" {
            $corruptedFile = Join-Path $TestDrive "corrupted.json"
            "{ this is not valid json }" | Out-File $corruptedFile

            # Should not throw, should return empty or log error
            { $loaded = Load-StateFile -StateFile $corruptedFile } | Should -Not -Throw
        }

        It "Handles empty file" {
            $emptyFile = Join-Path $TestDrive "empty.json"
            "" | Out-File $emptyFile

            { $loaded = Load-StateFile -StateFile $emptyFile } | Should -Not -Throw
        }
    }
}

Describe "Update-HostState" -Tag "Unit", "State" {
    Context "Updating host states" {
        BeforeEach {
            $testState = @{
                "192.168.1.1" = "pending"
                "192.168.1.2" = "pending"
            }
        }

        It "Updates existing host state" {
            Update-HostState -State $testState -TargetHost "192.168.1.1" -NewState "completed"
            $testState["192.168.1.1"] | Should -Be "completed"
        }

        It "Adds new host to state" {
            Update-HostState -State $testState -TargetHost "192.168.1.3" -NewState "pending"
            $testState.ContainsKey("192.168.1.3") | Should -Be $true
            $testState["192.168.1.3"] | Should -Be "pending"
        }

        It "Changes state from failed to completed" {
            $testState["192.168.1.1"] = "failed"
            Update-HostState -State $testState -TargetHost "192.168.1.1" -NewState "completed"
            $testState["192.168.1.1"] | Should -Be "completed"
        }

        It "Updates multiple hosts independently" {
            Update-HostState -State $testState -TargetHost "192.168.1.1" -NewState "completed"
            Update-HostState -State $testState -TargetHost "192.168.1.2" -NewState "failed"

            $testState["192.168.1.1"] | Should -Be "completed"
            $testState["192.168.1.2"] | Should -Be "failed"
        }
    }

    Context "Valid state transitions" {
        BeforeEach {
            $testState = @{}
        }

        It "Allows pending -> completed" {
            Update-HostState -State $testState -TargetHost "host1" -NewState "pending"
            Update-HostState -State $testState -TargetHost "host1" -NewState "completed"
            $testState["host1"] | Should -Be "completed"
        }

        It "Allows pending -> failed" {
            Update-HostState -State $testState -TargetHost "host2" -NewState "pending"
            Update-HostState -State $testState -TargetHost "host2" -NewState "failed"
            $testState["host2"] | Should -Be "failed"
        }

        It "Allows failed -> completed (retry success)" {
            Update-HostState -State $testState -TargetHost "host3" -NewState "failed"
            Update-HostState -State $testState -TargetHost "host3" -NewState "completed"
            $testState["host3"] | Should -Be "completed"
        }
    }
}

Describe "Get-OutputFolder" -Tag "Unit", "State" {
    Context "Folder generation" {
        BeforeAll {
            $testBaseDir = $TestDrive
        }

        It "Generates folder with host IP" {
            $result = Get-OutputFolder -BaseDir $testBaseDir -TargetHost "192.168.1.1" -ScanType "tcp-1000"
            $result | Should -Match "192\.168\.1\.1"
        }

        It "Generates folder with scan type" {
            $result = Get-OutputFolder -BaseDir $testBaseDir -TargetHost "192.168.1.1" -ScanType "tcp-full"
            $result | Should -Match "tcp-full"
        }

        It "Returns absolute path" {
            $result = Get-OutputFolder -BaseDir $testBaseDir -TargetHost "192.168.1.1" -ScanType "tcp-1000"
            [System.IO.Path]::IsPathRooted($result) | Should -Be $true
        }

        It "Creates unique folders for different hosts" {
            $folder1 = Get-OutputFolder -BaseDir $testBaseDir -TargetHost "192.168.1.1" -ScanType "tcp-1000"
            $folder2 = Get-OutputFolder -BaseDir $testBaseDir -TargetHost "192.168.1.2" -ScanType "tcp-1000"

            $folder1 | Should -Not -Be $folder2
        }

        It "Creates unique folders for different scan types" {
            $folder1 = Get-OutputFolder -BaseDir $testBaseDir -TargetHost "192.168.1.1" -ScanType "tcp-1000"
            $folder2 = Get-OutputFolder -BaseDir $testBaseDir -TargetHost "192.168.1.1" -ScanType "udp-1000"

            $folder1 | Should -Not -Be $folder2
        }
    }

    Context "Sanitization" {
        It "Handles hostnames with dots" {
            $result = Get-OutputFolder -BaseDir $TestDrive -TargetHost "server.example.com" -ScanType "tcp-1000"
            # Should sanitize dots or handle safely
            $result | Should -Not -BeNullOrEmpty
        }

        It "Handles special characters in scan type" {
            $result = Get-OutputFolder -BaseDir $TestDrive -TargetHost "192.168.1.1" -ScanType "custom-scan"
            $result | Should -Not -BeNullOrEmpty
        }
    }
}
