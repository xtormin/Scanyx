# State.Tests.ps1
# Unit tests for state management functions

BeforeAll {
    # Load the main script
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1'))
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
            $deepPath = [IO.Path]::Combine($TestDrive, "deep", "nested", "path", "state.json")
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

Describe "Cross-platform paths" -Tag "Unit", "State", "CrossPlatform" {
    Context "Get-OutputFolder uses the native separator" {
        It "Never emits a backslash on Unix (single scan, from CIDR)" -Skip:($null -eq $IsLinux -or -not ($IsLinux -or $IsMacOS)) {
            $result = Get-OutputFolder -BaseDir "/tmp/scanyx" -TargetHost "10.0.0.5" -SourceCIDR "10.0.0.0/24"
            $result | Should -Not -Match '\\'
            $result | Should -Match 'networks'
        }

        It "Never emits a backslash on Unix (single scan, individual host)" -Skip:($null -eq $IsLinux -or -not ($IsLinux -or $IsMacOS)) {
            $result = Get-OutputFolder -BaseDir "/tmp/scanyx" -TargetHost "10.0.0.5"
            $result | Should -Not -Match '\\'
            $result | Should -Match 'hosts'
        }

        It "Never emits a backslash on Unix (workflow mode)" -Skip:($null -eq $IsLinux -or -not ($IsLinux -or $IsMacOS)) {
            $result = Get-OutputFolder -BaseDir "/tmp/scanyx" -TargetHost "10.0.0.5" `
                        -WorkflowName "full-discovery" -WorkflowStep 1 -StepProfile "tcp-1000"
            $result | Should -Not -Match '\\'
            $result | Should -Match 'S1-tcp-1000'
        }

        It "Uses the platform separator in every mode" {
            $sep = [IO.Path]::DirectorySeparatorChar
            $paths = @(
                (Get-OutputFolder -BaseDir $TestDrive -TargetHost "10.0.0.5" -SourceCIDR "10.0.0.0/24"),
                (Get-OutputFolder -BaseDir $TestDrive -TargetHost "10.0.0.5"),
                (Get-OutputFolder -BaseDir $TestDrive -TargetHost "10.0.0.5" -ScanType "tcp-1000"),
                (Get-OutputFolder -BaseDir $TestDrive -TargetHost "10.0.0.5" -WorkflowName "wf" -WorkflowStep 2 -StepProfile "tcp-full")
            )
            foreach ($path in $paths) {
                $path | Should -BeLike "*$sep*"
            }
        }

        It "Replaces the CIDR slash so it does not become a directory level" {
            $result = Get-OutputFolder -BaseDir $TestDrive -TargetHost "10.0.0.5" -SourceCIDR "10.0.0.0/24"
            $result | Should -Match '10\.0\.0\.0-24'
        }
    }
}

Describe "Update-HostState liveness fields" -Tag "Unit", "State", "Liveness" {

    It "Stores the verdict, its reason and the open-port count" {
        $state = @{ hosts = @{}; completed = 0; failed = 0; pending = 0 }
        Update-HostState -State $state -TargetHost "10.0.0.1" -Status "completed" -ScanFile "/tmp/a.nmap" `
                         -Liveness "alive" -LivenessReason "no open ports; 31 closed" -OpenPortCount 0

        $state.hosts["10.0.0.1"].liveness | Should -Be "alive"
        $state.hosts["10.0.0.1"].liveness_reason | Should -Be "no open ports; 31 closed"
        $state.hosts["10.0.0.1"].open_port_count | Should -Be 0
    }

    It "Preserves the verdict when a later call only changes status" {
        # A failed retry must not erase a verdict earned on the previous attempt.
        $state = @{ hosts = @{}; completed = 0; failed = 0; pending = 0 }
        Update-HostState -State $state -TargetHost "10.0.0.2" -Status "completed" -ScanFile "/tmp/b.nmap" `
                         -Liveness "open" -LivenessReason "2 open" -OpenPortCount 2
        Update-HostState -State $state -TargetHost "10.0.0.2" -Status "failed" -Error "timeout"

        $state.hosts["10.0.0.2"].status | Should -Be "failed"
        $state.hosts["10.0.0.2"].liveness | Should -Be "open"
        $state.hosts["10.0.0.2"].open_port_count | Should -Be 2
    }

    It "Lets an explicit verdict override the preserved one" {
        $state = @{ hosts = @{}; completed = 0; failed = 0; pending = 0 }
        Update-HostState -State $state -TargetHost "10.0.0.3" -Status "completed" -Liveness "filtered"
        Update-HostState -State $state -TargetHost "10.0.0.3" -Status "completed" -Liveness "open" -OpenPortCount 1

        $state.hosts["10.0.0.3"].liveness | Should -Be "open"
    }

    It "Preserves the command-list output flag" {
        $state = @{ hosts = @{ "t1" = @{ output_flag = "-oG"; status = "pending" } }; completed = 0; failed = 0; pending = 0 }
        Update-HostState -State $state -TargetHost "t1" -Status "completed"
        $state.hosts["t1"].output_flag | Should -Be "-oG"
    }

    It "Ignores liveness in the flat mode the tests use, without throwing" {
        $flat = @{}
        { Update-HostState -State $flat -Host "10.0.0.4" -NewState "completed" -Liveness "open" } | Should -Not -Throw
        $flat["10.0.0.4"] | Should -Be "completed"
    }

    It "Round-trips the verdict through save and load" {
        $stateFile = Join-Path $TestDrive "liveness-state.json"
        $state = @{ hosts = @{}; completed = 0; failed = 0; pending = 0 }
        Update-HostState -State $state -TargetHost "10.0.0.5" -Status "completed" -ScanFile "/tmp/c.nmap" `
                         -Liveness "unreachable" -LivenessReason "host-unreach" -OpenPortCount 0
        Save-StateFile -StateFile $stateFile -State $state

        $loaded = Load-StateFile -StateFile $stateFile
        $loaded.hosts."10.0.0.5".liveness | Should -Be "unreachable"
        $loaded.hosts."10.0.0.5".liveness_reason | Should -Be "host-unreach"
        $loaded.hosts."10.0.0.5".open_port_count | Should -Be 0
    }

    It "Reads a state file written before liveness existed without throwing" {
        $stateFile = Join-Path $TestDrive "legacy-state.json"
        @{
            hosts = @{ "10.0.0.6" = @{ status = "completed"; attempts = 1; scan_file = "/tmp/gone.nmap" } }
            completed = 1; failed = 0; pending = 0
        } | ConvertTo-Json -Depth 10 | Set-Content $stateFile

        $loaded = Load-StateFile -StateFile $stateFile
        { Get-PersistedLiveness -HostState $loaded.hosts."10.0.0.6" } | Should -Not -Throw
        # No verdict and no readable output: still eligible for a retry, as before.
        Test-HostNeedsRescan -HostState $loaded.hosts."10.0.0.6" -Mode 'NoResponse' | Should -BeTrue
    }
}
