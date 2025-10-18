# Configuration.Tests.ps1
# Integration tests for configuration loading and management

BeforeAll {
    # Load the main script and mocks
    . $PSScriptRoot\..\..\scanyx.ps1
    . $PSScriptRoot\..\Mocks\Nmap.Mock.ps1
}

Describe "Load-ScanConfiguration" -Tag "Integration", "Configuration" {
    Context "Loading valid configuration" {
        BeforeEach {
            $testConfigPath = Join-Path $TestDrive "valid-config.json"
            New-MockScanProfiles -Path $testConfigPath
        }

        It "Loads configuration successfully" {
            $config = Load-ScanConfiguration -ConfigFile $testConfigPath
            $config | Should -Not -BeNullOrEmpty
        }

        It "Loads profiles section" {
            $config = Load-ScanConfiguration -ConfigFile $testConfigPath
            $config.profiles | Should -Not -BeNullOrEmpty
        }

        It "Loads workflows section" {
            $config = Load-ScanConfiguration -ConfigFile $testConfigPath
            $config.workflows | Should -Not -BeNullOrEmpty
        }

        It "Profiles have expected structure" {
            $config = Load-ScanConfiguration -ConfigFile $testConfigPath
            $config.profiles.PSObject.Properties.Count | Should -BeGreaterThan 0

            foreach ($profile in $config.profiles.PSObject.Properties) {
                $profile.Value.name | Should -Not -BeNullOrEmpty
                $profile.Value.args | Should -Not -BeNullOrEmpty
            }
        }

        It "Workflows have expected structure" {
            $config = Load-ScanConfiguration -ConfigFile $testConfigPath
            $config.workflows.PSObject.Properties.Count | Should -BeGreaterThan 0

            foreach ($workflow in $config.workflows.PSObject.Properties) {
                $workflow.Value.name | Should -Not -BeNullOrEmpty
                $workflow.Value.steps | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context "Creating default configuration" {
        It "Creates config file when it doesn't exist" {
            $newConfigPath = Join-Path $TestDrive "new-config.json"

            $config = Load-ScanConfiguration -ConfigFile $newConfigPath
            Test-Path $newConfigPath | Should -Be $true
        }

        It "Default config has tcp profiles" {
            $newConfigPath = Join-Path $TestDrive "default-config.json"
            $config = Load-ScanConfiguration -ConfigFile $newConfigPath

            $config.profiles.PSObject.Properties.Name | Should -Contain "tcp-1000"
        }

        It "Default config has udp profiles" {
            $newConfigPath = Join-Path $TestDrive "default-udp-config.json"
            $config = Load-ScanConfiguration -ConfigFile $newConfigPath

            $config.profiles.PSObject.Properties.Name | Should -Contain "udp-common"
        }

        It "Default config has workflows" {
            $newConfigPath = Join-Path $TestDrive "default-workflow-config.json"
            $config = Load-ScanConfiguration -ConfigFile $newConfigPath

            $config.workflows | Should -Not -BeNullOrEmpty
        }
    }

    Context "Handling invalid configuration" {
        It "Handles corrupted JSON gracefully" {
            $corruptedPath = Join-Path $TestDrive "corrupted.json"
            "{ invalid json }" | Out-File $corruptedPath

            # Should not throw, should fall back to defaults
            { $config = Load-ScanConfiguration -ConfigFile $corruptedPath } | Should -Not -Throw
        }

        It "Handles empty file" {
            $emptyPath = Join-Path $TestDrive "empty.json"
            "" | Out-File $emptyPath

            { $config = Load-ScanConfiguration -ConfigFile $emptyPath } | Should -Not -Throw
        }

        It "Handles missing profiles section" {
            $noProfilesPath = Join-Path $TestDrive "no-profiles.json"
            @{ workflows = @{} } | ConvertTo-Json | Out-File $noProfilesPath

            $config = Load-ScanConfiguration -ConfigFile $noProfilesPath
            # Should create default profiles or handle gracefully
            $config | Should -Not -BeNullOrEmpty
        }
    }

    Context "Custom profiles" {
        BeforeEach {
            $customConfigPath = Join-Path $TestDrive "custom-config.json"
            $customConfig = @{
                profiles = @{
                    "my-custom-scan" = @{
                        name = "My Custom Scan"
                        description = "Custom scan profile"
                        args = "-sT -p 1-100 -T3 --script banner"
                    }
                }
                workflows = @{}
            }
            $customConfig | ConvertTo-Json -Depth 10 | Out-File $customConfigPath
        }

        It "Loads custom profile" {
            $config = Load-ScanConfiguration -ConfigFile $customConfigPath
            $config.profiles."my-custom-scan" | Should -Not -BeNullOrEmpty
        }

        It "Custom profile has correct properties" {
            $config = Load-ScanConfiguration -ConfigFile $customConfigPath
            $profile = $config.profiles."my-custom-scan"

            $profile.name | Should -Be "My Custom Scan"
            $profile.args | Should -Match "-sT"
            $profile.args | Should -Match "--script banner"
        }
    }

    Context "Workflow validation" {
        BeforeEach {
            $workflowConfigPath = Join-Path $TestDrive "workflow-config.json"
            $workflowConfig = @{
                profiles = @{
                    "step1" = @{ name = "Step 1"; args = "-p 80" }
                    "step2" = @{ name = "Step 2"; args = "-p 443" }
                }
                workflows = @{
                    "multi-step" = @{
                        name = "Multi Step Workflow"
                        description = "Test multi-step workflow"
                        steps = @(
                            @{ profile = "step1"; condition = "always" }
                            @{ profile = "step2"; condition = "previous_success" }
                        )
                    }
                }
            }
            $workflowConfig | ConvertTo-Json -Depth 10 | Out-File $workflowConfigPath
        }

        It "Loads workflow with multiple steps" {
            $config = Load-ScanConfiguration -ConfigFile $workflowConfigPath
            $workflow = $config.workflows."multi-step"

            $workflow.steps.Count | Should -Be 2
        }

        It "Workflow steps reference valid profiles" {
            $config = Load-ScanConfiguration -ConfigFile $workflowConfigPath
            $workflow = $config.workflows."multi-step"

            foreach ($step in $workflow.steps) {
                $config.profiles.PSObject.Properties.Name | Should -Contain $step.profile
            }
        }

        It "Workflow steps have valid conditions" {
            $config = Load-ScanConfiguration -ConfigFile $workflowConfigPath
            $workflow = $config.workflows."multi-step"

            $validConditions = @("always", "previous_success", "previous_has_results")
            foreach ($step in $workflow.steps) {
                $validConditions | Should -Contain $step.condition
            }
        }
    }
}
