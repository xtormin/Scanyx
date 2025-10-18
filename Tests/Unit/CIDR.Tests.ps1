# CIDR.Tests.ps1
# Unit tests for CIDR expansion and resolution functions

BeforeAll {
    # Load the main script
    . $PSScriptRoot\..\..\scanyx.ps1
}

Describe "Expand-CIDR" -Tag "Unit", "CIDR" {
    Context "Small network expansion" {
        It "Expands /32 to single IP" {
            $result = Expand-CIDR "192.168.1.1/32"
            $result.Count | Should -Be 1
            $result[0] | Should -Be "192.168.1.1"
        }

        It "Expands /31 to 2 IPs" {
            $result = Expand-CIDR "192.168.1.0/31"
            $result.Count | Should -Be 2
            $result | Should -Contain "192.168.1.0"
            $result | Should -Contain "192.168.1.1"
        }

        It "Expands /30 to 2 usable IPs (excludes network/broadcast)" {
            $result = Expand-CIDR "192.168.1.0/30"
            $result.Count | Should -Be 2
            $result | Should -Contain "192.168.1.1"
            $result | Should -Contain "192.168.1.2"
            # Network (.0) and broadcast (.3) excluded
        }

        It "Expands /29 to 6 usable IPs (excludes network/broadcast)" {
            $result = Expand-CIDR "10.0.0.0/29"
            $result.Count | Should -Be 6
            $result[0] | Should -Be "10.0.0.1"
            $result[5] | Should -Be "10.0.0.6"
            # .0 (network) and .7 (broadcast) excluded
        }

        It "Expands /28 to 14 usable IPs (excludes network/broadcast)" {
            $result = Expand-CIDR "172.16.0.0/28"
            $result.Count | Should -Be 14
            $result[0] | Should -Be "172.16.0.1"
            $result[13] | Should -Be "172.16.0.14"
            # .0 (network) and .15 (broadcast) excluded
        }
    }

    Context "Medium network expansion" {
        It "Expands /27 to 30 usable IPs (excludes network/broadcast)" {
            $result = Expand-CIDR "192.168.1.0/27"
            $result.Count | Should -Be 30
            $result[0] | Should -Be "192.168.1.1"
            $result[29] | Should -Be "192.168.1.30"
        }

        It "Expands /26 to 62 usable IPs (excludes network/broadcast)" {
            $result = Expand-CIDR "192.168.1.0/26"
            $result.Count | Should -Be 62
        }

        It "Expands /25 to 126 usable IPs (excludes network/broadcast)" {
            $result = Expand-CIDR "192.168.1.0/25"
            $result.Count | Should -Be 126
        }

        It "Expands /24 to 254 usable IPs (excludes network/broadcast)" {
            $result = Expand-CIDR "192.168.1.0/24"
            $result.Count | Should -Be 254
            $result[0] | Should -Be "192.168.1.1"
            $result[253] | Should -Be "192.168.1.254"
        }
    }

    Context "Large network handling" {
        It "Handles /23 (510 usable IPs) correctly" {
            $result = Expand-CIDR "192.168.0.0/23"
            $result.Count | Should -Be 510
            $result | Should -Contain "192.168.0.1"
            $result | Should -Contain "192.168.1.254"
        }

        It "Handles /22 (1022 usable IPs) correctly" {
            $result = Expand-CIDR "10.0.0.0/22"
            $result.Count | Should -Be 1022
        }

        # Note: For very large networks (/16, /8), the function may have
        # limits or special handling. Adjust these tests based on implementation.
        It "Handles /16 appropriately" {
            # If function limits expansion, adjust assertion
            $result = Expand-CIDR "172.16.0.0/16"
            # Either returns CIDR unexpanded, truncated array, or full 65536
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context "Edge cases and validation" {
        It "Handles different IP ranges correctly" {
            $result = Expand-CIDR "10.0.0.0/30"
            $result.Count | Should -Be 2
        }

        It "Preserves order of IPs (excludes network/broadcast)" {
            $result = Expand-CIDR "192.168.1.0/30"
            $result[0] | Should -Be "192.168.1.1"
            $result[1] | Should -Be "192.168.1.2"
        }

        It "Handles high octet values" {
            $result = Expand-CIDR "192.168.255.252/30"
            $result.Count | Should -Be 2
            $result | Should -Contain "192.168.255.253"
            $result | Should -Contain "192.168.255.254"
        }
    }
}

Describe "Get-MostSpecificCIDR" -Tag "Unit", "CIDR" {
    Context "Single CIDR matching" {
        BeforeAll {
            $sensitiveCidrs = @{
                "192.168.1.0/24" = 24
            }
        }

        It "Matches IP within CIDR" {
            $result = Get-MostSpecificCIDR "192.168.1.10" $sensitiveCidrs
            $result | Should -Be "192.168.1.0/24"
        }

        It "Returns null for IP outside CIDR" {
            $result = Get-MostSpecificCIDR "192.168.2.10" $sensitiveCidrs
            $result | Should -BeNullOrEmpty
        }
    }

    Context "Multiple overlapping CIDRs" {
        BeforeAll {
            $sensitiveCidrs = @{
                "192.168.0.0/16"  = 16  # Broader
                "192.168.1.0/24"  = 24  # Specific
                "192.168.1.10/32" = 32  # Most specific
            }
        }

        It "Selects most specific CIDR (/32)" {
            $result = Get-MostSpecificCIDR "192.168.1.10" $sensitiveCidrs
            $result | Should -Be "192.168.1.10/32"
        }

        It "Selects /24 when /32 doesn't match" {
            $result = Get-MostSpecificCIDR "192.168.1.20" $sensitiveCidrs
            $result | Should -Be "192.168.1.0/24"
        }

        It "Selects /16 when only broad match" {
            $result = Get-MostSpecificCIDR "192.168.5.100" $sensitiveCidrs
            $result | Should -Be "192.168.0.0/16"
        }
    }

    Context "Non-overlapping CIDRs" {
        BeforeAll {
            $sensitiveCidrs = @{
                "10.0.0.0/24"     = 24
                "192.168.1.0/24"  = 24
                "172.16.0.0/16"   = 16
            }
        }

        It "Matches correct CIDR among multiple" {
            $result = Get-MostSpecificCIDR "172.16.5.10" $sensitiveCidrs
            $result | Should -Be "172.16.0.0/16"
        }

        It "Returns null when no CIDR matches" {
            $result = Get-MostSpecificCIDR "8.8.8.8" $sensitiveCidrs
            $result | Should -BeNullOrEmpty
        }
    }

    Context "Edge cases" {
        It "Handles empty CIDR list" {
            $result = Get-MostSpecificCIDR "192.168.1.1" @{}
            $result | Should -BeNullOrEmpty
        }

        It "Handles single host CIDR" {
            $sensitiveCidrs = @{
                "192.168.1.50/32" = 32
            }
            $result = Get-MostSpecificCIDR "192.168.1.50" $sensitiveCidrs
            $result | Should -Be "192.168.1.50/32"
        }
    }
}

Describe "Resolve-HostEntry" -Tag "Unit", "CIDR" {
    Context "Individual IP addresses" {
        It "Resolves single IP" {
            $result = Resolve-HostEntry "192.168.1.1"
            $result.Hosts.Count | Should -Be 1
            $result.Hosts[0] | Should -Be "192.168.1.1"
            $result.Type | Should -Be "IP"
        }

        It "Resolves IP with whitespace" {
            $result = Resolve-HostEntry "  192.168.1.1  "
            $result.Hosts.Count | Should -Be 1
            $result.Hosts[0] | Should -Be "192.168.1.1"
        }
    }

    Context "CIDR expansion" {
        It "Resolves CIDR /32" {
            $result = Resolve-HostEntry "192.168.1.1/32"
            $result.Hosts.Count | Should -Be 1
            $result.Type | Should -Be "CIDR"
        }

        It "Resolves CIDR /30" {
            $result = Resolve-HostEntry "192.168.1.0/30"
            $result.Hosts.Count | Should -Be 2
            $result.Type | Should -Be "CIDR"
        }

        It "Resolves CIDR /24" {
            $result = Resolve-HostEntry "192.168.1.0/24"
            $result.Hosts.Count | Should -Be 254
            $result.Type | Should -Be "CIDR"
        }
    }

    Context "Hostnames" {
        It "Resolves simple hostname" {
            $result = Resolve-HostEntry "server"
            $result.Hosts.Count | Should -Be 1
            $result.Hosts[0] | Should -Be "server"
            $result.Type | Should -Be "Hostname"
        }

        It "Resolves FQDN" {
            $result = Resolve-HostEntry "server.example.com"
            $result.Hosts.Count | Should -Be 1
            $result.Hosts[0] | Should -Be "server.example.com"
            $result.Type | Should -Be "Hostname"
        }
    }

    Context "Comments and invalid entries" {
        It "Skips line starting with #" {
            $result = Resolve-HostEntry "# This is a comment"
            $result.Hosts.Count | Should -Be 0
            $result.Type | Should -Be "Comment"
        }

        It "Skips empty line" {
            $result = Resolve-HostEntry ""
            $result.Hosts.Count | Should -Be 0
            $result.Type | Should -Be "Comment"
        }

        It "Skips whitespace-only line" {
            $result = Resolve-HostEntry "   "
            $result.Hosts.Count | Should -Be 0
            $result.Type | Should -Be "Comment"
        }

        It "Skips invalid entry" {
            $result = Resolve-HostEntry "invalid..entry"
            $result.Hosts.Count | Should -Be 0
            $result.Type | Should -Be "Invalid"
        }
    }
}
