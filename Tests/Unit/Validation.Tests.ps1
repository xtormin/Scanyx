# Validation.Tests.ps1
# Unit tests for validation functions in SCANYX

BeforeAll {
    # Load the main script
    . $PSScriptRoot\..\..\scanyx.ps1
}

Describe "Test-ValidIPOrHost" -Tag "Unit", "Validation" {
    Context "Valid IPv4 addresses" {
        It "Validates standard IP address" {
            Test-ValidIPOrHost "192.168.1.1" | Should -Be $true
        }

        It "Validates IP with zeros" {
            Test-ValidIPOrHost "10.0.0.1" | Should -Be $true
        }

        It "Validates edge case 0.0.0.0" {
            Test-ValidIPOrHost "0.0.0.0" | Should -Be $true
        }

        It "Validates edge case 255.255.255.255" {
            Test-ValidIPOrHost "255.255.255.255" | Should -Be $true
        }
    }

    Context "Invalid IPv4 addresses" {
        It "Rejects IP with octets > 255" {
            Test-ValidIPOrHost "256.1.1.1" | Should -Be $false
        }

        It "Rejects IP with negative numbers" {
            Test-ValidIPOrHost "-1.1.1.1" | Should -Be $false
        }

        It "Rejects IP with too many octets" {
            Test-ValidIPOrHost "192.168.1.1.1" | Should -Be $false
        }

        It "Rejects IP with too few octets" {
            Test-ValidIPOrHost "192.168.1" | Should -Be $false
        }

        It "Rejects IP with letters" {
            Test-ValidIPOrHost "192.168.1.a" | Should -Be $false
        }
    }

    Context "Valid hostnames" {
        It "Validates simple hostname" {
            Test-ValidIPOrHost "server" | Should -Be $true
        }

        It "Validates FQDN" {
            Test-ValidIPOrHost "server.example.com" | Should -Be $true
        }

        It "Validates hostname with hyphens" {
            Test-ValidIPOrHost "web-server.example.com" | Should -Be $true
        }

        It "Validates subdomain" {
            Test-ValidIPOrHost "api.v2.example.com" | Should -Be $true
        }
    }

    Context "Invalid hostnames" {
        It "Rejects hostname starting with hyphen" {
            Test-ValidIPOrHost "-server.com" | Should -Be $false
        }

        It "Rejects hostname ending with hyphen" {
            Test-ValidIPOrHost "server-.com" | Should -Be $false
        }

        It "Rejects hostname with consecutive dots" {
            Test-ValidIPOrHost "server..com" | Should -Be $false
        }

        It "Rejects empty string" {
            Test-ValidIPOrHost "" | Should -Be $false
        }

        It "Rejects whitespace only" {
            Test-ValidIPOrHost "   " | Should -Be $false
        }
    }
}

Describe "Test-ValidCIDR" -Tag "Unit", "Validation" {
    Context "Valid CIDR notations" {
        It "Validates /32 (single host)" {
            Test-ValidCIDR "192.168.1.1/32" | Should -Be $true
        }

        It "Validates /24 (class C)" {
            Test-ValidCIDR "192.168.1.0/24" | Should -Be $true
        }

        It "Validates /16 (class B)" {
            Test-ValidCIDR "172.16.0.0/16" | Should -Be $true
        }

        It "Validates /8 (class A)" {
            Test-ValidCIDR "10.0.0.0/8" | Should -Be $true
        }

        It "Validates /0 (entire internet)" {
            Test-ValidCIDR "0.0.0.0/0" | Should -Be $true
        }

        It "Validates /30 (4 hosts)" {
            Test-ValidCIDR "192.168.1.0/30" | Should -Be $true
        }
    }

    Context "Invalid CIDR notations" {
        It "Rejects CIDR with mask > 32" {
            Test-ValidCIDR "192.168.1.0/33" | Should -Be $false
        }

        It "Rejects CIDR with negative mask" {
            Test-ValidCIDR "192.168.1.0/-1" | Should -Be $false
        }

        It "Rejects CIDR with invalid IP" {
            Test-ValidCIDR "256.1.1.1/24" | Should -Be $false
        }

        It "Rejects CIDR without mask" {
            Test-ValidCIDR "192.168.1.0/" | Should -Be $false
        }

        It "Rejects CIDR with wrong separator" {
            Test-ValidCIDR "192.168.1.0:24" | Should -Be $false
        }

        It "Rejects IP without CIDR notation" {
            Test-ValidCIDR "192.168.1.1" | Should -Be $false
        }
    }
}

Describe "Test-SessionName" -Tag "Unit", "Validation" {
    Context "Valid session names" {
        It "Validates simple name" {
            Test-SessionName "mysession" | Should -Be $true
        }

        It "Validates name with hyphens" {
            Test-SessionName "my-session-2025" | Should -Be $true
        }

        It "Validates name with underscores" {
            Test-SessionName "my_session_test" | Should -Be $true
        }

        It "Validates name with numbers" {
            Test-SessionName "session123" | Should -Be $true
        }

        It "Validates mixed alphanumeric" {
            Test-SessionName "Pentest-Phase1_2025" | Should -Be $true
        }
    }

    Context "Invalid session names" {
        It "Rejects name with spaces" {
            Test-SessionName "my session" | Should -Be $false
        }

        It "Rejects name with special chars" {
            Test-SessionName "session@2025" | Should -Be $false
        }

        It "Rejects name starting with number" {
            Test-SessionName "123session" | Should -Be $false
        }

        It "Rejects empty name" {
            Test-SessionName "" | Should -Be $false
        }

        It "Rejects name with dots" {
            Test-SessionName "my.session" | Should -Be $false
        }
    }
}
