# Results.Tests.ps1
# Unit tests for Nmap result analysis functions

BeforeAll {
    # Load the main script
    . $PSScriptRoot\..\..\scanyx.ps1
}

Describe "Test-HostHasOpenPorts" -Tag "Unit", "Results" {
    Context "XML with open ports" {
        BeforeEach {
            $xmlWithOpenPorts = @"
<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.1.1"/>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http"/>
            </port>
            <port protocol="tcp" portid="443">
                <state state="open"/>
                <service name="https"/>
            </port>
        </ports>
    </host>
</nmaprun>
"@
            $testXmlFile = Join-Path $TestDrive "open-ports.xml"
            $xmlWithOpenPorts | Out-File $testXmlFile
        }

        It "Detects open ports correctly" {
            $result = Test-HostHasOpenPorts -XmlFile $testXmlFile
            $result | Should -Be $true
        }
    }

    Context "XML with closed/filtered ports only" {
        BeforeEach {
            $xmlWithClosedPorts = @"
<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.1.2"/>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="closed"/>
            </port>
            <port protocol="tcp" portid="443">
                <state state="filtered"/>
            </port>
        </ports>
    </host>
</nmaprun>
"@
            $testXmlFile = Join-Path $TestDrive "closed-ports.xml"
            $xmlWithClosedPorts | Out-File $testXmlFile
        }

        It "Returns false for closed/filtered ports" {
            $result = Test-HostHasOpenPorts -XmlFile $testXmlFile
            $result | Should -Be $false
        }
    }

    Context "XML with host down" {
        BeforeEach {
            $xmlHostDown = @"
<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="down"/>
        <address addr="192.168.1.3"/>
    </host>
</nmaprun>
"@
            $testXmlFile = Join-Path $TestDrive "host-down.xml"
            $xmlHostDown | Out-File $testXmlFile
        }

        It "Returns false for host down" {
            $result = Test-HostHasOpenPorts -XmlFile $testXmlFile
            $result | Should -Be $false
        }
    }

    Context "XML with no ports section" {
        BeforeEach {
            $xmlNoPorts = @"
<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.1.4"/>
    </host>
</nmaprun>
"@
            $testXmlFile = Join-Path $TestDrive "no-ports.xml"
            $xmlNoPorts | Out-File $testXmlFile
        }

        It "Returns false when no ports scanned" {
            $result = Test-HostHasOpenPorts -XmlFile $testXmlFile
            $result | Should -Be $false
        }
    }

    Context "XML with mixed port states" {
        BeforeEach {
            $xmlMixedPorts = @"
<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.1.5"/>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open"/>
            </port>
            <port protocol="tcp" portid="23">
                <state state="closed"/>
            </port>
            <port protocol="tcp" portid="80">
                <state state="filtered"/>
            </port>
        </ports>
    </host>
</nmaprun>
"@
            $testXmlFile = Join-Path $TestDrive "mixed-ports.xml"
            $xmlMixedPorts | Out-File $testXmlFile
        }

        It "Returns true if at least one port is open" {
            $result = Test-HostHasOpenPorts -XmlFile $testXmlFile
            $result | Should -Be $true
        }
    }

    Context "Invalid or corrupted XML" {
        It "Handles non-existing file gracefully" {
            $nonExistingFile = Join-Path $TestDrive "non-existing.xml"
            $result = Test-HostHasOpenPorts -XmlFile $nonExistingFile
            $result | Should -Be $false
        }

        It "Handles corrupted XML gracefully" {
            $corruptedXml = "This is not XML <invalid>"
            $testXmlFile = Join-Path $TestDrive "corrupted.xml"
            $corruptedXml | Out-File $testXmlFile

            { $result = Test-HostHasOpenPorts -XmlFile $testXmlFile } | Should -Not -Throw
        }

        It "Handles empty file" {
            $testXmlFile = Join-Path $TestDrive "empty.xml"
            "" | Out-File $testXmlFile

            { $result = Test-HostHasOpenPorts -XmlFile $testXmlFile } | Should -Not -Throw
        }
    }

    Context "Multiple hosts in single XML" {
        BeforeEach {
            $xmlMultipleHosts = @"
<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.1.10"/>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="open"/>
            </port>
        </ports>
    </host>
    <host>
        <status state="down"/>
        <address addr="192.168.1.11"/>
    </host>
</nmaprun>
"@
            $testXmlFile = Join-Path $TestDrive "multiple-hosts.xml"
            $xmlMultipleHosts | Out-File $testXmlFile
        }

        It "Detects open ports in multi-host XML" {
            $result = Test-HostHasOpenPorts -XmlFile $testXmlFile
            $result | Should -Be $true
        }
    }

    Context "UDP ports" {
        BeforeEach {
            $xmlUdpPorts = @"
<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.1.20"/>
        <ports>
            <port protocol="udp" portid="53">
                <state state="open"/>
                <service name="domain"/>
            </port>
        </ports>
    </host>
</nmaprun>
"@
            $testXmlFile = Join-Path $TestDrive "udp-ports.xml"
            $xmlUdpPorts | Out-File $testXmlFile
        }

        It "Detects open UDP ports" {
            $result = Test-HostHasOpenPorts -XmlFile $testXmlFile
            $result | Should -Be $true
        }
    }
}

Describe "Build-SensitiveScanCommand" -Tag "Unit", "Results" {
    Context "Basic command building" {
        It "Builds basic command with default timing" {
            $result = Build-SensitiveScanCommand `
                -TargetHost "192.168.1.1" `
                -Arguments "-p 80,443" `
                -OutputFile "test.xml" `
                -IsSensitive $false `
                -SensitiveTiming "T4" `
                -SensitiveScripts "default"

            $result | Should -Match "nmap"
            $result | Should -Match "192\.168\.1\.1"
            $result | Should -Match "-p 80,443"
        }

        It "Applies sensitive timing when host is sensitive" {
            $result = Build-SensitiveScanCommand `
                -TargetHost "192.168.1.1" `
                -Arguments "-p 80,443 -T4" `
                -OutputFile "test.xml" `
                -IsSensitive $true `
                -SensitiveTiming "T2" `
                -SensitiveScripts "default"

            $result | Should -Match "-T2"
            $result | Should -Not -Match "-T4"
        }

        It "Adjusts scripts for sensitive hosts" {
            $result = Build-SensitiveScanCommand `
                -TargetHost "192.168.1.1" `
                -Arguments "-p 80,443 --script vuln" `
                -OutputFile "test.xml" `
                -IsSensitive $true `
                -SensitiveTiming "T2" `
                -SensitiveScripts "none"

            $result | Should -Not -Match "--script"
        }

        It "Includes output file" {
            $result = Build-SensitiveScanCommand `
                -TargetHost "192.168.1.1" `
                -Arguments "-p 80,443" `
                -OutputFile "output.xml" `
                -IsSensitive $false `
                -SensitiveTiming "T4" `
                -SensitiveScripts "default"

            $result | Should -Match "output\.xml"
        }
    }

    Context "Unprivileged mode" {
        It "Adds --unprivileged flag when specified" {
            $result = Build-SensitiveScanCommand `
                -TargetHost "192.168.1.1" `
                -Arguments "-p 80,443" `
                -OutputFile "test.xml" `
                -IsSensitive $false `
                -SensitiveTiming "T4" `
                -SensitiveScripts "default" `
                -Unprivileged $true

            $result | Should -Match "--unprivileged"
        }

        It "Replaces -sS with -sT in unprivileged mode" {
            $result = Build-SensitiveScanCommand `
                -TargetHost "192.168.1.1" `
                -Arguments "-sS -p 80,443" `
                -OutputFile "test.xml" `
                -IsSensitive $false `
                -SensitiveTiming "T4" `
                -SensitiveScripts "default" `
                -Unprivileged $true

            $result | Should -Match "-sT"
            $result | Should -Not -Match "-sS"
        }
    }
}
