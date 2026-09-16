# Results.Tests.ps1
# Unit tests for Nmap result analysis functions

BeforeAll {
    # Load the main script
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1'))
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

Describe "Scan results log" -Tag "Unit", "Results" {
    BeforeEach {
        $script:Dir = [IO.Path]::Combine([IO.Path]::GetTempPath(), "scanyx-res-$(Get-Random)")
        New-Item -Path $script:Dir -ItemType Directory -Force | Out-Null
        $script:Rf = [IO.Path]::Combine($script:Dir, "scan-results.json")
    }
    AfterEach {
        if (Test-Path $script:Dir) { Remove-Item $script:Dir -Recurse -Force }
    }

    It "Puts the append-only log beside the json" {
        $log = Get-ScanResultsLogPath -ResultsFile $script:Rf
        [IO.Path]::GetFileName($log) | Should -Be "scan-results.jsonl"
        [IO.Path]::GetDirectoryName($log) | Should -Be $script:Dir
    }

    It "Writes one line per result" {
        1..3 | ForEach-Object {
            Add-ScanResult -ResultsFile $script:Rf -ScanResult @{ host = "10.0.0.$_"; status = "completed" }
        }
        $lines = @(Get-Content (Get-ScanResultsLogPath -ResultsFile $script:Rf))
        $lines.Count | Should -Be 3
        $lines[0] | Should -Not -Match "`n"
    }

    It "Renders the json in the documented shape" {
        Add-ScanResult -ResultsFile $script:Rf -ScanResult @{ host = "10.0.0.1"; status = "completed"; attempts = 1 }
        Export-ScanResults -ResultsFile $script:Rf -SessionId "s1"

        $j = Get-Content $script:Rf -Raw | ConvertFrom-Json
        $j.scan_session | Should -Be "s1"
        $j.scans.Count | Should -Be 1
        $j.scans[0].host | Should -Be "10.0.0.1"
    }

    It "Keeps an error message that spans several lines on one line" {
        Add-ScanResult -ResultsFile $script:Rf -ScanResult @{ host = "10.0.0.1"; error = "first`nsecond`nthird" }
        @(Get-Content (Get-ScanResultsLogPath -ResultsFile $script:Rf)).Count | Should -Be 1

        Export-ScanResults -ResultsFile $script:Rf -SessionId "s1"
        $j = Get-Content $script:Rf -Raw | ConvertFrom-Json
        $j.scans[0].error | Should -Be "first`nsecond`nthird"
    }

    It "Recovers the intact records when a run died mid-append" {
        1..2 | ForEach-Object {
            Add-ScanResult -ResultsFile $script:Rf -ScanResult @{ host = "10.0.0.$_"; status = "completed" }
        }
        $log = Get-ScanResultsLogPath -ResultsFile $script:Rf
        Add-Content -Path $log -Value '{"host":"10.0.0.3","stat' -NoNewline

        Export-ScanResults -ResultsFile $script:Rf -SessionId "s1" -WarningAction SilentlyContinue
        $j = Get-Content $script:Rf -Raw | ConvertFrom-Json
        $j.scans.Count | Should -Be 2
    }

    It "Does not let a truncated line swallow the next result" {
        Add-ScanResult -ResultsFile $script:Rf -ScanResult @{ host = "10.0.0.1"; status = "completed" }
        $log = Get-ScanResultsLogPath -ResultsFile $script:Rf
        Add-Content -Path $log -Value '{"host":"10.0.0.2","stat' -NoNewline

        Add-ScanResult -ResultsFile $script:Rf -ScanResult @{ host = "10.0.0.3"; status = "completed" }
        Export-ScanResults -ResultsFile $script:Rf -SessionId "s1" -WarningAction SilentlyContinue

        $j = Get-Content $script:Rf -Raw | ConvertFrom-Json
        $hosts = @($j.scans | ForEach-Object { $_.host })
        $hosts | Should -Contain "10.0.0.3"
        $j.scans.Count | Should -Be 2
    }

    It "Accumulates across runs, as a resumed session does" {
        Add-ScanResult -ResultsFile $script:Rf -ScanResult @{ host = "10.0.0.1"; status = "completed" }
        Export-ScanResults -ResultsFile $script:Rf -SessionId "s1"
        Add-ScanResult -ResultsFile $script:Rf -ScanResult @{ host = "10.0.0.2"; status = "completed" }
        Export-ScanResults -ResultsFile $script:Rf -SessionId "s1"

        $j = Get-Content $script:Rf -Raw | ConvertFrom-Json
        $j.scans.Count | Should -Be 2
    }

    It "Renders the json as it goes, so a hard kill does not lose everything" {
        # A kill -9 fires no exit handler, so the artifact cannot only be
        # written at the end of the run.
        Add-ScanResult -ResultsFile $script:Rf -ScanResult @{ host = "10.0.0.1"; status = "completed" }
        (Get-Content $script:Rf -Raw | ConvertFrom-Json).scans.Count | Should -Be 1
    }

    It "Does not re-render the json for every single result" {
        # Rendering per result is what made the old implementation quadratic
        Add-ScanResult -ResultsFile $script:Rf -ScanResult @{ host = "10.0.0.1"; status = "completed" }
        Add-ScanResult -ResultsFile $script:Rf -ScanResult @{ host = "10.0.0.2"; status = "completed" }

        $log = Get-ScanResultsLogPath -ResultsFile $script:Rf
        @(Get-Content $log).Count | Should -Be 2
        (Get-Content $script:Rf -Raw | ConvertFrom-Json).scans.Count | Should -Be 1

        # ...but it catches up once the throttle window has passed
        $script:lastResultsExport[$log] = (Get-Date).AddSeconds(-31)
        Add-ScanResult -ResultsFile $script:Rf -ScanResult @{ host = "10.0.0.3"; status = "completed" }
        (Get-Content $script:Rf -Raw | ConvertFrom-Json).scans.Count | Should -Be 3
    }

    It "Keeps the session id when re-rendering without being given one" {
        @{ scan_session = "mi-sesion"; scans = @() } | ConvertTo-Json | Set-Content $script:Rf
        Add-ScanResult -ResultsFile $script:Rf -ScanResult @{ host = "10.0.0.1"; status = "completed" }
        Export-ScanResults -ResultsFile $script:Rf
        (Get-Content $script:Rf -Raw | ConvertFrom-Json).scan_session | Should -Be "mi-sesion"
    }

    It "Writes nothing and does not throw when there is no log yet" {
        { Export-ScanResults -ResultsFile $script:Rf -SessionId "s1" } | Should -Not -Throw
        Test-Path $script:Rf | Should -BeFalse
    }

    It "Scales linearly rather than quadratically" {
        # The old implementation re-read and rewrote the whole document per
        # result. Tripling the count should not multiply the work by ~9.
        $measure = {
            param($n)
            $d = [IO.Path]::Combine([IO.Path]::GetTempPath(), "scanyx-perf-$(Get-Random)")
            New-Item -Path $d -ItemType Directory -Force | Out-Null
            $f = [IO.Path]::Combine($d, "scan-results.json")
            $sw = [Diagnostics.Stopwatch]::StartNew()
            for ($i = 1; $i -le $n; $i++) {
                Add-ScanResult -ResultsFile $f -ScanResult @{ host = "10.0.0.$i"; status = "completed"; attempts = 1 }
            }
            $sw.Stop()
            Remove-Item $d -Recurse -Force
            return $sw.Elapsed.TotalMilliseconds
        }

        $small = & $measure 60
        $large = & $measure 180
        # Generous bound: this only has to catch a return to quadratic growth,
        # and it must not go red because the machine was busy.
        $large | Should -BeLessThan ([math]::Max($small, 1) * 6)
    }
}
