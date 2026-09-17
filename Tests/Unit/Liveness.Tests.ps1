# Liveness.Tests.ps1
# Unit tests for evidence-based host liveness classification.
#
# The precedence table is exercised through Resolve-LivenessVerdict with plain
# hashtables, so each rule (and each deliberate conflict between rules) is one
# assertion rather than one XML fixture.

BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1'))
    $script:FixtureDir = [IO.Path]::Combine($PSScriptRoot, '..', 'Fixtures')
}

Describe "Resolve-LivenessVerdict" -Tag "Unit", "Liveness" {

    Context "Rule 1: an open port wins outright" {
        It "Reports open for a single open port" {
            $v = Resolve-LivenessVerdict -Facts @{ OpenCount = 1; PortElements = 1; Reasons = @{ 'syn-ack' = 1 } }
            $v.Verdict | Should -Be 'open'
        }

        It "Reports open even when a router also answered with host-unreach" {
            $v = Resolve-LivenessVerdict -Facts @{
                OpenCount = 1; PortElements = 5
                Reasons = @{ 'syn-ack' = 1; 'host-unreach' = 4 }
            }
            $v.Verdict | Should -Be 'open'
        }
    }

    Context "Rule 2: the target itself answered" {
        It "Reports alive for closed ports with no open ones" {
            $v = Resolve-LivenessVerdict -Facts @{
                OpenCount = 0; ClosedCount = 31; HasClosedPort = $true; PortElements = 31
                Reasons = @{ 'conn-refused' = 31 }
            }
            $v.Verdict | Should -Be 'alive'
        }

        It "Reports alive from the extraports summary alone" {
            # This is the shape --open used to destroy: no individual <port>
            # elements at all, only the closed-port rollup.
            $v = Resolve-LivenessVerdict -Facts @{
                OpenCount = 0; ClosedCount = 65535; HasClosedPort = $true; PortElements = 65535
                Reasons = @{ 'reset' = 65535 }
            }
            $v.Verdict | Should -Be 'alive'
        }

        It "Reports alive when only srtt shows the target answered" {
            $v = Resolve-LivenessVerdict -Facts @{
                OpenCount = 0; FilteredCount = 3; PortElements = 3
                Reasons = @{ 'no-response' = 3 }; Srtt = 1200
            }
            $v.Verdict | Should -Be 'alive'
        }

        It "Reports alive when traceroute's last hop is the target" {
            $v = Resolve-LivenessVerdict -Facts @{
                OpenCount = 0; FilteredCount = 1; PortElements = 1
                Reasons = @{ 'no-response' = 1 }; TraceLastHop = '192.168.1.60'
            } -TargetHost '192.168.1.60'
            $v.Verdict | Should -Be 'alive'
        }

        It "Does not report alive when traceroute stopped short of the target" {
            $v = Resolve-LivenessVerdict -Facts @{
                OpenCount = 0; FilteredCount = 1; PortElements = 1
                Reasons = @{ 'no-response' = 1 }; TraceLastHop = '192.168.1.1'
            } -TargetHost '192.168.1.60'
            $v.Verdict | Should -Be 'filtered'
        }

        It "Treats port-unreach as the target answering, not a router" {
            # ICMP type 3 code 3 comes from the host itself; 3/1 and 3/0 do not.
            # That split is the whole point of the classification.
            $v = Resolve-LivenessVerdict -Facts @{
                OpenCount = 0; ClosedCount = 2; HasClosedPort = $true; PortElements = 2
                Reasons = @{ 'port-unreach' = 2; 'host-unreach' = 1 }
            }
            $v.Verdict | Should -Be 'alive'
        }

        It "Ignores a -Pn user-set host status" {
            $v = Resolve-LivenessVerdict -Facts @{
                OpenCount = 0; FilteredCount = 2; PortElements = 2
                Reasons = @{ 'no-response' = 2 }; StatusReason = 'user-set'
            }
            $v.Verdict | Should -Be 'filtered'
        }

        It "Uses a real host status reason when there is one" {
            $v = Resolve-LivenessVerdict -Facts @{
                OpenCount = 0; FilteredCount = 2; PortElements = 2
                Reasons = @{ 'no-response' = 2 }; StatusReason = 'echo-reply'
            }
            $v.Verdict | Should -Be 'alive'
        }
    }

    Context "Rule 3: only a third party answered" {
        It "Reports unreachable for host-unreach" {
            $v = Resolve-LivenessVerdict -Facts @{
                OpenCount = 0; FilteredCount = 2; PortElements = 2
                Reasons = @{ 'host-unreach' = 2 }
            }
            $v.Verdict | Should -Be 'unreachable'
        }

        It "Reports unreachable for admin-prohibited and says the source is ambiguous" {
            $v = Resolve-LivenessVerdict -Facts @{
                OpenCount = 0; FilteredCount = 2; PortElements = 2
                Reasons = @{ 'admin-prohibited' = 2 }
            }
            $v.Verdict | Should -Be 'unreachable'
            $v.Evidence | Should -Match 'ambiguous'
        }
    }

    Context "Rule 4 and 5" {
        It "Reports filtered when everything went unanswered" {
            $v = Resolve-LivenessVerdict -Facts @{
                OpenCount = 0; FilteredCount = 1000; PortElements = 1000
                Reasons = @{ 'no-response' = 1000 }
            }
            $v.Verdict | Should -Be 'filtered'
        }

        It "Reports unknown when nothing was probed at all" {
            $v = Resolve-LivenessVerdict -Facts @{ OpenCount = 0; PortElements = 0; Reasons = @{} }
            $v.Verdict | Should -Be 'unknown'
        }

        It "Reports unknown for a null fact set" {
            (Resolve-LivenessVerdict -Facts $null).Verdict | Should -Be 'unknown'
        }
    }
}

Describe "Get-NormalizedNmapReason" -Tag "Unit", "Liveness" {
    It "Singularises the plural forms older nmap uses in extrareasons" {
        Get-NormalizedNmapReason 'resets'        | Should -Be 'reset'
        Get-NormalizedNmapReason 'no-responses'  | Should -Be 'no-response'
        Get-NormalizedNmapReason 'port-unreaches'| Should -Be 'port-unreach'
    }

    It "Leaves singular reasons alone" {
        Get-NormalizedNmapReason 'conn-refused'  | Should -Be 'conn-refused'
        Get-NormalizedNmapReason 'syn-ack'       | Should -Be 'syn-ack'
        Get-NormalizedNmapReason 'arp-response'  | Should -Be 'arp-response'
        Get-NormalizedNmapReason 'user-set'      | Should -Be 'user-set'
    }

    It "Handles empty input" {
        Get-NormalizedNmapReason ''  | Should -Be ''
        Get-NormalizedNmapReason $null | Should -Be ''
    }
}

Describe "Get-NmapXmlPath" -Tag "Unit", "Liveness" {
    BeforeAll {
        $script:base = Join-Path $TestDrive "scan"
        "<nmaprun></nmaprun>" | Out-File "$script:base.xml"
        "text"                | Out-File "$script:base.nmap"
    }

    It "Finds the .xml sibling of a .nmap file" {
        Get-NmapXmlPath -ResultFile "$script:base.nmap" | Should -Be "$script:base.xml"
    }

    It "Finds the .xml sibling of a .gnmap file" {
        Get-NmapXmlPath -ResultFile "$script:base.gnmap" | Should -Be "$script:base.xml"
    }

    It "Returns an .xml file unchanged" {
        Get-NmapXmlPath -ResultFile "$script:base.xml" | Should -Be "$script:base.xml"
    }

    It "Returns the file itself for an -oX command-list line" {
        Get-NmapXmlPath -ResultFile "$script:base.xml" -OutputFlag '-oX' | Should -Be "$script:base.xml"
    }

    It "Returns nothing for output flags that write no XML" {
        Get-NmapXmlPath -ResultFile "$script:base.nmap" -OutputFlag '-oN' | Should -Be ""
        Get-NmapXmlPath -ResultFile "$script:base.nmap" -OutputFlag '-oG' | Should -Be ""
    }

    It "Returns nothing when the sibling does not exist" {
        Get-NmapXmlPath -ResultFile (Join-Path $TestDrive "missing.nmap") | Should -Be ""
    }

    It "Returns nothing for empty input" {
        Get-NmapXmlPath -ResultFile "" | Should -Be ""
    }
}

Describe "Get-HostLivenessVerdict against real nmap output" -Tag "Unit", "Liveness" {
    It "Classifies <_> as <expected> from <source>" -ForEach @(
        @{ File = 'nmap-open-extraports.xml';      Expected = 'open';        Source = 'xml' }
        @{ File = 'nmap-all-closed.xml';           Expected = 'alive';       Source = 'xml' }
        @{ File = 'nmap-no-response.xml';          Expected = 'filtered';    Source = 'xml' }
        @{ File = 'nmap-udp-openfiltered.xml';     Expected = 'filtered';    Source = 'xml' }
        @{ File = 'nmap-host-unreach.xml';         Expected = 'unreachable'; Source = 'xml' }
        @{ File = 'nmap-udp-port-unreach.xml';     Expected = 'alive';       Source = 'xml' }
        @{ File = 'nmap-trace.xml';                Expected = 'alive';       Source = 'xml' }
        @{ File = 'sample-nmap-output.xml';        Expected = 'open';        Source = 'xml' }
        @{ File = 'nmap-truncated-after-host.xml'; Expected = 'open';        Source = 'xml-repaired' }
        @{ File = 'nmap-truncated-mid-host.xml';   Expected = 'unknown';     Source = 'text' }
        @{ File = 'nmap-all-closed-text.nmap';     Expected = 'alive';       Source = 'text' }
        @{ File = 'sample-nmap-open-text.nmap';    Expected = 'open';        Source = 'text' }
        @{ File = 'sample-nmap-output-nolatency.nmap'; Expected = 'filtered'; Source = 'text' }
        @{ File = 'sample-udp-openfiltered.nmap';  Expected = 'filtered';    Source = 'text' }
    ) {
        $v = Get-HostLivenessVerdict -ResultFile (Join-Path $script:FixtureDir $File)
        $v.Verdict | Should -Be $Expected
        $v.Source  | Should -Be $Source
    }

    It "Never throws on a missing file" {
        { Get-HostLivenessVerdict -ResultFile (Join-Path $TestDrive "nope.nmap") } | Should -Not -Throw
        (Get-HostLivenessVerdict -ResultFile (Join-Path $TestDrive "nope.nmap")).Verdict | Should -Be 'unknown'
    }

    It "Never throws on empty input" {
        (Get-HostLivenessVerdict -ResultFile "").Verdict | Should -Be 'unknown'
    }
}

Describe "open|filtered is not an open port" -Tag "Unit", "Liveness" {
    # Regression: the plain-text branch used to match the bare `open` prefix of
    # "53/udp open|filtered domain", so a UDP scan of a host that answered
    # nothing at all reported it as alive with open ports.

    It "Rejects open|filtered in XML" {
        Test-HostHasOpenPorts -XmlFile (Join-Path $script:FixtureDir 'nmap-udp-openfiltered.xml') | Should -BeFalse
    }

    It "Rejects open|filtered in plain text" {
        Test-HostHasOpenPorts -XmlFile (Join-Path $script:FixtureDir 'sample-udp-openfiltered.nmap') | Should -BeFalse
    }

    It "Still accepts a genuinely open port in plain text" {
        Test-HostHasOpenPorts -XmlFile (Join-Path $script:FixtureDir 'sample-nmap-open-text.nmap') | Should -BeTrue
    }

    It "Counts open|filtered as filtered, not open" {
        $v = Get-LivenessVerdictFromText -Content "PORT    STATE         SERVICE`n53/udp  open|filtered domain`n"
        $v.OpenCount | Should -Be 0
        $v.FilteredCount | Should -Be 1
    }
}

Describe "Test-HostNeedsRescan" -Tag "Unit", "Liveness" {
    It "NoResponse retries <_> = <retry>" -ForEach @(
        @{ Verdict = 'open';        Retry = $false }
        @{ Verdict = 'alive';       Retry = $false }
        @{ Verdict = 'filtered';    Retry = $true }
        @{ Verdict = 'unreachable'; Retry = $true }
        @{ Verdict = 'unknown';     Retry = $true }
    ) {
        Test-HostNeedsRescan -HostState ([pscustomobject]@{ liveness = $Verdict }) -Mode 'NoResponse' |
            Should -Be $Retry
    }

    It "NoOpenPorts retries everything without an open port" {
        Test-HostNeedsRescan -HostState ([pscustomobject]@{ liveness = 'open' })  -Mode 'NoOpenPorts' | Should -BeFalse
        Test-HostNeedsRescan -HostState ([pscustomobject]@{ liveness = 'alive' }) -Mode 'NoOpenPorts' | Should -BeTrue
    }

    It "Rescans when the host cannot be classified at all" {
        # A missing output file used to count as dead; it still gets retried.
        Test-HostNeedsRescan -HostState ([pscustomobject]@{ status = 'completed' }) -Mode 'NoResponse' | Should -BeTrue
        Test-HostNeedsRescan -HostState $null -Mode 'NoResponse' | Should -BeTrue
    }
}

Describe "Get-PersistedLiveness" -Tag "Unit", "Liveness" {
    It "Returns the stored verdict without touching the disk" {
        Get-PersistedLiveness -HostState ([pscustomobject]@{ liveness = 'alive'; scan_file = '/nonexistent' }) |
            Should -Be 'alive'
    }

    It "Recomputes from disk for a state file written before liveness existed" {
        $state = [pscustomobject]@{
            status = 'completed'
            scan_file = (Join-Path $script:FixtureDir 'nmap-all-closed.xml')
        }
        Get-PersistedLiveness -HostState $state | Should -Be 'alive'
    }

    It "Returns empty, without throwing, for a host state with no scan file" {
        Get-PersistedLiveness -HostState ([pscustomobject]@{ status = 'pending' }) | Should -Be ""
        Get-PersistedLiveness -HostState $null | Should -Be ""
    }
}

Describe "Format-LivenessCounters" -Tag "Unit", "Liveness", "Presentation" {
    BeforeAll {
        $script:counts = @{ open = 12; alive = 9; filtered = 14; unreachable = 3; unknown = 2 }
    }

    It "Collapses filtered, unreachable and unknown into one no-response figure" {
        $wide = Format-LivenessCounters -Counts $script:counts -Width 120
        $wide | Should -Be " | Open: 12 | Alive: 9 | NoResp: 19"
    }

    It "Shortens on a narrow terminal" {
        $narrow = Format-LivenessCounters -Counts $script:counts -Width 80
        $narrow | Should -Be " | O:12 A:9 N:19"
        # It must not cost more room than the Live/Dead line it replaced.
        $narrow.Length | Should -BeLessOrEqual " | Live: 12 | Dead: 19".Length
    }

    It "Handles an empty tally" {
        Format-LivenessCounters -Counts @{} -Width 120 | Should -Be " | Open: 0 | Alive: 0 | NoResp: 0"
    }
}

Describe "A timed-out scan is not evidence of anything" -Tag "Unit", "Liveness" {
    # --host-timeout makes nmap give up before probing. The old code read the
    # empty port table as "no open ports" and called the host dead.

    It "Reports unknown when the host timed out before any port was probed" {
        $v = Resolve-LivenessVerdict -Facts @{ OpenCount = 0; PortElements = 0; Reasons = @{}; TimedOut = $true }
        $v.Verdict | Should -Be 'unknown'
        $v.Evidence | Should -Match 'timed out'
    }

    It "Reports unknown rather than filtered when it timed out part way through" {
        $v = Resolve-LivenessVerdict -Facts @{
            OpenCount = 0; FilteredCount = 4; PortElements = 4
            Reasons = @{ 'no-response' = 4 }; TimedOut = $true
        }
        $v.Verdict | Should -Be 'unknown'
    }

    It "Still reports open when it found something before timing out" {
        $v = Resolve-LivenessVerdict -Facts @{
            OpenCount = 1; PortElements = 4; Reasons = @{ 'syn-ack' = 1 }; TimedOut = $true
        }
        $v.Verdict | Should -Be 'open'
    }
}
