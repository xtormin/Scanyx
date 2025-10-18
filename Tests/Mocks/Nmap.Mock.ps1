# Nmap.Mock.ps1
# Mock functions for Nmap commands to avoid real network scans during testing

function New-MockNmapXml {
    <#
    .SYNOPSIS
    Generates mock Nmap XML output for testing

    .PARAMETER Host
    The host IP or hostname

    .PARAMETER Ports
    Array of port objects with portid, protocol, and state

    .PARAMETER HostState
    State of the host (up or down)
    #>
    param(
        [string]$Host,
        [array]$Ports = @(),
        [string]$HostState = "up"
    )

    $portsXml = ""
    foreach ($port in $Ports) {
        $portsXml += @"

            <port protocol="$($port.protocol)" portid="$($port.portid)">
                <state state="$($port.state)"/>
                <service name="$($port.service)"/>
            </port>
"@
    }

    if ($Ports.Count -gt 0) {
        $portsSection = @"

        <ports>$portsXml
        </ports>
"@
    } else {
        $portsSection = ""
    }

    $xml = @"
<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="mock" start="1234567890" version="7.94">
    <scaninfo type="syn" protocol="tcp" numservices="1000"/>
    <host>
        <status state="$HostState" reason="echo-reply"/>
        <address addr="$Host" addrtype="ipv4"/>$portsSection
    </host>
    <runstats>
        <finished time="1234567890" timestr="Mock Scan" elapsed="1.23"/>
        <hosts up="1" down="0" total="1"/>
    </runstats>
</nmaprun>
"@

    return $xml
}

function Mock-NmapCommand {
    <#
    .SYNOPSIS
    Simulates Nmap execution for testing

    .PARAMETER Host
    Target host

    .PARAMETER OutputFile
    Output XML file path

    .PARAMETER Scenario
    Test scenario: "success", "host-up", "host-down", "failure", "timeout"
    #>
    param(
        [string]$Host,
        [string]$OutputFile,
        [string]$Scenario = "success"
    )

    switch ($Scenario) {
        "success" {
            # Host up with open ports
            $mockXml = New-MockNmapXml -Host $Host -HostState "up" -Ports @(
                @{ portid = "22"; protocol = "tcp"; state = "open"; service = "ssh" }
                @{ portid = "80"; protocol = "tcp"; state = "open"; service = "http" }
                @{ portid = "443"; protocol = "tcp"; state = "open"; service = "https" }
            )
            $mockXml | Out-File $OutputFile
            return 0
        }

        "host-up" {
            # Host up with some open ports
            $mockXml = New-MockNmapXml -Host $Host -HostState "up" -Ports @(
                @{ portid = "80"; protocol = "tcp"; state = "open"; service = "http" }
            )
            $mockXml | Out-File $OutputFile
            return 0
        }

        "host-down" {
            # Host down, no ports
            $mockXml = New-MockNmapXml -Host $Host -HostState "down" -Ports @()
            $mockXml | Out-File $OutputFile
            return 0
        }

        "no-open-ports" {
            # Host up but all ports closed/filtered
            $mockXml = New-MockNmapXml -Host $Host -HostState "up" -Ports @(
                @{ portid = "22"; protocol = "tcp"; state = "closed"; service = "ssh" }
                @{ portid = "80"; protocol = "tcp"; state = "filtered"; service = "http" }
            )
            $mockXml | Out-File $OutputFile
            return 0
        }

        "failure" {
            # Nmap execution failed
            Write-Error "Mock Nmap failure"
            return 1
        }

        "timeout" {
            # Simulate timeout (no output file created)
            return 124
        }

        "partial" {
            # Partial results (some ports scanned)
            $mockXml = New-MockNmapXml -Host $Host -HostState "up" -Ports @(
                @{ portid = "22"; protocol = "tcp"; state = "open"; service = "ssh" }
            )
            $mockXml | Out-File $OutputFile
            return 0
        }

        default {
            throw "Unknown mock scenario: $Scenario"
        }
    }
}

function Mock-NmapInstallation {
    <#
    .SYNOPSIS
    Mocks Test-NmapInstalled function

    .PARAMETER Installed
    Whether Nmap should appear installed
    #>
    param([bool]$Installed = $true)

    if ($Installed) {
        Mock Test-NmapInstalled { return $true } -ModuleName Scanyx
    } else {
        Mock Test-NmapInstalled { return $false } -ModuleName Scanyx
    }
}

function New-MockScanProfiles {
    <#
    .SYNOPSIS
    Creates mock scan-profiles.json for testing

    .PARAMETER Path
    Path where to save the mock config
    #>
    param([string]$Path)

    $mockConfig = @{
        profiles = @{
            "tcp-test" = @{
                name = "TCP Test Scan"
                description = "Test profile for unit tests"
                args = "-sT -p 80,443 -T4"
            }
            "udp-test" = @{
                name = "UDP Test Scan"
                description = "UDP test profile"
                args = "-sU -p 53,161 -T4"
            }
        }
        workflows = @{
            "test-workflow" = @{
                name = "Test Workflow"
                description = "Test workflow for unit tests"
                steps = @(
                    @{ profile = "tcp-test"; condition = "always" }
                    @{ profile = "udp-test"; condition = "previous_success" }
                )
            }
        }
    }

    $mockConfig | ConvertTo-Json -Depth 10 | Out-File $Path
}

function New-MockHostsFile {
    <#
    .SYNOPSIS
    Creates mock hosts file for testing

    .PARAMETER Path
    Path where to save the mock hosts file

    .PARAMETER Content
    Array of hosts to include
    #>
    param(
        [string]$Path,
        [array]$Content = @("192.168.1.1", "192.168.1.0/30", "server.example.com")
    )

    $Content -join "`n" | Out-File $Path
}

function New-MockSessionStructure {
    <#
    .SYNOPSIS
    Creates mock session directory structure

    .PARAMETER BaseDir
    Base directory for session

    .PARAMETER SessionName
    Name of the session
    #>
    param(
        [string]$BaseDir,
        [string]$SessionName
    )

    $sessionDir = Join-Path $BaseDir ".sessions\$SessionName"
    New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null

    # Create mock state file
    $stateFile = Join-Path $sessionDir "state.json"
    @{
        "192.168.1.1" = "completed"
        "192.168.1.2" = "pending"
    } | ConvertTo-Json | Out-File $stateFile

    # Create mock log file
    $logFile = Join-Path $sessionDir "scan.log"
    "[INFO] Mock log entry" | Out-File $logFile

    return $sessionDir
}

# Export functions
Export-ModuleMember -Function @(
    'New-MockNmapXml',
    'Mock-NmapCommand',
    'Mock-NmapInstallation',
    'New-MockScanProfiles',
    'New-MockHostsFile',
    'New-MockSessionStructure'
)
