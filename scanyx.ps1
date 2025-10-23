<#
.SYNOPSIS
SCANYX - Advanced Nmap scanner with parallel execution, state persistence, and comprehensive logging.

.DESCRIPTION
SCANYX is a PowerShell pentesting tool that performs port scans on hosts specified in a text file using Nmap with advanced features:
- Parallel scanning with configurable concurrency
- State persistence for resume capability
- Comprehensive logging (text, JSON, and error logs)
- Automatic retry mechanism for failed scans
- Progress tracking and summary reports
- Input validation and error handling
- Workflow support for chaining multiple scan profiles
- External JSON configuration for scan profiles and workflows

.PARAMETER HostFile
Optional path to the text file containing the hosts to be scanned.
Supports: Individual IPs (192.168.1.10), CIDR notation (192.168.1.0/24), and hostnames (server.example.com).
One entry per line. Lines starting with # are treated as comments.
Either -HostFile or -Hosts must be provided.

.PARAMETER Hosts
Optional array of hosts to scan provided directly as command line arguments.
Supports the same formats as HostFile (IPs, CIDR, hostnames).
Can be combined with -HostFile to scan hosts from both sources.

.PARAMETER ExcludeFile
Optional path to a text file containing hosts to exclude from scanning.
Supports the same formats as HostFile (IPs, CIDR, hostnames).

.PARAMETER ExcludeHosts
Optional array of hosts to exclude provided directly as command line arguments.
Supports the same formats as ExcludeFile (IPs, CIDR, hostnames).
Can be combined with -ExcludeFile to exclude hosts from both sources.

.PARAMETER ResolveHostnames
Attempt to resolve hostnames to IPs for exclusion matching. May be slow for large lists.

.PARAMETER SensitiveFile
Optional path to a text file containing sensitive hosts to scan with reduced timing/scripts.
Supports the same formats as HostFile (IPs, CIDR, hostnames).

.PARAMETER SensitiveHosts
Optional array of sensitive hosts provided directly as command line arguments.
Supports the same formats as SensitiveFile (IPs, CIDR, hostnames).
Can be combined with -SensitiveFile to mark hosts as sensitive from both sources.

.PARAMETER SensitiveTiming
Nmap timing template for sensitive hosts (T0-T4). Default: T2 (less aggressive than normal T4).

.PARAMETER SensitiveScripts
NSE scripts to use for sensitive hosts. Options: default, vuln, none, default+vuln. Default: default.

.PARAMETER ScanType
Specifies the scan profile to use. Profiles are loaded from nmap-profiles-workflows.json in the script directory.
Default profiles include: tcp-1000, tcp-full, udp-common, udp-1000, udp-full.
You can add custom profiles by editing nmap-profiles-workflows.json.

.PARAMETER OutputDir
Specifies the output directory for scan results. Default: "nmap"

.PARAMETER MaxConcurrent
Maximum number of concurrent scans. Default: 5

.PARAMETER MaxRetries
Maximum number of retry attempts for failed scans. Default: 1

.PARAMETER RetryDelay
Delay in seconds between retry attempts. Default: 60

.PARAMETER OverwriteMode
Behavior when scan results already exist for a host:
- Skip: Skip hosts with existing results
- Overwrite: Overwrite existing results
- Ask: Prompt for each host (default)

.PARAMETER Resume
Continue scanning only pending hosts (skips completed and failed hosts).

.PARAMETER ResumeRetryFailed
Continue scanning pending hosts AND retry failed hosts.

.PARAMETER RetryFailed
Only retry hosts that previously failed (skips pending and completed).

.PARAMETER Force
Ignore previous state and start fresh scan (archives old state files).

.PARAMETER Unprivileged
Use unprivileged mode for nmap scans (adds --unprivileged flag).
Required on Windows when ethernet devices are not available for raw scans.
Automatically replaces -sS with -sT for compatibility.

.PARAMETER ConfigFile
Optional path to custom scan profiles configuration JSON file.
Default: nmap-profiles-workflows.json in script directory.
Allows using different configurations for different projects or scan scenarios.

.PARAMETER VerboseMode
Enable verbose mode to display the full nmap command being executed for each host and show the complete nmap output after each scan completes.
Useful for debugging and understanding the exact commands being run and their output.

.EXAMPLE
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-1000
Execute a TCP top 1000 ports scan with default settings.

.EXAMPLE
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-full -MaxConcurrent 10 -OverwriteMode Skip
Execute a full TCP scan with 10 concurrent scans, skipping existing results.

.EXAMPLE
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType udp-common -Resume
Resume a previous scan session, continuing only with pending hosts.

.EXAMPLE
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-1000 -ResumeRetryFailed
Resume and retry failed hosts from previous session.

.EXAMPLE
.\scanyx.ps1 -HostFile .\hosts.txt -ExcludeFile .\excluded.txt -ScanType tcp-1000
Scan hosts from hosts.txt excluding those listed in excluded.txt.

.EXAMPLE
.\scanyx.ps1 -HostFile .\networks.txt -ExcludeFile .\gateways.txt -ResolveHostnames -ScanType tcp-full
Scan CIDR ranges from networks.txt, excluding hosts in gateways.txt with hostname resolution.

.EXAMPLE
.\scanyx.ps1 -HostFile .\hosts.txt -SensitiveFile .\production.txt -ScanType tcp-1000
Scan hosts with normal timing, but use T2 timing and default scripts for sensitive hosts.

.EXAMPLE
.\scanyx.ps1 -HostFile .\networks.txt -SensitiveFile .\critical.txt -SensitiveTiming T1 -SensitiveScripts none -ScanType tcp-full
Scan with very slow timing (T1) and no NSE scripts for critical/sensitive hosts.

.EXAMPLE
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-1000 -VerboseMode
Execute a scan with verbose mode enabled to see the exact nmap commands being run.

.EXAMPLE
.\scanyx.ps1 -Hosts "192.168.1.0/24","10.0.0.50" -ScanType tcp-1000
Scan hosts provided directly via command line without using a file.

.EXAMPLE
.\scanyx.ps1 -Hosts "192.168.0.0/24" -ExcludeHosts "192.168.0.1","192.168.0.254" -ScanType tcp-1000
Scan a network excluding specific hosts, all provided via command line.

.EXAMPLE
.\scanyx.ps1 -HostFile .\hosts.txt -Hosts "192.168.5.0/24" -ExcludeHosts "192.168.5.1" -SensitiveHosts "192.168.5.10" -ScanType tcp-1000
Combine file-based and command line hosts, exclusions, and sensitive hosts.

.EXAMPLE
# Create custom scan profile by editing nmap-profiles-workflows.json:
# {
#   "custom-stealth": {
#     "name": "Stealth Scan",
#     "description": "Slow and stealthy scan",
#     "command": "nmap -v -T2 -Pn -sS --host-timeout 15m"
#   }
# }
# Then use: .\scanyx.ps1 -HostFile .\hosts.txt -ScanType custom-stealth

.NOTES
Author: Jennifer Torres (@xtormin)
Version: 2.8.0
Requires: Nmap installed and available in PATH

Scan profiles are loaded from nmap-profiles-workflows.json in the script directory.
If the file doesn't exist, it will be created with default profiles.
#>

# ============================================
# HELPER FUNCTIONS (Global Scope)
# ============================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "VERBOSE")]
        [string]$Level = "INFO",
        [string]$LogFile,
        [string]$ErrorLogFile = $null
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Console output with colors
    $color = switch ($Level) {
        "INFO"    { "White" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
        "VERBOSE" { "Cyan" }
    }
    Write-Host $logEntry -ForegroundColor $color

    # File output
    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue

    # Error log
    if ($Level -eq "ERROR" -and $ErrorLogFile) {
        Add-Content -Path $ErrorLogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
}

function Test-NmapInstalled {
    try {
        $null = Get-Command nmap -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Test-ValidIPOrHost {
    param([string]$Address)

    # Check if it looks like an IP
    $segments = $Address -split '\.'

    # If exactly 4 segments, check if it's an IP or hostname
    if ($segments.Count -eq 4) {
        $numericSegments = ($segments | Where-Object { $_ -match '^\d+$' }).Count

        # If all 4 segments are numeric, validate as IP
        if ($numericSegments -eq 4) {
            $ipPattern = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            if ($Address -match $ipPattern) {
                return $true
            }
            # All numeric but invalid IP (e.g., 256.1.1.1)
            return $false
        }

        # If 2-3 segments are numeric, it's likely a malformed IP, not a hostname
        # Examples: 192.168.1.a, 192.168.1.1.1 (after split, but this has 5 segments)
        if ($numericSegments -ge 2) {
            # Reject things that look like malformed IPs
            return $false
        }

        # If 0-1 segments are numeric, treat as potential hostname (e.g., api.v2.example.com)
        # Fall through to hostname validation below
    }

    # Check if valid hostname/FQDN (must contain at least one letter)
    # Hostnames must start with alphanumeric, can contain hyphens, and end with alphanumeric
    $hostnamePattern = '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    if ($Address -match $hostnamePattern) {
        # Ensure it contains at least one letter (not just numbers)
        if ($Address -match '[a-zA-Z]') {
            return $true
        }
    }

    return $false
}

function Test-ValidCIDR {
    param([string]$CIDR)

    # Check CIDR format: xxx.xxx.xxx.xxx/yy
    $cidrPattern = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[12][0-9]|3[0-2])$'
    if ($CIDR -match $cidrPattern) {
        # Extract subnet mask
        $mask = [int]($CIDR -split '/')[1]
        # Valid range: /0 to /32 (allow all valid CIDR masks)
        # Note: /0 represents the entire internet (0.0.0.0/0)
        if ($mask -ge 0 -and $mask -le 32) {
            return $true
        }
    }

    return $false
}

function Expand-CIDR {
    param([string]$CIDR)

    try {
        # Split IP and mask
        $parts = $CIDR -split '/'
        $ipAddress = $parts[0]
        $maskBits = [int]$parts[1]

        # Convert IP to unsigned 32-bit integer
        $ipBytes = $ipAddress.Split('.')
        [uint32]$ipInt = ([uint32]$ipBytes[0] -shl 24) + ([uint32]$ipBytes[1] -shl 16) + ([uint32]$ipBytes[2] -shl 8) + [uint32]$ipBytes[3]

        # Calculate number of host bits and total hosts
        $hostBits = 32 - $maskBits
        [uint64]$totalHosts = [math]::Pow(2, $hostBits)

        # Calculate subnet mask using bit operations
        # Create mask by setting the first $maskBits bits to 1
        [uint32]$mask = 0
        if ($maskBits -eq 32) {
            $mask = [uint32]::MaxValue
        } elseif ($maskBits -gt 0) {
            # Build mask bit by bit to avoid casting issues
            for ($b = 0; $b -lt $maskBits; $b++) {
                $mask = $mask -bor ([uint32]1 -shl (31 - $b))
            }
        }

        # Calculate network address
        [uint32]$networkInt = $ipInt -band $mask

        # Calculate broadcast address
        [uint32]$broadcastInt = $networkInt -bor (-bnot $mask)

        # Calculate usable range (exclude network and broadcast for subnets < /31)
        if ($maskBits -lt 31) {
            $firstHost = $networkInt + 1
            $lastHost = $broadcastInt - 1
        } elseif ($maskBits -eq 31) {
            # /31 point-to-point - use both addresses
            $firstHost = $networkInt
            $lastHost = $broadcastInt
        } else {
            # /32 single host
            $firstHost = $networkInt
            $lastHost = $networkInt
        }

        # Generate IP list
        $hosts = @()
        for ([uint32]$i = $firstHost; $i -le $lastHost; $i++) {
            $byte1 = ($i -shr 24) -band 0xFF
            $byte2 = ($i -shr 16) -band 0xFF
            $byte3 = ($i -shr 8) -band 0xFF
            $byte4 = $i -band 0xFF
            $hosts += "$byte1.$byte2.$byte3.$byte4"
        }

        # Force return as array (PowerShell returns single items as scalars)
        # Using comma operator to prevent unwrapping of single-element arrays
        return ,$hosts
    } catch {
        Write-Warning "Failed to expand CIDR $CIDR : $_"
        return @()
    }
}

function Resolve-HostEntry {
    param(
        [string]$Line,
        [string]$LogFile = "",
        [bool]$ResolveHostname = $false
    )

    $Line = $Line.Trim()

    # Skip empty lines and comments
    if ($Line -eq "" -or $Line.StartsWith("#")) {
        return @{
            Type = "Comment"
            Hosts = @()
            Original = $Line
        }
    }

    # Check if CIDR
    if (Test-ValidCIDR $Line) {
        $expandedHosts = Expand-CIDR $Line
        if ($LogFile) {
            Write-Log -Message "Expanded $Line to $($expandedHosts.Count) hosts" -Level "INFO" -LogFile $LogFile
        }
        return @{
            Type = "CIDR"
            Hosts = $expandedHosts
            Original = $Line
            SourceCIDR = $Line
        }
    }

    # Check if IP
    $ipPattern = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if ($Line -match $ipPattern) {
        return @{
            Type = "IP"
            Hosts = ,$Line
            Original = $Line
            SourceCIDR = $null
        }
    }

    # Check if hostname
    $hostnamePattern = '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    if ($Line -match $hostnamePattern) {
        $hosts = ,$Line

        # Optionally resolve to IP
        if ($ResolveHostname) {
            try {
                $resolved = [System.Net.Dns]::GetHostAddresses($Line)
                $resolvedIPs = $resolved | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }
                if ($resolvedIPs.Count -gt 0) {
                    $hosts += $resolvedIPs
                    if ($LogFile) {
                        Write-Log -Message "Resolved $Line to $($resolvedIPs -join ', ')" -Level "INFO" -LogFile $LogFile
                    }
                }
            } catch {
                if ($LogFile) {
                    Write-Log -Message "Failed to resolve hostname $Line" -Level "WARNING" -LogFile $LogFile
                }
            }
        }

        return @{
            Type = "Hostname"
            Hosts = $hosts
            Original = $Line
            SourceCIDR = $null
        }
    }

    # Invalid entry
    return @{
        Type = "Invalid"
        Hosts = @()
        Original = $Line
        SourceCIDR = $null
    }
}

function Get-MostSpecificCIDR {
    param(
        [string]$IPAddress,
        $CIDRList  # Can be array or hashtable
    )

    if ($CIDRList.Count -eq 0) {
        return $null
    }

    # Get CIDR list (handle both array and hashtable)
    $cidrs = if ($CIDRList -is [hashtable]) {
        $CIDRList.Keys
    } else {
        $CIDRList
    }

    # Filter CIDRs that contain this IP
    $matchingCIDRs = @()
    foreach ($cidr in $cidrs) {
        $parts = $cidr -split '/'
        $networkIP = $parts[0]
        $maskBits = [int]$parts[1]

        # Convert IP and network to integers
        $ipBytes = $IPAddress.Split('.')
        $netBytes = $networkIP.Split('.')
        $ipInt = ([long][int]$ipBytes[0] -shl 24) + ([long][int]$ipBytes[1] -shl 16) + ([long][int]$ipBytes[2] -shl 8) + [long][int]$ipBytes[3]
        $netInt = ([long][int]$netBytes[0] -shl 24) + ([long][int]$netBytes[1] -shl 16) + ([long][int]$netBytes[2] -shl 8) + [long][int]$netBytes[3]

        # Calculate mask
        $mask = [long]([math]::Pow(2, 32) - [math]::Pow(2, (32 - $maskBits)))

        # Check if IP is in this CIDR
        if (($ipInt -band $mask) -eq ($netInt -band $mask)) {
            $matchingCIDRs += @{
                CIDR = $cidr
                Mask = $maskBits
            }
        }
    }

    if ($matchingCIDRs.Count -eq 0) {
        return $null
    }

    # Return CIDR with highest mask (most specific)
    $mostSpecific = $matchingCIDRs | Sort-Object -Property Mask -Descending | Select-Object -First 1
    return $mostSpecific.CIDR
}

function Get-OutputFolder {
    param(
        [Parameter(Mandatory=$false)]
        [string]$TargetHost,
        [Parameter(Mandatory=$false)]
        [Alias("Host")]
        [string]$HostParameter,
        [string]$SourceCIDR = "",
        [string]$BaseDir,
        [string]$ScanType = "",
        [string]$WorkflowName = "",
        [int]$WorkflowStep = 0,
        [string]$StepProfile = ""
    )

    # Support both -TargetHost and -Host (for tests)
    $hostKey = if ($TargetHost) { $TargetHost } else { $HostParameter }

    # Simple mode for tests (includes scan type in path)
    if ($ScanType -and -not $WorkflowName) {
        return Join-Path $BaseDir "$hostKey\$ScanType"
    }

    if ($WorkflowName -and $WorkflowName -ne "") {
        # Workflow mode: BaseDir/SN-profile/networks|hosts/host/
        $stepFolder = "S$WorkflowStep-$StepProfile"
        if ($SourceCIDR) {
            $cidrFolder = $SourceCIDR -replace '/', '-'
            return "$BaseDir\$stepFolder\networks\$cidrFolder\$hostKey"
        } else {
            return "$BaseDir\$stepFolder\hosts\$hostKey"
        }
    } else {
        # Single scan mode: each host has its own folder
        if ($SourceCIDR) {
            # From CIDR: goes to networks/cidr/host/ folder
            $cidrFolder = $SourceCIDR -replace '/', '-'
            return "$BaseDir\networks\$cidrFolder\$hostKey"
        } else {
            # Individual host: goes to hosts/host/ folder
            return "$BaseDir\hosts\$hostKey"
        }
    }
}

function Build-SensitiveScanCommand {
    param(
        [string]$TargetHost,
        [string]$Arguments,
        [string]$OutputFile,
        [bool]$IsSensitive,
        [string]$SensitiveTiming,
        [string]$SensitiveScripts,
        [bool]$Unprivileged = $false
    )

    # Start with base nmap command
    $cmd = "nmap"

    # Add arguments
    if ($Arguments) {
        $cmd += " $Arguments"
    }

    # Handle sensitive hosts: replace timing
    if ($IsSensitive) {
        $cmd = $cmd -replace '-T\d+', "-$SensitiveTiming"

        # Replace scripts if sensitive
        if ($SensitiveScripts -eq "none") {
            $cmd = $cmd -replace '--script[=\s]+[^\s]+', ''
            $cmd = $cmd -replace '\s+', ' '
        }
    }

    # Handle unprivileged mode
    if ($Unprivileged) {
        $cmd += " --unprivileged"
        $cmd = $cmd -replace '-sS', '-sT'
    }

    # Add output file
    $cmd += " -oX `"$OutputFile`""

    # Add host
    $cmd += " $TargetHost"

    return $cmd.Trim() -replace '\s+', ' '
}

function Save-StateFile {
    param(
        [string]$StateFile,
        [hashtable]$State
    )

    try {
        # Create parent directory if it doesn't exist
        $parentDir = Split-Path -Path $StateFile -Parent
        if ($parentDir -and -not (Test-Path $parentDir)) {
            New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
        }

        $State | ConvertTo-Json -Depth 10 | Set-Content -Path $StateFile -ErrorAction Stop
    } catch {
        Write-Warning "Failed to save state file: $_"
    }
}

function Load-StateFile {
    param([string]$StateFile)

    if (Test-Path $StateFile) {
        try {
            $json = Get-Content -Path $StateFile -Raw -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($json)) {
                return @{}
            }
            $obj = $json | ConvertFrom-Json
            # Convert PSCustomObject to Hashtable
            $hashtable = @{}
            $obj.PSObject.Properties | ForEach-Object {
                $hashtable[$_.Name] = $_.Value
            }
            return $hashtable
        } catch {
            Write-Warning "Failed to load state file: $_"
            return @{}
        }
    }
    return @{}
}

function Update-HostState {
    param(
        [hashtable]$State,
        [Parameter(Mandatory=$false)]
        [string]$TargetHost,
        [Parameter(Mandatory=$false)]
        [Alias("Host")]
        [string]$HostParameter,
        [Parameter(Mandatory=$false)]
        [string]$Status,
        [Parameter(Mandatory=$false)]
        [string]$NewState,
        [int]$Attempts = 0,
        [string]$Error = "",
        [string]$ScanFile = ""
    )

    # Support both -TargetHost and -Host (for tests)
    $hostKey = if ($TargetHost) { $TargetHost } else { $HostParameter }
    $statusValue = if ($Status) { $Status } else { $NewState }

    # Simple mode for tests (flat hashtable)
    if (-not $State.ContainsKey("hosts")) {
        $State[$hostKey] = $statusValue
        return
    }

    # Complex mode for real usage (structured state)
    $hostState = @{
        status = $statusValue
        attempts = $Attempts
        last_update = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
        error = $Error
    }

    # Preserve existing fields that shouldn't be overwritten
    if ($State.hosts.ContainsKey($hostKey)) {
        $existingHost = $State.hosts[$hostKey]
        if ($existingHost.source_cidr) { $hostState.source_cidr = $existingHost.source_cidr }
        if ($existingHost.alternative_cidrs) { $hostState.alternative_cidrs = $existingHost.alternative_cidrs }
        if ($existingHost.output_folder) { $hostState.output_folder = $existingHost.output_folder }
        if ($existingHost.sensitive) { $hostState.sensitive = $existingHost.sensitive }
        if ($existingHost.scan_type) { $hostState.scan_type = $existingHost.scan_type }
        if ($existingHost.timing) { $hostState.timing = $existingHost.timing }
        if ($existingHost.scripts) { $hostState.scripts = $existingHost.scripts }
    }

    # Add or update scan file
    if ($ScanFile -ne "") {
        $hostState.scan_file = $ScanFile
    } elseif ($State.hosts.ContainsKey($hostKey) -and $State.hosts[$hostKey].scan_file) {
        $hostState.scan_file = $State.hosts[$hostKey].scan_file
    }

    $State.hosts[$hostKey] = $hostState

    # Update counters
    $State.completed = ($State.hosts.GetEnumerator() | Where-Object { $_.Value.status -eq "completed" }).Count
    $State.failed = ($State.hosts.GetEnumerator() | Where-Object { $_.Value.status -eq "failed" }).Count
    $State.in_progress = ($State.hosts.GetEnumerator() | Where-Object { $_.Value.status -eq "in_progress" }).Count
    $State.pending = ($State.hosts.GetEnumerator() | Where-Object { $_.Value.status -eq "pending" }).Count
}

function Add-ScanResult {
    param(
        [string]$ResultsFile,
        [hashtable]$ScanResult
    )

    try {
        # Load existing results or create new structure
        if (Test-Path $ResultsFile) {
            $results = Get-Content -Path $ResultsFile -Raw | ConvertFrom-Json
            $scansList = [System.Collections.ArrayList]@($results.scans)
        } else {
            $results = @{
                scan_session = ""
                scans = @()
            }
            $scansList = [System.Collections.ArrayList]@()
        }

        # Add new scan result
        $null = $scansList.Add($ScanResult)
        $results.scans = $scansList

        # Save
        $results | ConvertTo-Json -Depth 10 | Set-Content -Path $ResultsFile
    } catch {
        Write-Warning "Failed to save scan result: $_"
    }
}

function Test-HostHasOpenPorts {
    param([string]$XmlFile)

    # Validate that XmlFile is not empty or null
    if ([string]::IsNullOrWhiteSpace($XmlFile)) {
        return $false
    }

    if (-not (Test-Path $XmlFile)) {
        return $false
    }

    try {
        $content = Get-Content $XmlFile -Raw -ErrorAction Stop

        # Detect file format and use appropriate pattern
        if ($content -match '<\?xml' -or $content -match '<nmaprun') {
            # XML format: <state state="open"/>
            return $content -match '<state\s+state="open"'
        } else {
            # Plain text .nmap format: "22/tcp   open  ssh"
            return $content -match "\d+/(tcp|udp)\s+open"
        }
    } catch {
        return $false
    }
}

function Show-ProgressBar {
    param(
        [int]$Completed,
        [int]$Total,
        [int]$Failed,
        [string]$CurrentHost = "",
        [int]$WorkflowStep = 0,
        [int]$WorkflowTotalSteps = 0,
        [string]$StepProfile = "",
        [hashtable]$NetworkProgress = @{},
        [int]$AliveHosts = 0,
        [hashtable]$HostStateInfo = @{},
        [hashtable]$ActiveJobs = @{},
        [DateTime]$ScanStartTime = [DateTime]::MinValue,
        [array]$CompletedDurations = @()
    )

    $percent = if ($Total -gt 0) { [math]::Min([math]::Round(($Completed / $Total) * 100, 1), 100) } else { 0 }
    $successful = $Completed - $Failed

    # Count hosts with open ports (Live hosts) and without (Dead hosts)
    $liveHosts = 0
    $deadHosts = 0
    if ($HostStateInfo.Count -gt 0) {
        foreach ($hostEntry in $HostStateInfo.GetEnumerator()) {
            $hostData = $hostEntry.Value
            if ($hostData.status -eq "completed" -and $hostData.scan_file) {
                if (Test-HostHasOpenPorts -XmlFile $hostData.scan_file) {
                    $liveHosts++
                } else {
                    $deadHosts++
                }
            }
        }
    }

    # Helper function to format time in HH:MM format (with days if >= 1 day)
    function Format-TimeSpan {
        param([TimeSpan]$TimeSpan)

        if ($TimeSpan.TotalDays -ge 1) {
            $days = [math]::Floor($TimeSpan.TotalDays)
            $hours = $TimeSpan.Hours
            $minutes = $TimeSpan.Minutes
            return "${days}d $($hours.ToString('00')):$($minutes.ToString('00'))"
        } else {
            $hours = [math]::Floor($TimeSpan.TotalHours)
            $minutes = $TimeSpan.Minutes
            return "$($hours.ToString('00')):$($minutes.ToString('00'))"
        }
    }

    # Calculate elapsed time
    $elapsedStr = ""
    $etaStr = ""
    if ($ScanStartTime -ne [DateTime]::MinValue) {
        $elapsed = (Get-Date) - $ScanStartTime
        $elapsedStr = Format-TimeSpan -TimeSpan $elapsed

        # Calculate ETA (only after 10 completed scans)
        if ($CompletedDurations.Count -ge 10 -and $Total -gt $Completed) {
            $avgDuration = ($CompletedDurations | Measure-Object -Average).Average
            $remainingHosts = $Total - $Completed
            $estimatedSeconds = $remainingHosts * $avgDuration
            $eta = [TimeSpan]::FromSeconds($estimatedSeconds)
            $etaStr = " / ~$(Format-TimeSpan -TimeSpan $eta) ETA"
        }
    }

    # Get active hosts list
    $activeHostsList = @()
    if ($ActiveJobs.Count -gt 0) {
        $activeHostsList = $ActiveJobs.Keys | Sort-Object
    }

    # Format active hosts display (limit to 5)
    $currentHostsDisplay = ""
    if ($activeHostsList.Count -gt 0) {
        if ($activeHostsList.Count -le 5) {
            $currentHostsDisplay = $activeHostsList -join ", "
        } else {
            $displayHosts = $activeHostsList[0..4] -join ", "
            $remaining = $activeHostsList.Count - 5
            $currentHostsDisplay = "$displayHosts, ... (+$remaining more)"
        }
    }

    # Check if we're in workflow mode
    $isWorkflow = $WorkflowStep -gt 0 -and $WorkflowTotalSteps -gt 0

    if ($isWorkflow) {
        # Workflow mode: Show two progress bars (workflow progress + current step progress)

        # Calculate workflow progress
        $workflowPercent = [math]::Round((($WorkflowStep - 1) / $WorkflowTotalSteps) * 100, 1)

        # Build main status with alive hosts and network info
        $mainStatus = "Step ${WorkflowStep}/${WorkflowTotalSteps}: ${StepProfile} | Alive: ${AliveHosts}/${Total} hosts"

        # Add network completion info if scanning multiple networks
        if ($NetworkProgress.Count -gt 0) {
            $completedNetworks = ($NetworkProgress.GetEnumerator() | Where-Object { $_.Value.Scanned -eq $_.Value.Total }).Count
            $totalNetworks = $NetworkProgress.Count
            $mainStatus += " | Networks: $completedNetworks/$totalNetworks completed"
        }

        # Main progress bar: Workflow steps
        Write-Progress -Id 1 `
                       -Activity "Workflow Progress" `
                       -Status $mainStatus `
                       -PercentComplete $workflowPercent

        # Build secondary status - Ultra compact format
        $secondaryStatus = "$Completed/$Total ($percent%) | OK: $successful | Fail: $Failed"

        if ($liveHosts -gt 0) {
            $secondaryStatus += " | Live: $liveHosts"
        }

        if ($deadHosts -gt 0) {
            $secondaryStatus += " | Dead: $deadHosts"
        }

        if ($elapsedStr -ne "") {
            $secondaryStatus += " | Time: $elapsedStr$etaStr"
        }

        $secondaryCurrentOperation = ""
        if ($currentHostsDisplay -ne "") {
            $secondaryCurrentOperation = "Current ($($activeHostsList.Count)): $currentHostsDisplay"
        }

        # Secondary progress bar: Current step hosts
        Write-Progress -Id 2 `
                       -ParentId 1 `
                       -Activity "Current step: $StepProfile" `
                       -Status $secondaryStatus `
                       -CurrentOperation $secondaryCurrentOperation `
                       -PercentComplete $percent
    } else {
        # Single scan mode: Show single progress bar - Ultra compact format
        $statusMessage = "$Completed/$Total ($percent%) | OK: $successful | Fail: $Failed"

        if ($liveHosts -gt 0) {
            $statusMessage += " | Live: $liveHosts"
        }

        if ($deadHosts -gt 0) {
            $statusMessage += " | Dead: $deadHosts"
        }

        if ($elapsedStr -ne "") {
            $statusMessage += " | Time: $elapsedStr$etaStr"
        }

        $currentOperation = ""
        if ($currentHostsDisplay -ne "") {
            $currentOperation = "Current ($($activeHostsList.Count)): $currentHostsDisplay"
        }

        Write-Progress -Activity "Scanning hosts" `
                       -Status $statusMessage `
                       -CurrentOperation $currentOperation `
                       -PercentComplete $percent
    }
}

function Show-NetworkSummary {
    param(
        [hashtable]$NetworkProgress,
        [string]$Title = "Network Scan Summary"
    )

    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "  $Title" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow

    if (-not $NetworkProgress -or $NetworkProgress.Count -eq 0) {
        Write-Host "No network data available" -ForegroundColor Gray
        return
    }

    # Classify networks by status
    $completed = @($NetworkProgress.GetEnumerator() | Where-Object { $_.Value.Scanned -eq $_.Value.Total -and $_.Value.Total -gt 0 })
    $partial = @($NetworkProgress.GetEnumerator() | Where-Object { $_.Value.Scanned -gt 0 -and $_.Value.Scanned -lt $_.Value.Total })
    $notStarted = @($NetworkProgress.GetEnumerator() | Where-Object { $_.Value.Scanned -eq 0 -and $_.Value.Total -gt 0 })

    # Show completed networks
    if ($completed.Count -gt 0) {
        Write-Host "`nCompleted Networks ($($completed.Count)):" -ForegroundColor Green
        foreach ($net in ($completed | Sort-Object Key)) {
            Write-Host "  $([char]0x2713) $($net.Key): $($net.Value.Alive)/$($net.Value.Total) alive" -ForegroundColor Green
        }
    }

    # Show partially scanned networks
    if ($partial.Count -gt 0) {
        Write-Host "`nPartially Scanned Networks ($($partial.Count)):" -ForegroundColor Yellow
        foreach ($net in ($partial | Sort-Object Key)) {
            $percent = [math]::Round(($net.Value.Scanned / $net.Value.Total) * 100, 1)
            Write-Host "  $([char]0x26A0) $($net.Key): $($net.Value.Scanned)/$($net.Value.Total) scanned ($percent%) | $($net.Value.Alive) alive" -ForegroundColor Yellow
        }
    }

    # Show not started networks
    if ($notStarted.Count -gt 0) {
        Write-Host "`nNot Started Networks ($($notStarted.Count)):" -ForegroundColor Red
        foreach ($net in ($notStarted | Sort-Object Key)) {
            Write-Host "  $([char]0x2717) $($net.Key): 0/$($net.Value.Total) scanned" -ForegroundColor Red
        }
    }

    Write-Host "" # Empty line for spacing
}

function Get-UserChoice {
    param(
        [string]$Prompt,
        [string[]]$Options,
        [string]$Default = ""
    )

    Write-Host "`n$Prompt" -ForegroundColor Cyan
    for ($i = 0; $i -lt $Options.Length; $i++) {
        $prefix = if ($Options[$i] -eq $Default) { "*" } else { " " }
        Write-Host "  [$($i+1)]$prefix $($Options[$i])"
    }

    do {
        $choice = Read-Host "`nEnter choice (1-$($Options.Length))"
        if ($choice -eq "" -and $Default) {
            return $Default
        }
        $choiceNum = $choice -as [int]
    } while ($choiceNum -lt 1 -or $choiceNum -gt $Options.Length)

    return $Options[$choiceNum - 1]
}

function Get-ConfigContent {
    <#
    .SYNOPSIS
    Gets configuration content from a file path or URL.

    .DESCRIPTION
    Attempts to load configuration content from either a local file or HTTP/HTTPS URL.
    Returns a hashtable with Success status, Content, and Source information.

    .PARAMETER ConfigPath
    Path to local file or HTTP/HTTPS URL
    #>
    param([string]$ConfigPath)

    # Detectar si es URL (http:// o https://)
    if ($ConfigPath -match '^https?://') {
        try {
            Write-Host "[INFO] Downloading configuration from URL: $ConfigPath" -ForegroundColor Cyan
            $content = (New-Object Net.WebClient).DownloadString($ConfigPath)
            Write-Host "[INFO] Configuration downloaded successfully" -ForegroundColor Green
            return @{
                Success = $true
                Content = $content
                Source = "URL"
            }
        } catch {
            Write-Warning "Failed to download configuration from URL: $_"
            return @{
                Success = $false
                Error = $_.Exception.Message
                Source = "URL"
            }
        }
    } else {
        # Archivo local
        if (Test-Path $ConfigPath) {
            try {
                $content = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
                return @{
                    Success = $true
                    Content = $content
                    Source = "File"
                }
            } catch {
                return @{
                    Success = $false
                    Error = $_.Exception.Message
                    Source = "File"
                }
            }
        } else {
            return @{
                Success = $false
                Error = "File not found"
                Source = "File"
            }
        }
    }
}

function Convert-ScanConfigFromJson {
    <#
    .SYNOPSIS
    Converts JSON configuration object to hashtables for profiles and workflows.

    .DESCRIPTION
    Helper function to avoid code duplication when converting loaded JSON config.
    Handles both new format (with profiles/workflows keys) and old format (root level).
    #>
    param($LoadedConfig)

    # Convert profiles
    $profiles = @{}
    if ($LoadedConfig.PSObject.Properties.Name -contains 'profiles') {
        foreach ($prop in $LoadedConfig.profiles.PSObject.Properties) {
            $profiles[$prop.Name] = @{
                name = $prop.Value.name
                description = $prop.Value.description
                command = $prop.Value.command
            }
        }
    } else {
        # Old format: root level profiles
        foreach ($prop in $LoadedConfig.PSObject.Properties) {
            if ($prop.Name -ne 'workflows') {
                $profiles[$prop.Name] = @{
                    name = $prop.Value.name
                    description = $prop.Value.description
                    command = $prop.Value.command
                }
            }
        }
    }

    # Convert workflows
    $workflows = @{}
    if ($LoadedConfig.PSObject.Properties.Name -contains 'workflows') {
        foreach ($prop in $LoadedConfig.workflows.PSObject.Properties) {
            $steps = @()
            foreach ($step in $prop.Value.steps) {
                $steps += @{
                    profile = $step.profile
                    description = $step.description
                    condition = if ($step.PSObject.Properties.Name -contains 'condition') { $step.condition } else { "always" }
                }
            }
            $workflows[$prop.Name] = @{
                name = $prop.Value.name
                description = $prop.Value.description
                steps = $steps
            }
        }
    }

    return @{
        profiles = $profiles
        workflows = $workflows
    }
}

function Load-ScanConfiguration {
    param(
        [string]$ConfigFile
    )

    # Default profiles
    $defaultProfiles = @{
        "tcp-1000" = @{
            name = "TCP Top 1000 Ports"
            description = "Fast TCP scan of top 1000 ports with scripts and version detection"
            command = "nmap -v -T4 -Pn -open -sS --script=default,vuln -A --host-timeout 60m"
        }
        "tcp-full" = @{
            name = "TCP Full Port Scan"
            description = "Complete TCP scan of all 65535 ports"
            command = "nmap -v -T4 -Pn -open -sS --script=default,vuln -A --host-timeout 60m -p-"
        }
        "udp-common" = @{
            name = "UDP Common Ports"
            description = "UDP scan of most common ports"
            command = "nmap -v -T4 -Pn -sU -sV -A --host-timeout 60m -p '53,67,69,11,123,137,161,500,514,520,563'"
        }
        "udp-1000" = @{
            name = "UDP Top 1000 Ports"
            description = "UDP scan of top 1000 ports"
            command = "nmap -v -T4 -Pn -sU -sV -A --host-timeout 60m"
        }
        "udp-full" = @{
            name = "UDP Full Port Scan"
            description = "Complete UDP scan of all 65535 ports"
            command = "nmap -v -T4 -Pn -sU -sV -A --host-timeout 60m -p-"
        }
    }

    # Default workflows
    $defaultWorkflows = @{
        "full-discovery" = @{
            name = "Full Discovery Workflow"
            description = "Complete host discovery: quick TCP scan -> full TCP scan -> common UDP ports"
            steps = @(
                @{
                    profile = "tcp-1000"
                    description = "Quick TCP port discovery"
                    condition = "always"
                },
                @{
                    profile = "tcp-full"
                    description = "Full TCP port scan"
                    condition = "previous_success"
                },
                @{
                    profile = "udp-common"
                    description = "Common UDP ports"
                    condition = "previous_success"
                }
            )
        }
    }

    # Default configuration structure
    $defaultConfig = @{
        profiles = $defaultProfiles
        workflows = $defaultWorkflows
    }

    # Try to get configuration content (from URL or file)
    $configResult = Get-ConfigContent -ConfigPath $ConfigFile

    if ($configResult.Success) {
        try {
            $loadedConfig = $configResult.Content | ConvertFrom-Json

            # Show source information
            if ($configResult.Source -eq "URL") {
                Write-Host "[INFO] Loaded configuration from URL" -ForegroundColor Green
            } else {
                Write-Host "[INFO] Loaded configuration from local file" -ForegroundColor Green
            }

            # Convert using helper function
            return Convert-ScanConfigFromJson -LoadedConfig $loadedConfig
        } catch {
            Write-Warning "Failed to parse configuration: $_"
            Write-Warning "Using default configuration"
            return $defaultConfig
        }
    } else {
        # Failed to get configuration
        if ($configResult.Source -eq "URL") {
            # URL failed - ask user what to do
            Write-Host ""
            Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
            Write-Host "║  ERROR: Failed to download configuration from URL            ║" -ForegroundColor Red
            Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
            Write-Host ""
            Write-Host "  URL: " -NoNewline -ForegroundColor Yellow
            Write-Host "$ConfigFile" -ForegroundColor White
            Write-Host "  Error: " -NoNewline -ForegroundColor Yellow
            Write-Host "$($configResult.Error)" -ForegroundColor Gray
            Write-Host ""

            Write-Host "What would you like to do?" -ForegroundColor Cyan
            Write-Host "  [1] Use default configuration (hardcoded profiles)" -ForegroundColor White
            Write-Host "  [2] Specify a local configuration file path" -ForegroundColor White
            Write-Host "  [3] Cancel execution" -ForegroundColor White
            Write-Host ""

            $choice = Read-Host "Select option [1-3]"

            switch ($choice) {
                "1" {
                    Write-Host "[INFO] Using default configuration" -ForegroundColor Green
                    return $defaultConfig
                }
                "2" {
                    Write-Host ""
                    $localPath = Read-Host "Enter path to local configuration file"

                    if ([string]::IsNullOrWhiteSpace($localPath)) {
                        Write-Host "[ERROR] No path specified. Using default configuration" -ForegroundColor DarkRed
                        return $defaultConfig
                    }

                    Write-Host "[INFO] Attempting to load: $localPath" -ForegroundColor Cyan
                    $localResult = Get-ConfigContent -ConfigPath $localPath

                    if ($localResult.Success) {
                        try {
                            $loadedConfig = $localResult.Content | ConvertFrom-Json
                            Write-Host "[INFO] Configuration loaded successfully from local file" -ForegroundColor Green
                            return Convert-ScanConfigFromJson -LoadedConfig $loadedConfig
                        } catch {
                            Write-Warning "Failed to parse local configuration: $_"
                            Write-Host "[INFO] Using default configuration" -ForegroundColor Yellow
                            return $defaultConfig
                        }
                    } else {
                        Write-Warning "Failed to load local configuration: $($localResult.Error)"
                        Write-Host "[INFO] Using default configuration" -ForegroundColor Yellow
                        return $defaultConfig
                    }
                }
                "3" {
                    Write-Host ""
                    Write-Host "[INFO] Execution cancelled by user" -ForegroundColor Yellow
                    Write-Host ""
                    return $null
                }
                default {
                    Write-Host "[WARNING] Invalid option. Using default configuration" -ForegroundColor Yellow
                    return $defaultConfig
                }
            }
        } else {
            # File not found - create default file
            try {
                $defaultConfig | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigFile -ErrorAction Stop
                Write-Host "[INFO] Created default scan configuration file: $ConfigFile" -ForegroundColor Green
                Write-Host "[WARNING] Default profiles use -sS (SYN scan) which requires administrator privileges." -ForegroundColor Yellow
                Write-Host "          Options:" -ForegroundColor Yellow
                Write-Host "          1. Use -Unprivileged parameter to auto-convert -sS to -sT" -ForegroundColor Yellow
                Write-Host "          2. Edit $ConfigFile to change -sS to -sT manually" -ForegroundColor Yellow
                Write-Host "          3. Create custom config and use -ConfigFile parameter" -ForegroundColor Yellow
            } catch {
                Write-Warning "Failed to create default configuration file: $_"
            }
            return $defaultConfig
        }
    }
}

function Invoke-NmapScan {
    param(
        [string]$Host,
        [string]$ScanCommand,
        [string]$OutputPath,
        [string]$FileName
    )

    try {
        # Construct full command
        $fullCommand = "$ScanCommand -oA `"$OutputPath\$FileName`" $Host"

        # Execute nmap using Start-Process for better security
        $processArgs = @{
            FilePath = "nmap"
            ArgumentList = ($ScanCommand -replace '^nmap\s+', '') + " -oA `"$OutputPath\$FileName`" $Host"
            Wait = $true
            NoNewWindow = $true
            RedirectStandardOutput = "$OutputPath\$FileName.stdout"
            RedirectStandardError = "$OutputPath\$FileName.stderr"
            PassThru = $true
        }

        $process = Start-Process @processArgs

        $errorOutput = if (Test-Path "$OutputPath\$FileName.stderr") {
            Get-Content "$OutputPath\$FileName.stderr" -Raw
        } else { "" }

        # Verify that nmap actually created output files
        $nmapFileExists = Test-Path "$OutputPath\$FileName.nmap"
        $exitCodeOk = $process.ExitCode -eq 0

        # Success only if exit code is 0 AND .nmap file exists
        $scanSuccess = $exitCodeOk -and $nmapFileExists

        # If exit code was 0 but no file, add to error
        if ($exitCodeOk -and -not $nmapFileExists) {
            $errorOutput = "Nmap exited with code 0 but did not generate output files. " + $errorOutput
        }

        return @{
            Success = $scanSuccess
            ExitCode = $process.ExitCode
            ErrorOutput = $errorOutput
        }
    } catch {
        return @{
            Success = $false
            ExitCode = -1
            ErrorOutput = $_.Exception.Message
        }
    }
}

# Global ScriptBlock for nmap scan jobs (reusable across retry and initial scans)
$Global:NmapScanScriptBlock = {
    param($TargetHost, $ScanCommand, $OutputPath, $FileName, $Attempts, $Unprivileged)

    $startTime = Get-Date

    # Execute scan - Build argument list properly
    $nmapArgs = @()

    # Parse command into arguments (handle quoted strings)
    $cmdWithoutNmap = $ScanCommand -replace '^nmap\s+', ''
    $regex = [regex]'(?:[^\s"'']+|"[^"]*"|''[^'']*'')+'
    $matches = $regex.Matches($cmdWithoutNmap)
    foreach ($match in $matches) {
        $arg = $match.Value.Trim('"').Trim("'")
        # Replace -sS with -sT if unprivileged mode is enabled
        if ($Unprivileged -and $arg -eq "-sS") {
            $nmapArgs += "-sT"
        } else {
            $nmapArgs += $arg
        }
    }

    # Add --unprivileged if specified
    if ($Unprivileged) {
        $nmapArgs += "--unprivileged"
    }

    # Add output and target (quote the path if it contains spaces)
    $outputFullPath = "$OutputPath\$FileName"
    if ($outputFullPath -match '\s') {
        $nmapArgs += @("-oA", "`"$outputFullPath`"", $TargetHost)
    } else {
        $nmapArgs += @("-oA", $outputFullPath, $TargetHost)
    }

    $processArgs = @{
        FilePath = "nmap"
        ArgumentList = $nmapArgs
        Wait = $true
        NoNewWindow = $true
        RedirectStandardOutput = "$OutputPath\$FileName.stdout"
        RedirectStandardError = "$OutputPath\$FileName.stderr"
        PassThru = $true
    }

    try {
        $process = Start-Process @processArgs
        $endTime = Get-Date
        $duration = $endTime - $startTime

        $errorOutput = if (Test-Path "$OutputPath\$FileName.stderr") {
            Get-Content "$OutputPath\$FileName.stderr" -Raw
        } else { "" }

        # Add exit code to error message for debugging
        $exitCode = $process.ExitCode
        if ($exitCode -ne 0) {
            $errorOutput = "Nmap exited with code $exitCode. " + $errorOutput
        }

        # Verify that nmap actually created output files
        $nmapFileExists = Test-Path "$OutputPath\$FileName.nmap"
        $exitCodeOk = $exitCode -eq 0

        # Success only if exit code is 0 AND .nmap file exists
        $scanSuccess = $exitCodeOk -and $nmapFileExists

        # If exit code was 0 but no file, add to error
        if ($exitCodeOk -and -not $nmapFileExists) {
            $errorOutput = "Nmap exited with code 0 but did not generate output files. " + $errorOutput
        }

        # If no error message but scan failed, add generic message
        if (-not $scanSuccess -and [string]::IsNullOrWhiteSpace($errorOutput)) {
            $errorOutput = "Nmap scan failed. Exit code: $exitCode. No stderr output captured. Check nmap installation and permissions."
        }

        return @{
            Success = $scanSuccess
            StartTime = $startTime.ToString("yyyy-MM-ddTHH:mm:ss")
            EndTime = $endTime.ToString("yyyy-MM-ddTHH:mm:ss")
            Duration = "{0:mm}m {0:ss}s" -f $duration
            DurationSeconds = [int]$duration.TotalSeconds
            Error = $errorOutput
            Attempts = $Attempts
        }
    } catch {
        $endTime = Get-Date
        $duration = $endTime - $startTime

        return @{
            Success = $false
            StartTime = $startTime.ToString("yyyy-MM-ddTHH:mm:ss")
            EndTime = $endTime.ToString("yyyy-MM-ddTHH:mm:ss")
            Duration = "{0:mm}m {0:ss}s" -f $duration
            DurationSeconds = [int]$duration.TotalSeconds
            Error = $_.Exception.Message
            Attempts = $Attempts
        }
    }
}

function Start-NmapScanJob {
    param(
        [string]$TargetHost,
        [string]$ScanCommand,
        [string]$OutputPath,
        [string]$FileName,
        [int]$Attempts,
        [bool]$Unprivileged
    )

    return Start-Job -ScriptBlock $Global:NmapScanScriptBlock -ArgumentList $TargetHost, $ScanCommand, $OutputPath, $FileName, $Attempts, $Unprivileged
}

function Test-SessionName {
    param(
        [string]$Name
    )

    # Validations
    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    # Minimum length: 3 characters
    if ($Name.Length -lt 3) {
        return $false
    }

    # Maximum length: 50 characters
    if ($Name.Length -gt 50) {
        return $false
    }

    # Only allow alphanumeric, hyphens, underscores (no leading numbers)
    if ($Name -notmatch '^[a-zA-Z][a-zA-Z0-9_-]*$') {
        return $false
    }

    return $true
}

function Initialize-Session {
    param(
        [string]$SessionName,
        [string]$OutputDir,
        [string]$ScanType,
        [string]$Workflow
    )

    $sessionsDir = Join-Path $OutputDir ".sessions"
    $sessionDir = Join-Path $sessionsDir $SessionName

    # Create .sessions directory if it doesn't exist
    if (-not (Test-Path $sessionsDir)) {
        New-Item -ItemType Directory -Path $sessionsDir -Force | Out-Null
    }

    # Create session directory
    if (-not (Test-Path $sessionDir)) {
        New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null
    }

    return $sessionDir
}

function Get-SessionList {
    param(
        [string]$OutputDir
    )

    $sessionsDir = Join-Path $OutputDir ".sessions"

    # Check if .sessions directory exists
    if (-not (Test-Path $sessionsDir)) {
        Write-Host "`nNo se encontraron sesiones en: " -NoNewline -ForegroundColor Yellow
        Write-Host "$OutputDir" -ForegroundColor White
        Write-Host ""
        Write-Host "El directorio " -NoNewline -ForegroundColor Gray
        Write-Host ".sessions/" -NoNewline -ForegroundColor Cyan
        Write-Host " no existe en este directorio." -ForegroundColor Gray
        Write-Host ""
        Write-Host "Sugerencias:" -ForegroundColor Cyan
        Write-Host "  • Usa " -NoNewline -ForegroundColor Gray
        Write-Host "-OutputDir <directorio>" -NoNewline -ForegroundColor Yellow
        Write-Host " para buscar en un directorio diferente" -ForegroundColor Gray
        Write-Host "  • Usa " -NoNewline -ForegroundColor Gray
        Write-Host "-SessionName <nombre>" -NoNewline -ForegroundColor Yellow
        Write-Host " para crear una nueva sesión con nombre" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Ejemplo:" -ForegroundColor Cyan
        Write-Host "  .\scanyx.ps1 -ListSessions -OutputDir <tu-directorio>" -ForegroundColor White
        Write-Host ""
        return @()
    }

    # Get all session directories
    $sessionDirs = Get-ChildItem -Path $sessionsDir -Directory

    if ($sessionDirs.Count -eq 0) {
        Write-Host "`nNo se encontraron sesiones en: " -NoNewline -ForegroundColor Yellow
        Write-Host "$OutputDir" -ForegroundColor White
        Write-Host ""
        Write-Host "El directorio existe pero no contiene sesiones." -ForegroundColor Gray
        Write-Host ""
        Write-Host "Sugerencias:" -ForegroundColor Cyan
        Write-Host "  • Usa " -NoNewline -ForegroundColor Gray
        Write-Host "-SessionName <nombre>" -NoNewline -ForegroundColor Yellow
        Write-Host " para crear una nueva sesión con nombre" -ForegroundColor Gray
        Write-Host ""
        return @()
    }

    $sessions = @()

    foreach ($dir in $sessionDirs) {
        $stateFile = Join-Path $dir.FullName "scan-state.json"

        if (Test-Path $stateFile) {
            try {
                $state = Get-Content $stateFile -Raw | ConvertFrom-Json

                $elapsed = 0
                if ($state.start_time) {
                    $startTime = [DateTime]::Parse($state.start_time)
                    if ($state.end_time) {
                        $endTime = [DateTime]::Parse($state.end_time)
                        $elapsed = ($endTime - $startTime).TotalSeconds
                    } else {
                        $elapsed = ((Get-Date) - $startTime).TotalSeconds
                    }
                }

                $sessions += [PSCustomObject]@{
                    Name = $dir.Name
                    Type = if ($state.workflow) { "Workflow: $($state.workflow)" } else { $state.scan_type }
                    Status = $state.status
                    Total = if ($state.total_hosts) { $state.total_hosts } else { $state.hosts.Count }
                    Completed = if ($state.completed) { $state.completed } else { 0 }
                    Failed = if ($state.failed) { $state.failed } else { 0 }
                    Pending = if ($state.pending) { $state.pending } else { 0 }
                    StartTime = $state.start_time
                    EndTime = $state.end_time
                    ElapsedSeconds = [int]$elapsed
                    StateFile = $stateFile
                }
            } catch {
                Write-Warning "Failed to load session state: $($dir.Name)"
            }
        }
    }

    # Sort by start time (most recent first)
    $sessions = $sessions | Sort-Object StartTime -Descending

    return $sessions
}

function Show-SessionList {
    param(
        [array]$Sessions,
        [switch]$SuppressHeader
    )

    if (-not $SuppressHeader) {
        Write-Host "`nAvailable Sessions in: " -NoNewline -ForegroundColor Cyan
        Write-Host "$OutputDir`n" -ForegroundColor White
    }

    foreach ($session in $Sessions) {
        # Format duration
        $duration = ""
        if ($session.ElapsedSeconds -gt 0) {
            $hours = [math]::Floor($session.ElapsedSeconds / 3600)
            $minutes = [math]::Floor(($session.ElapsedSeconds % 3600) / 60)
            $seconds = $session.ElapsedSeconds % 60

            if ($hours -gt 0) {
                $duration = "${hours}h ${minutes}m"
            } elseif ($minutes -gt 0) {
                $duration = "${minutes}m ${seconds}s"
            } else {
                $duration = "${seconds}s"
            }
        }

        # Calculate progress percentage
        $progress = 0
        if ($session.Total -gt 0) {
            $progress = [math]::Round(($session.Completed / $session.Total) * 100, 1)
        }

        # Status color
        $statusColor = switch ($session.Status) {
            "completed" { "Green" }
            "in_progress" { "Yellow" }
            "interrupted" { "Cyan" }
            default { "Gray" }
        }

        Write-Host "┌─────────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
        Write-Host "│ Session: " -NoNewline -ForegroundColor Cyan
        Write-Host "$($session.Name)" -NoNewline -ForegroundColor White
        Write-Host (" " * (60 - $session.Name.Length)) -NoNewline
        Write-Host "│" -ForegroundColor Cyan
        Write-Host "├─────────────────────────────────────────────────────────────────────┤" -ForegroundColor Cyan

        Write-Host "│ Type       : " -NoNewline -ForegroundColor Cyan
        Write-Host "$($session.Type)" -NoNewline -ForegroundColor White
        Write-Host (" " * (56 - $session.Type.Length)) -NoNewline
        Write-Host "│" -ForegroundColor Cyan

        Write-Host "│ Status     : " -NoNewline -ForegroundColor Cyan
        Write-Host "$($session.Status)" -NoNewline -ForegroundColor $statusColor
        Write-Host (" " * (56 - $session.Status.Length)) -NoNewline
        Write-Host "│" -ForegroundColor Cyan

        $progressLine = "$($session.Completed)/$($session.Total) ($progress%) | Success: $($session.Completed) | Failed: $($session.Failed)"
        Write-Host "│ Progress   : " -NoNewline -ForegroundColor Cyan
        Write-Host "$progressLine" -NoNewline -ForegroundColor White
        Write-Host (" " * (56 - $progressLine.Length)) -NoNewline
        Write-Host "│" -ForegroundColor Cyan

        if ($session.StartTime) {
            $startFormatted = ([DateTime]::Parse($session.StartTime)).ToString("yyyy-MM-dd HH:mm:ss")
            Write-Host "│ Started    : " -NoNewline -ForegroundColor Cyan
            Write-Host "$startFormatted" -NoNewline -ForegroundColor White
            Write-Host (" " * (56 - $startFormatted.Length)) -NoNewline
            Write-Host "│" -ForegroundColor Cyan
        }

        if ($session.Status -eq "completed" -and $session.EndTime) {
            Write-Host "│ Duration   : " -NoNewline -ForegroundColor Cyan
            Write-Host "$duration" -NoNewline -ForegroundColor White
            Write-Host (" " * (56 - $duration.Length)) -NoNewline
            Write-Host "│" -ForegroundColor Cyan
        } elseif ($session.Status -eq "in_progress") {
            Write-Host "│ Elapsed    : " -NoNewline -ForegroundColor Cyan
            Write-Host "$duration" -NoNewline -ForegroundColor White
            Write-Host (" " * (56 - $duration.Length)) -NoNewline
            Write-Host "│" -ForegroundColor Cyan
        }

        $relativePath = $session.StateFile.Replace($OutputDir, "").TrimStart('\')
        # Truncate path if too long
        if ($relativePath.Length -gt 56) {
            $relativePath = "..." + $relativePath.Substring($relativePath.Length - 53)
        }
        Write-Host "│ State File : " -NoNewline -ForegroundColor Cyan
        Write-Host "$relativePath" -NoNewline -ForegroundColor Gray
        $padding = [Math]::Max(0, 56 - $relativePath.Length)
        Write-Host (" " * $padding) -NoNewline
        Write-Host "│" -ForegroundColor Cyan

        Write-Host "└─────────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
        Write-Host ""
    }

    if (-not $SuppressHeader) {
        Write-Host "Total: " -NoNewline -ForegroundColor Cyan
        Write-Host "$($Sessions.Count) session(s) found`n" -ForegroundColor White
    }
}

function Get-SessionState {
    param(
        [string]$SessionName,
        [string]$OutputDir
    )

    $sessionsDir = Join-Path $OutputDir ".sessions"
    $sessionDir = Join-Path $sessionsDir $SessionName
    $stateFile = Join-Path $sessionDir "scan-state.json"

    if (-not (Test-Path $sessionDir)) {
        Write-Host "`n[ERROR] Session '$SessionName' not found" -ForegroundColor DarkRed
        Write-Host "Available sessions:" -ForegroundColor Yellow
        $sessions = Get-SessionList -OutputDir $OutputDir
        if ($sessions.Count -gt 0) {
            foreach ($s in $sessions) {
                Write-Host "  - $($s.Name)" -ForegroundColor Gray
            }
        }
        Write-Host "`nTip: Use -ListSessions to see all available sessions`n" -ForegroundColor Gray
        return $null
    }

    if (-not (Test-Path $stateFile)) {
        Write-Host "`n[ERROR] Session state file not found for session '$SessionName'" -ForegroundColor DarkRed
        Write-Host "State file expected at: $stateFile`n" -ForegroundColor Gray
        return $null
    }

    try {
        $state = Load-StateFile -StateFile $stateFile
        return @{
            State = $state
            SessionDir = $sessionDir
            StateFile = $stateFile
        }
    } catch {
        Write-Host "`n[ERROR] Failed to load session state: $($_.Exception.Message)`n" -ForegroundColor DarkRed
        return $null
    }
}

function Show-ScanyxBanner {
    <#
    .SYNOPSIS
    Displays the SCANYX ASCII art banner with branding.

    .DESCRIPTION
    Centralized function to display the SCANYX banner consistently across the script.
    Used in: main script start, wizard headers, and summary sections.
    #>
    Write-Host ""
    Write-Host " ░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░" -ForegroundColor Red
    Write-Host "░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░" -ForegroundColor Red
    Write-Host "░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░" -ForegroundColor Red
    Write-Host " ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░ " -ForegroundColor Red
    Write-Host "       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░" -ForegroundColor Red
    Write-Host "       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░" -ForegroundColor Red
    Write-Host "░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░" -ForegroundColor Red
    Write-Host ""
    Write-Host "                   https://github.com/xtormin/Scanyx (v2.8.1)" -ForegroundColor Red
    Write-Host "                           @xtormin (Jennifer Torres)" -ForegroundColor Red
    Write-Host ""
}

#region Wizard Functions

function Show-WizardHeader {
    param([string]$Title, [int]$Step, [int]$TotalSteps)

    Clear-Host
    Show-ScanyxBanner
    Write-Host "╭─────────────────────────────────────────────────────────────────────────────╮" -ForegroundColor Cyan
    Write-Host "│ INTERACTIVE CONFIGURATION                                                   │" -ForegroundColor Cyan
    Write-Host "╰─────────────────────────────────────────────────────────────────────────────╯" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Step " -NoNewline -ForegroundColor White
    Write-Host "$Step" -NoNewline -ForegroundColor Yellow
    Write-Host " of " -NoNewline -ForegroundColor White
    Write-Host "$TotalSteps" -NoNewline -ForegroundColor Yellow
    Write-Host " - " -NoNewline -ForegroundColor White
    Write-Host "$Title" -ForegroundColor Cyan
    Write-Host ""
}

function Get-ScanTypeChoice {
    param([hashtable]$Profiles)

    Write-Host "  Scan profiles:" -ForegroundColor White
    Write-Host ""

    $index = 1
    $profileList = @()
    foreach ($key in $Profiles.Keys | Sort-Object) {
        $scanProfile = $Profiles[$key]
        Write-Host "    [$index] " -NoNewline -ForegroundColor Yellow
        Write-Host "$($scanProfile.name)" -NoNewline -ForegroundColor White
        Write-Host " - $($scanProfile.description)" -ForegroundColor Gray
        $profileList += $key
        $index++
    }

    Write-Host ""
    Write-Host "  Select scan type [1-$($profileList.Count)]: " -NoNewline -ForegroundColor Cyan

    $selection = Read-Host

    if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $profileList.Count) {
        return $profileList[[int]$selection - 1]
    } else {
        Write-Host ""
        Write-Host "  [ERROR] Invalid selection. Using default profile: tcp-1000" -ForegroundColor DarkRed
        Start-Sleep -Seconds 2
        return "tcp-1000"
    }
}

function Get-WorkflowChoice {
    param([hashtable]$Workflows)

    Write-Host "  Do you want to run a workflow (multiple scans in sequence)? [Y/n]: " -NoNewline -ForegroundColor Cyan
    $useWorkflow = Read-Host

    if ($useWorkflow -eq "" -or $useWorkflow -match '^[Yy]') {
        Write-Host ""
        Write-Host "  Available workflows:" -ForegroundColor White
        Write-Host ""

        $index = 1
        $workflowList = @()
        foreach ($key in $Workflows.Keys | Sort-Object) {
            $workflow = $Workflows[$key]
            Write-Host "    [$index] " -NoNewline -ForegroundColor Yellow
            Write-Host "$($workflow.name)" -NoNewline -ForegroundColor White
            Write-Host " - $($workflow.description)" -ForegroundColor Gray
            $workflowList += $key
            $index++
        }

        Write-Host ""
        Write-Host "  Select workflow [1-$($workflowList.Count)] or Enter to cancel: " -NoNewline -ForegroundColor Cyan
        $selection = Read-Host

        if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $workflowList.Count) {
            return $workflowList[[int]$selection - 1]
        }
    }

    return $null
}

function Get-HostFileInput {
    Write-Host "  Host file path (or Enter to specify hosts directly): " -NoNewline -ForegroundColor Cyan
    $hostFile = Read-Host

    if ($hostFile -ne "" -and -not (Test-Path $hostFile)) {
        Write-Host ""
        Write-Host "  [WARNING] File does not exist: $hostFile" -ForegroundColor Yellow
        Write-Host "  Continue anyway? [y/N]: " -NoNewline -ForegroundColor Cyan
        $continue = Read-Host
        if ($continue -notmatch '^[Yy]') {
            return ""
        }
    }

    return $hostFile
}

function Get-DirectHostsInput {
    Write-Host "  Hosts to scan (comma-separated - IPs, CIDRs or hostnames):" -ForegroundColor Cyan
    Write-Host "  Example: 192.168.1.0/24,10.0.0.50,server.example.com" -ForegroundColor Gray
    Write-Host "  > " -NoNewline -ForegroundColor Cyan
    $hostsInput = Read-Host

    if ($hostsInput -ne "") {
        return $hostsInput -split ',' | ForEach-Object { $_.Trim() }
    }

    return @()
}

function Get-SessionNameInput {
    Write-Host "  Custom session name (optional): " -NoNewline -ForegroundColor Cyan
    $sessionName = Read-Host

    if ($sessionName -ne "") {
        # Validate session name
        $isValid = Test-SessionName -Name $sessionName
        if (-not $isValid) {
            Write-Host ""
            Write-Host "  [ERROR] Invalid session name. Must be 3-50 chars, start with letter, only letters/numbers/hyphens/underscores allowed." -ForegroundColor DarkRed
            Start-Sleep -Seconds 2
            return ""
        }
    }

    return $sessionName
}

function Get-ExclusionInput {
    Write-Host "  Exclude some hosts from scan? [y/N]: " -NoNewline -ForegroundColor Cyan
    $exclude = Read-Host

    $result = @{
        ExcludeFile = ""
        ExcludeHosts = @()
        ResolveHostnames = $false
    }

    if ($exclude -match '^[Yy]') {
        Write-Host ""
        Write-Host "  Exclusion file (or Enter to specify hosts directly): " -NoNewline -ForegroundColor Cyan
        $excludeFile = Read-Host

        if ($excludeFile -eq "") {
            Write-Host "  Hosts to exclude (comma-separated): " -NoNewline -ForegroundColor Cyan
            $excludeHosts = Read-Host
            if ($excludeHosts -ne "") {
                $result.ExcludeHosts = $excludeHosts -split ',' | ForEach-Object { $_.Trim() }
            }
        } else {
            $result.ExcludeFile = $excludeFile
        }

        Write-Host "  Resolve hostnames for exclusions? [y/N]: " -NoNewline -ForegroundColor Cyan
        $resolve = Read-Host
        $result.ResolveHostnames = ($resolve -match '^[Yy]')
    }

    return $result
}

function Get-SensitiveHostsInput {
    Write-Host "  Are there sensitive hosts requiring careful scanning? [y/N]: " -NoNewline -ForegroundColor Cyan
    $sensitive = Read-Host

    $result = @{
        SensitiveFile = ""
        SensitiveHosts = @()
        SensitiveTiming = "T2"
        SensitiveScripts = "default"
    }

    if ($sensitive -match '^[Yy]') {
        Write-Host ""
        Write-Host "  Sensitive hosts file (or Enter to specify directly): " -NoNewline -ForegroundColor Cyan
        $sensitiveFile = Read-Host

        if ($sensitiveFile -eq "") {
            Write-Host "  Sensitive hosts (comma-separated): " -NoNewline -ForegroundColor Cyan
            $sensitiveHosts = Read-Host
            if ($sensitiveHosts -ne "") {
                $result.SensitiveHosts = $sensitiveHosts -split ',' | ForEach-Object { $_.Trim() }
            }
        } else {
            $result.SensitiveFile = $sensitiveFile
        }

        Write-Host ""
        Write-Host "  Timing for sensitive hosts [T0-T4, default: T2]: " -NoNewline -ForegroundColor Cyan
        $timing = Read-Host
        if ($timing -match '^T[0-4]$') {
            $result.SensitiveTiming = $timing
        }

        Write-Host "  NSE scripts [default/vuln/none/default+vuln, default: default]: " -NoNewline -ForegroundColor Cyan
        $scripts = Read-Host
        if ($scripts -in @("default", "vuln", "none", "default+vuln")) {
            $result.SensitiveScripts = $scripts
        }
    }

    return $result
}

function Get-PerformanceSettings {
    $result = @{
        MaxConcurrent = 5
        MaxRetries = 1
        RetryDelay = 60
    }

    Write-Host "  Maximum concurrent scans [1-50, default: 5]: " -NoNewline -ForegroundColor Cyan
    $concurrent = Read-Host
    if ($concurrent -match '^\d+$' -and [int]$concurrent -ge 1 -and [int]$concurrent -le 50) {
        $result.MaxConcurrent = [int]$concurrent
    }

    Write-Host "  Maximum retries for failed scans [0-10, default: 1]: " -NoNewline -ForegroundColor Cyan
    $retries = Read-Host
    if ($retries -match '^\d+$' -and [int]$retries -ge 0 -and [int]$retries -le 10) {
        $result.MaxRetries = [int]$retries
    }

    Write-Host "  Delay between retries in seconds [0-3600, default: 60]: " -NoNewline -ForegroundColor Cyan
    $delay = Read-Host
    if ($delay -match '^\d+$' -and [int]$delay -ge 0 -and [int]$delay -le 3600) {
        $result.RetryDelay = [int]$delay
    }

    return $result
}

function Get-OutputSettings {
    $result = @{
        OutputDir = "nmap"
        OverwriteMode = "Ask"
        VerboseMode = $false
    }

    Write-Host "  Output directory [default: nmap]: " -NoNewline -ForegroundColor Cyan
    $outputDir = Read-Host
    if ($outputDir -ne "") {
        $result.OutputDir = $outputDir
    }

    Write-Host "  Overwrite mode [Skip/Overwrite/Ask, default: Ask]: " -NoNewline -ForegroundColor Cyan
    $overwrite = Read-Host
    if ($overwrite -in @("Skip", "Overwrite", "Ask")) {
        $result.OverwriteMode = $overwrite
    }

    Write-Host "  Enable verbose mode (show full nmap commands)? [y/N]: " -NoNewline -ForegroundColor Cyan
    $verbose = Read-Host
    $result.VerboseMode = ($verbose -match '^[Yy]')

    return $result
}

function Get-AdvancedOptions {
    $result = @{
        Unprivileged = $false
        ConfigFile = ""
    }

    Write-Host "  ¿Usar modo no privilegiado (--unprivileged)? [s/N]: " -NoNewline -ForegroundColor Cyan
    $unprivileged = Read-Host
    $result.Unprivileged = ($unprivileged -match '^[Ss]')

    Write-Host "  Archivo de configuración personalizado (opcional): " -NoNewline -ForegroundColor Cyan
    $configFile = Read-Host
    if ($configFile -ne "") {
        $result.ConfigFile = $configFile
    }

    return $result
}

function Show-WizardSummary {
    param([hashtable]$Config)

    Write-Host ""
    Write-Host "╭─────────────────────────────────────────────────────────────────────────────╮" -ForegroundColor Cyan
    Write-Host "│ RESUMEN DE CONFIGURACIÓN                                                    │" -ForegroundColor Cyan
    Write-Host "╰─────────────────────────────────────────────────────────────────────────────╯" -ForegroundColor Cyan
    Write-Host ""

    if ($Config.Workflow) {
        Write-Host "  Workflow       : " -NoNewline -ForegroundColor White
        Write-Host "$($Config.Workflow)" -ForegroundColor Yellow
    } else {
        Write-Host "  Tipo de Escaneo: " -NoNewline -ForegroundColor White
        Write-Host "$($Config.ScanType)" -ForegroundColor Yellow
    }

    if ($Config.HostFile) {
        Write-Host "  Archivo Hosts  : " -NoNewline -ForegroundColor White
        Write-Host "$($Config.HostFile)" -ForegroundColor Green
    }

    if ($Config.Hosts.Count -gt 0) {
        Write-Host "  Hosts Directos : " -NoNewline -ForegroundColor White
        Write-Host "$($Config.Hosts.Count) host(s)" -ForegroundColor Green
    }

    if ($Config.SessionName) {
        Write-Host "  Nombre Sesión  : " -NoNewline -ForegroundColor White
        Write-Host "$($Config.SessionName)" -ForegroundColor Magenta
    }

    if ($Config.ExcludeFile -or $Config.ExcludeHosts.Count -gt 0) {
        Write-Host "  Exclusiones    : " -NoNewline -ForegroundColor White
        if ($Config.ExcludeFile) {
            Write-Host "$($Config.ExcludeFile)" -ForegroundColor Red
        } else {
            Write-Host "$($Config.ExcludeHosts.Count) host(s)" -ForegroundColor Red
        }
    }

    if ($Config.SensitiveFile -or $Config.SensitiveHosts.Count -gt 0) {
        Write-Host "  Hosts Sensibles: " -NoNewline -ForegroundColor White
        if ($Config.SensitiveFile) {
            Write-Host "$($Config.SensitiveFile)" -ForegroundColor Yellow
        } else {
            Write-Host "$($Config.SensitiveHosts.Count) host(s)" -ForegroundColor Yellow
        }
        Write-Host "    └─ Timing    : " -NoNewline -ForegroundColor Gray
        Write-Host "$($Config.SensitiveTiming)" -NoNewline -ForegroundColor White
        Write-Host " | Scripts: " -NoNewline -ForegroundColor Gray
        Write-Host "$($Config.SensitiveScripts)" -ForegroundColor White
    }

    Write-Host "  Concurrencia   : " -NoNewline -ForegroundColor White
    Write-Host "$($Config.MaxConcurrent)" -NoNewline -ForegroundColor Cyan
    Write-Host " | Reintentos: " -NoNewline -ForegroundColor White
    Write-Host "$($Config.MaxRetries)" -NoNewline -ForegroundColor Cyan
    Write-Host " | Delay: " -NoNewline -ForegroundColor White
    Write-Host "$($Config.RetryDelay)s" -ForegroundColor Cyan

    Write-Host "  Salida         : " -NoNewline -ForegroundColor White
    Write-Host "$($Config.OutputDir)" -NoNewline -ForegroundColor Green
    Write-Host " | Sobrescritura: " -NoNewline -ForegroundColor White
    Write-Host "$($Config.OverwriteMode)" -ForegroundColor Green

    if ($Config.VerboseMode) {
        Write-Host "  Modo Verbose   : " -NoNewline -ForegroundColor White
        Write-Host "Activado" -ForegroundColor Yellow
    }

    if ($Config.Unprivileged) {
        Write-Host "  No Privilegiado: " -NoNewline -ForegroundColor White
        Write-Host "Activado" -ForegroundColor Yellow
    }

    Write-Host ""
}

function New-CommandString {
    param([hashtable]$Config)

    $cmd = ".\scanyx.ps1"

    # Scan type or workflow
    if ($Config.Workflow) {
        $cmd += " -Workflow `"$($Config.Workflow)`""
    } else {
        $cmd += " -ScanType `"$($Config.ScanType)`""
    }

    # Hosts
    if ($Config.HostFile) {
        $cmd += " -HostFile `"$($Config.HostFile)`""
    }

    if ($Config.Hosts.Count -gt 0) {
        $hostsStr = ($Config.Hosts | ForEach-Object { "`"$_`"" }) -join ","
        $cmd += " -Hosts $hostsStr"
    }

    # Session name
    if ($Config.SessionName) {
        $cmd += " -SessionName `"$($Config.SessionName)`""
    }

    # Exclusions
    if ($Config.ExcludeFile) {
        $cmd += " -ExcludeFile `"$($Config.ExcludeFile)`""
    }

    if ($Config.ExcludeHosts.Count -gt 0) {
        $excludeStr = ($Config.ExcludeHosts | ForEach-Object { "`"$_`"" }) -join ","
        $cmd += " -ExcludeHosts $excludeStr"
    }

    if ($Config.ResolveHostnames) {
        $cmd += " -ResolveHostnames"
    }

    # Sensitive hosts
    if ($Config.SensitiveFile) {
        $cmd += " -SensitiveFile `"$($Config.SensitiveFile)`""
    }

    if ($Config.SensitiveHosts.Count -gt 0) {
        $sensitiveStr = ($Config.SensitiveHosts | ForEach-Object { "`"$_`"" }) -join ","
        $cmd += " -SensitiveHosts $sensitiveStr"
    }

    if ($Config.SensitiveTiming -ne "T2") {
        $cmd += " -SensitiveTiming $($Config.SensitiveTiming)"
    }

    if ($Config.SensitiveScripts -ne "default") {
        $cmd += " -SensitiveScripts $($Config.SensitiveScripts)"
    }

    # Performance
    if ($Config.MaxConcurrent -ne 5) {
        $cmd += " -MaxConcurrent $($Config.MaxConcurrent)"
    }

    if ($Config.MaxRetries -ne 1) {
        $cmd += " -MaxRetries $($Config.MaxRetries)"
    }

    if ($Config.RetryDelay -ne 60) {
        $cmd += " -RetryDelay $($Config.RetryDelay)"
    }

    # Output
    if ($Config.OutputDir -ne "nmap") {
        $cmd += " -OutputDir `"$($Config.OutputDir)`""
    }

    if ($Config.OverwriteMode -ne "Ask") {
        $cmd += " -OverwriteMode $($Config.OverwriteMode)"
    }

    if ($Config.VerboseMode) {
        $cmd += " -VerboseMode"
    }

    # Advanced
    if ($Config.Unprivileged) {
        $cmd += " -Unprivileged"
    }

    if ($Config.ConfigFile) {
        $cmd += " -ConfigFile `"$($Config.ConfigFile)`""
    }

    return $cmd
}

function Show-GeneratedCommand {
    param([string]$Command)

    Write-Host "╭─────────────────────────────────────────────────────────────────────────────╮" -ForegroundColor Green
    Write-Host "│ COMANDO GENERADO                                                            │" -ForegroundColor Green
    Write-Host "╰─────────────────────────────────────────────────────────────────────────────╯" -ForegroundColor Green
    Write-Host ""
    Write-Host "  $Command" -ForegroundColor White
    Write-Host ""
    Write-Host "  Puedes copiar este comando para usarlo en futuras ejecuciones." -ForegroundColor Gray
    Write-Host ""
}

function Confirm-Execution {
    Write-Host "  ¿Deseas ejecutar este escaneo ahora? [S/n]: " -NoNewline -ForegroundColor Cyan
    $execute = Read-Host

    return ($execute -eq "" -or $execute -match '^[Ss]')
}

function Start-ScanWizard {
    param(
        [hashtable]$ScanProfiles,
        [hashtable]$Workflows
    )

    $config = @{
        ScanType = ""
        Workflow = ""
        HostFile = ""
        Hosts = @()
        SessionName = ""
        ExcludeFile = ""
        ExcludeHosts = @()
        ResolveHostnames = $false
        SensitiveFile = ""
        SensitiveHosts = @()
        SensitiveTiming = "T2"
        SensitiveScripts = "default"
        MaxConcurrent = 5
        MaxRetries = 1
        RetryDelay = 60
        OutputDir = "nmap"
        OverwriteMode = "Ask"
        VerboseMode = $false
        Unprivileged = $false
        ConfigFile = ""
    }

    # Step 1: Scan Type or Workflow
    Show-WizardHeader -Title "Tipo de Escaneo" -Step 1 -TotalSteps 10

    # Check if workflows are available
    if ($Workflows -and $Workflows.Count -gt 0) {
        $workflowChoice = Get-WorkflowChoice -Workflows $Workflows
        if ($workflowChoice) {
            $config.Workflow = $workflowChoice
        }
    }

    if (-not $config.Workflow) {
        $config.ScanType = Get-ScanTypeChoice -Profiles $ScanProfiles
    }

    # Step 2: Host Input
    Show-WizardHeader -Title "Hosts a Escanear" -Step 2 -TotalSteps 10
    $config.HostFile = Get-HostFileInput

    if ($config.HostFile -eq "") {
        $config.Hosts = Get-DirectHostsInput

        if ($config.Hosts.Count -eq 0) {
            Write-Host ""
            Write-Host "  [ERROR] Debes especificar al menos un host o archivo de hosts." -ForegroundColor DarkRed
            Write-Host "  Presiona Enter para salir del wizard..." -ForegroundColor Gray
            Read-Host
            return
        }
    }

    # Step 3: Session Name
    Show-WizardHeader -Title "Nombre de Sesión" -Step 3 -TotalSteps 10
    $config.SessionName = Get-SessionNameInput

    # Step 4: Exclusions
    Show-WizardHeader -Title "Exclusiones" -Step 4 -TotalSteps 10
    $exclusions = Get-ExclusionInput
    $config.ExcludeFile = $exclusions.ExcludeFile
    $config.ExcludeHosts = $exclusions.ExcludeHosts
    $config.ResolveHostnames = $exclusions.ResolveHostnames

    # Step 5: Sensitive Hosts
    Show-WizardHeader -Title "Hosts Sensibles" -Step 5 -TotalSteps 10
    $sensitive = Get-SensitiveHostsInput
    $config.SensitiveFile = $sensitive.SensitiveFile
    $config.SensitiveHosts = $sensitive.SensitiveHosts
    $config.SensitiveTiming = $sensitive.SensitiveTiming
    $config.SensitiveScripts = $sensitive.SensitiveScripts

    # Step 6: Performance Settings
    Show-WizardHeader -Title "Configuración de Rendimiento" -Step 6 -TotalSteps 10
    $performance = Get-PerformanceSettings
    $config.MaxConcurrent = $performance.MaxConcurrent
    $config.MaxRetries = $performance.MaxRetries
    $config.RetryDelay = $performance.RetryDelay

    # Step 7: Output Settings
    Show-WizardHeader -Title "Configuración de Salida" -Step 7 -TotalSteps 10
    $output = Get-OutputSettings
    $config.OutputDir = $output.OutputDir
    $config.OverwriteMode = $output.OverwriteMode
    $config.VerboseMode = $output.VerboseMode

    # Step 8: Advanced Options
    Show-WizardHeader -Title "Opciones Avanzadas" -Step 8 -TotalSteps 10
    $advanced = Get-AdvancedOptions
    $config.Unprivileged = $advanced.Unprivileged
    $config.ConfigFile = $advanced.ConfigFile

    # Step 9: Summary
    Show-WizardHeader -Title "Resumen" -Step 9 -TotalSteps 10
    Show-WizardSummary -Config $config

    # Step 10: Generate Command & Confirm
    Show-WizardHeader -Title "Confirmación" -Step 10 -TotalSteps 10
    $command = New-CommandString -Config $config
    Show-GeneratedCommand -Command $command

    $shouldExecute = Confirm-Execution

    if ($shouldExecute) {
        Write-Host ""
        Write-Host "  Iniciando escaneo..." -ForegroundColor Green
        Write-Host ""
        Start-Sleep -Seconds 2
        return $config
    } else {
        Write-Host ""
        Write-Host "  Escaneo cancelado. Comando guardado para referencia futura." -ForegroundColor Yellow
        Write-Host ""
        return
    }
}


# ============================================
# MAIN FUNCTION
# ============================================

function Invoke-Scanyx {
<#
.SYNOPSIS
SCANYX (Scan Analysis eXecution) - Advanced Nmap scanner with parallel execution and state persistence.

.DESCRIPTION
Main function to execute network scans using Nmap with advanced features.

.EXAMPLE
Invoke-Scanyx -HostFile hosts.txt -ScanType tcp-1000

.EXAMPLE
Invoke-Scanyx -Hosts "192.168.1.0/24" -ScanType tcp-full -MaxConcurrent 10
#>
    [CmdletBinding(DefaultParameterSetName='SingleScan')]
    param (
        # Path to the file containing the list of hosts to scan
        [Parameter(Mandatory = $false)]
        [string]$HostFile = "",

        # Array of hosts to scan (IPs, CIDRs, hostnames)
        [Parameter(Mandatory = $false)]
        [string[]]$Hosts = @(),

        # Type of scan to perform (loaded from nmap-profiles-workflows.json)
        [Parameter(Mandatory = $false, ParameterSetName='SingleScan')]
        [string]$ScanType = "",

        # Workflow to execute (multiple scans in sequence)
        [Parameter(Mandatory = $false, ParameterSetName='WorkflowScan')]
        [string]$Workflow = "",

        # Condition for workflow step execution
        [Parameter(Mandatory = $false)]
        [ValidateSet("always", "previous_success", "previous_has_results")]
        [string]$WorkflowCondition = "always",

        # File containing hosts to exclude from scanning
        [Parameter(Mandatory = $false)]
        [string]$ExcludeFile = "",

        # Array of hosts to exclude from scanning (IPs, CIDRs, hostnames)
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeHosts = @(),

        # Resolve hostnames to IPs for exclusion matching
        [Parameter(Mandatory = $false)]
        [switch]$ResolveHostnames,

        # File containing sensitive hosts to scan with reduced timing/scripts
        [Parameter(Mandatory = $false)]
        [string]$SensitiveFile = "",

        # Array of sensitive hosts (IPs, CIDRs, hostnames)
        [Parameter(Mandatory = $false)]
        [string[]]$SensitiveHosts = @(),

        # Timing template for sensitive hosts (T0-T4)
        [Parameter(Mandatory = $false)]
        [ValidateSet("T0", "T1", "T2", "T3", "T4")]
        [string]$SensitiveTiming = "T2",

        # NSE scripts for sensitive hosts
        [Parameter(Mandatory = $false)]
        [ValidateSet("default", "vuln", "none", "default+vuln")]
        [string]$SensitiveScripts = "default",

        # Output directory for scan results
        [Parameter(Mandatory = $false)]
        [string]$OutputDir = "nmap",

        # Maximum number of concurrent scans
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 50)]
        [int]$MaxConcurrent = 5,

        # Maximum number of retry attempts
        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 10)]
        [int]$MaxRetries = 1,

        # Delay between retry attempts (seconds)
        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 3600)]
        [int]$RetryDelay = 60,

        # Overwrite mode for existing results
        [Parameter(Mandatory = $false)]
        [ValidateSet("Skip", "Overwrite", "Ask")]
        [string]$OverwriteMode = "Ask",

        # Resume: Continue with pending hosts only
        [Parameter(Mandatory = $false)]
        [switch]$Resume,

        # Resume and retry failed hosts
        [Parameter(Mandatory = $false)]
        [switch]$ResumeRetryFailed,

        # Resume and retry dead hosts (completed but no open ports)
        [Parameter(Mandatory = $false)]
        [switch]$ResumeRetryDead,

        # Retry only failed hosts
        [Parameter(Mandatory = $false)]
        [switch]$RetryFailed,

        # Retry only dead hosts (skip pending, failed, and alive)
        [Parameter(Mandatory = $false)]
        [switch]$RetryDead,

        # Force fresh start (archive old state)
        [Parameter(Mandatory = $false)]
        [switch]$Force,

        # Use unprivileged mode for nmap scans (adds --unprivileged flag)
        [Parameter(Mandatory = $false)]
        [switch]$Unprivileged,

        # Path to custom scan profiles configuration file
        [Parameter(Mandatory = $false)]
        [string]$ConfigFile = "",

        # Enable verbose mode to show nmap commands
        [Parameter(Mandatory = $false)]
        [switch]$VerboseMode,

        # Session name (custom identifier for this scan session)
        [Parameter(Mandatory = $false)]
        [string]$SessionName = "",

        # List all available sessions
        [Parameter(Mandatory = $false)]
        [switch]$ListSessions,

        # Resume a specific session by name
        [Parameter(Mandatory = $false)]
        [string]$ResumeSession = "",

        # Interactive wizard mode to configure scan step-by-step
        [Parameter(Mandatory = $false)]
        [switch]$Wizard
    )

#region Functions

#region Main Script


# Script start
$scriptStartTime = Get-Date
$sessionId = (Get-Date -Format "yyyyMMdd-HHmmss") + "_session"

Show-ScanyxBanner

# Handle -ListSessions (exit early)
# Convert OutputDir to absolute path for -ListSessions
if ($ListSessions) {
    $resolvedOutputDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)
    $sessions = @(Get-SessionList -OutputDir $resolvedOutputDir)
    if ($sessions.Count -gt 0) {
        Show-SessionList -Sessions $sessions
    }
    return
}

# Convert OutputDir to absolute path to ensure it works in background jobs
$OutputDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)

# Validate Nmap installation
if (-not (Test-NmapInstalled)) {
    Write-Host "[ERROR] Nmap is not installed or not in PATH. Please install Nmap first." -ForegroundColor DarkRed
    return
}

# Load scan configuration (profiles and workflows)
# When loaded via IEX, $PSScriptRoot and $MyInvocation.MyCommand.Path are $null
# In that case, use current directory or rely on ConfigFile parameter
$scriptDir = if ($PSScriptRoot) {
    $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    Get-Location | Select-Object -ExpandProperty Path
}

if (-not $ConfigFile -or $ConfigFile -eq "") {
    $configFile = Join-Path $scriptDir "nmap-profiles-workflows.json"
} else {
    $configFile = $ConfigFile
}
$scanConfig = Load-ScanConfiguration -ConfigFile $configFile

# Check if user cancelled configuration load
if ($null -eq $scanConfig) {
    Write-Host "[INFO] Configuration load cancelled. Exiting..." -ForegroundColor Yellow
    return
}

$scanProfiles = $scanConfig.profiles
$scanWorkflows = $scanConfig.workflows

# Show configuration source info
if ($ConfigFile -and $ConfigFile -match '^https?://') {
    Write-Host "[INFO] Using remote configuration: $ConfigFile" -ForegroundColor Cyan
} elseif ($ConfigFile -and $ConfigFile -ne "") {
    Write-Host "[INFO] Using custom configuration: $ConfigFile" -ForegroundColor Cyan
}

# Handle -Wizard mode (interactive configuration)
if ($Wizard) {
    $wizardConfig = Start-ScanWizard -ScanProfiles $scanProfiles -Workflows $scanWorkflows

    # Apply wizard configuration to script parameters
    if ($wizardConfig.Workflow) {
        $Workflow = $wizardConfig.Workflow
    } else {
        $ScanType = $wizardConfig.ScanType
    }

    $HostFile = $wizardConfig.HostFile
    $Hosts = $wizardConfig.Hosts
    $SessionName = $wizardConfig.SessionName
    $ExcludeFile = $wizardConfig.ExcludeFile
    $ExcludeHosts = $wizardConfig.ExcludeHosts
    $ResolveHostnames = $wizardConfig.ResolveHostnames
    $SensitiveFile = $wizardConfig.SensitiveFile
    $SensitiveHosts = $wizardConfig.SensitiveHosts
    $SensitiveTiming = $wizardConfig.SensitiveTiming
    $SensitiveScripts = $wizardConfig.SensitiveScripts
    $MaxConcurrent = $wizardConfig.MaxConcurrent
    $MaxRetries = $wizardConfig.MaxRetries
    $RetryDelay = $wizardConfig.RetryDelay
    $OutputDir = $wizardConfig.OutputDir
    $OverwriteMode = $wizardConfig.OverwriteMode
    $VerboseMode = $wizardConfig.VerboseMode
    $Unprivileged = $wizardConfig.Unprivileged
    if ($wizardConfig.ConfigFile) {
        $ConfigFile = $wizardConfig.ConfigFile
        # Reload configuration if custom file was specified
        $scanConfig = Load-ScanConfiguration -ConfigFile $wizardConfig.ConfigFile

        # Check if user cancelled configuration load
        if ($null -eq $scanConfig) {
            Write-Host "[INFO] Configuration load cancelled. Exiting..." -ForegroundColor Yellow
            return
        }

        $scanProfiles = $scanConfig.profiles
        $scanWorkflows = $scanConfig.workflows
    }

    # Convert OutputDir to absolute path again after wizard updates
    $OutputDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)
}

# Validate mutually exclusive resume/retry/force parameters
$resumeParams = @($Resume.IsPresent, $ResumeRetryFailed.IsPresent, $ResumeRetryDead.IsPresent, $RetryFailed.IsPresent, $RetryDead.IsPresent, $Force.IsPresent)
$resumeParamsCount = ($resumeParams | Where-Object { $_ }).Count
if ($resumeParamsCount -gt 1) {
    Write-Host "[ERROR] Parameters -Resume, -ResumeRetryFailed, -ResumeRetryDead, -RetryFailed, -RetryDead, and -Force are mutually exclusive. Use only one." -ForegroundColor DarkRed
    return
}

# Validate SessionName if provided
if ($SessionName -and $SessionName -ne "") {
    $isValid = Test-SessionName -Name $SessionName
    if (-not $isValid) {
        Write-Host "[ERROR] Invalid session name" -ForegroundColor DarkRed
        Write-Host "`nSession name requirements:" -ForegroundColor Yellow
        Write-Host "  - 3-50 characters long" -ForegroundColor Gray
        Write-Host "  - Must start with a letter" -ForegroundColor Gray
        Write-Host "  - Only letters, numbers, hyphens (-), and underscores (_)" -ForegroundColor Gray
        Write-Host "`nExamples:" -ForegroundColor Yellow
        Write-Host "  -SessionName `"pentest-client-2025`"" -ForegroundColor Cyan
        Write-Host "  -SessionName `"weekly_scan_oct`"" -ForegroundColor Cyan
        Write-Host "  -SessionName `"infrastructure-audit-phase1`"`n" -ForegroundColor Cyan
        return
    }
}

# Handle -ResumeSession
$resumingSession = $false
$resumedSessionData = $null
if ($ResumeSession -and $ResumeSession -ne "") {
    Write-Host "[INFO] Resuming session: $ResumeSession" -ForegroundColor Cyan
    $resumedSessionData = Get-SessionState -SessionName $ResumeSession -OutputDir $OutputDir
    if ($null -eq $resumedSessionData) {
        return
    }
    $resumingSession = $true

    # Override sessionId with resumed session name
    $sessionId = $ResumeSession

    # Load scan configuration from session state
    $stateScanType = $null

    # Try to get scan_type from state root first
    if ($resumedSessionData.State.scan_type -and $resumedSessionData.State.scan_type -ne "") {
        $stateScanType = $resumedSessionData.State.scan_type
    } else {
        # Fallback: Find first host that has scan_type defined
        $hostWithScanType = $resumedSessionData.State.hosts.PSObject.Properties | Where-Object {
            $_.Value.scan_type -and $_.Value.scan_type -ne ""
        } | Select-Object -First 1

        if ($hostWithScanType -and $hostWithScanType.Value.scan_type) {
            $stateScanType = $hostWithScanType.Value.scan_type
            Write-Host "[INFO] Loaded scan type from host data: $stateScanType" -ForegroundColor Cyan
        }
    }

    # Check for workflow (though unlikely for this session)
    if ($resumedSessionData.State.workflow -and $resumedSessionData.State.workflow -ne "null" -and $resumedSessionData.State.workflow -ne "") {
        $Workflow = $resumedSessionData.State.workflow
        Write-Host "[INFO] Loaded workflow from session: $Workflow" -ForegroundColor Green
    } elseif ($stateScanType) {
        $ScanType = $stateScanType
        Write-Host "[INFO] Loaded scan type from session: $ScanType" -ForegroundColor Green
    } else {
        Write-Host "[WARNING] Could not load scan type or workflow from session state" -ForegroundColor Yellow
    }

    Write-Host "[INFO] Session loaded successfully" -ForegroundColor Green
}

# Validate that either ScanType or Workflow is provided (mutually exclusive)
# Skip this validation if resuming a session (will use session's config)
if (-not $resumingSession) {
if ((-not $ScanType -or $ScanType -eq "") -and (-not $Workflow -or $Workflow -eq "")) {
    Write-Host "[ERROR] Either -ScanType or -Workflow parameter must be provided." -ForegroundColor DarkRed
    Write-Host "`nAvailable scan profiles:" -ForegroundColor Yellow
    foreach ($profile in $scanProfiles.GetEnumerator() | Sort-Object Key) {
        Write-Host "  - $($profile.Key): $($profile.Value.name)" -ForegroundColor Cyan
    }
    Write-Host "`nAvailable workflows:" -ForegroundColor Yellow
    foreach ($wf in $scanWorkflows.GetEnumerator() | Sort-Object Key) {
        Write-Host "  - $($wf.Key): $($wf.Value.name)" -ForegroundColor Cyan
        Write-Host "    $($wf.Value.description)" -ForegroundColor Gray
    }
    return
}

if ($ScanType -and $ScanType -ne "" -and $Workflow -and $Workflow -ne "") {
    Write-Host "[ERROR] Cannot use both -ScanType and -Workflow. Choose one." -ForegroundColor DarkRed
    return
}

# Validate ScanType or Workflow
$isWorkflowMode = $false
if ($Workflow -and $Workflow -ne "") {
    $isWorkflowMode = $true
    if (-not $scanWorkflows.ContainsKey($Workflow)) {
        Write-Host "[ERROR] Invalid workflow: $Workflow" -ForegroundColor DarkRed
        Write-Host "`nAvailable workflows:" -ForegroundColor Yellow
        foreach ($wf in $scanWorkflows.GetEnumerator() | Sort-Object Key) {
            Write-Host "  - $($wf.Key): $($wf.Value.name)" -ForegroundColor Cyan
            Write-Host "    $($wf.Value.description)" -ForegroundColor Gray
        }
        Write-Host "`nYou can customize workflows by editing: $configFile`n" -ForegroundColor Yellow
        return
    }

    # Validate that all profiles in workflow exist
    $workflowDef = $scanWorkflows[$Workflow]
    foreach ($step in $workflowDef.steps) {
        if (-not $scanProfiles.ContainsKey($step.profile)) {
            Write-Host "[ERROR] Workflow '$Workflow' references unknown profile: $($step.profile)" -ForegroundColor DarkRed
            return
        }
    }

    Write-Host "[INFO] Using workflow: $($workflowDef.name) ($($workflowDef.steps.Count) steps)" -ForegroundColor Green
} else {
    if (-not $scanProfiles.ContainsKey($ScanType)) {
        Write-Host "[ERROR] Invalid scan type: $ScanType" -ForegroundColor DarkRed
        Write-Host "`nAvailable scan profiles:" -ForegroundColor Yellow
        foreach ($profile in $scanProfiles.GetEnumerator() | Sort-Object Key) {
            Write-Host "  - $($profile.Key): $($profile.Value.name)" -ForegroundColor Cyan
            Write-Host "    $($profile.Value.description)" -ForegroundColor Gray
        }
        Write-Host "`nYou can customize scan profiles by editing: $configFile`n" -ForegroundColor Yellow
        return
    }

    Write-Host "[INFO] Using scan profile: $($scanProfiles[$ScanType].name)" -ForegroundColor Green
}
} # End of if (-not $resumingSession)

# Validate that at least one host source is provided
# Skip this validation if resuming a session
if (-not $resumingSession) {
if ((-not $HostFile -or $HostFile -eq "") -and ($Hosts.Count -eq 0)) {
    Write-Host "[ERROR] Either -HostFile or -Hosts parameter must be provided." -ForegroundColor DarkRed
    return
}

# Validate host file if provided
if ($HostFile -and $HostFile -ne "" -and -not (Test-Path $HostFile)) {
    Write-Host "[ERROR] Host file not found: $HostFile" -ForegroundColor DarkRed
    return
}
} # End of if (-not $resumingSession) for host validation

# Use SessionName or generate sessionId
if ($SessionName -and $SessionName -ne "") {
    $sessionId = $SessionName
}

# Create output directories
if ($isWorkflowMode) {
    # Workflow mode: create workflows base folder
    $workflowsFolder = "$OutputDir\$Workflow"
    $logsFolder = $workflowsFolder
    try {
        New-Item -Path $workflowsFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "[ERROR] Failed to create workflow directories: $_" -ForegroundColor DarkRed
        return
    }
    # Step folders will be created dynamically during workflow execution
} else {
    # Single scan mode: traditional structure
    $networksFolder = "$OutputDir\networks"
    $hostsFolder = "$OutputDir\hosts"
    $logsFolder = $OutputDir
    try {
        New-Item -Path $networksFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
        New-Item -Path $hostsFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
        New-Item -Path $logsFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "[ERROR] Failed to create output directories: $_" -ForegroundColor DarkRed
        return
    }
}

# Define log files
$logFile = "$logsFolder\scan.log"
$errorLogFile = "$logsFolder\scan-errors.log"
$resultsFile = "$logsFolder\scan-results.json"
# Note: $stateFile will be defined inside the workflow loop to support per-step state files

# Process target hosts from file and/or command line
# Skip this section if resuming a session (hosts are loaded from session state)
$targetHostsData = @{}  # Host -> {CIDR: [], Type: ""}
$allCIDRs = @()
$invalidEntries = @()
$totalExpanded = 0
$totalEntriesProcessed = 0

if (-not $resumingSession) {
    # Process host file if provided
    if ($HostFile -and $HostFile -ne "") {
    Write-Log -Message "Processing target hosts file: $HostFile" -Level "INFO" -LogFile $logFile
    $hostFileLines = Get-Content $HostFile
    foreach ($line in $hostFileLines) {
        $entry = Resolve-HostEntry -Line $line -LogFile $logFile -ResolveHostname $ResolveHostnames

        if ($entry.Type -eq "Invalid") {
            $invalidEntries += $entry.Original
            Write-Log -Message "Invalid entry: $($entry.Original)" -Level "WARNING" -LogFile $logFile
        } elseif ($entry.Type -ne "Comment") {
            foreach ($currentHost in $entry.Hosts) {
                if (-not $targetHostsData.ContainsKey($currentHost)) {
                    $targetHostsData[$currentHost] = @{
                        CIDRs = @()
                        Type = $entry.Type
                        Original = $entry.Original
                    }
                }

                if ($entry.SourceCIDR) {
                    $targetHostsData[$currentHost].CIDRs += $entry.SourceCIDR
                    if ($allCIDRs -notcontains $entry.SourceCIDR) {
                        $allCIDRs += $entry.SourceCIDR
                    }
                }
            }

            if ($entry.Type -eq "CIDR") {
                $totalExpanded += $entry.Hosts.Count
            }
        }
    }
    $totalEntriesProcessed += $hostFileLines.Count
}

# Process hosts from command line if provided
if ($Hosts.Count -gt 0) {
    Write-Log -Message "Processing target hosts from command line: $($Hosts.Count) entries" -Level "INFO" -LogFile $logFile
    foreach ($hostEntry in $Hosts) {
        $entry = Resolve-HostEntry -Line $hostEntry -LogFile $logFile -ResolveHostname $ResolveHostnames

        if ($entry.Type -eq "Invalid") {
            $invalidEntries += $entry.Original
            Write-Log -Message "Invalid entry: $($entry.Original)" -Level "WARNING" -LogFile $logFile
        } elseif ($entry.Type -ne "Comment") {
            foreach ($currentHost in $entry.Hosts) {
                if (-not $targetHostsData.ContainsKey($currentHost)) {
                    $targetHostsData[$currentHost] = @{
                        CIDRs = @()
                        Type = $entry.Type
                        Original = $entry.Original
                    }
                }

                if ($entry.SourceCIDR) {
                    $targetHostsData[$currentHost].CIDRs += $entry.SourceCIDR
                    if ($allCIDRs -notcontains $entry.SourceCIDR) {
                        $allCIDRs += $entry.SourceCIDR
                    }
                }
            }

            if ($entry.Type -eq "CIDR") {
                $totalExpanded += $entry.Hosts.Count
            }
        }
    }
    $totalEntriesProcessed += $Hosts.Count
}

    $targetHosts = $targetHostsData.Keys
    Write-Log -Message "Total entries processed: $totalEntriesProcessed" -Level "INFO" -LogFile $logFile
    Write-Log -Message "Unique target hosts after expansion: $($targetHosts.Count)" -Level "INFO" -LogFile $logFile

    if ($invalidEntries.Count -gt 0) {
        Write-Log -Message "Invalid entries found: $($invalidEntries.Count)" -Level "WARNING" -LogFile $logFile
        $invalidEntries | ForEach-Object { Write-Log -Message "  - $_" -Level "WARNING" -LogFile $logFile }
    }

    if ($targetHosts.Count -eq 0) {
        Write-Log -Message "No valid hosts found in target file" -Level "ERROR" -LogFile $logFile -ErrorLogFile $errorLogFile
        return
    }

    # Warn if large CIDR expansion
    if ($totalExpanded -gt 5000) {
        Write-Log -Message "WARNING: Expanded CIDR ranges to $totalExpanded hosts. This may take a long time." -Level "WARNING" -LogFile $logFile
    }
} else {
    # Resuming session: hosts are loaded from session state
    Write-Log -Message "Resuming session: hosts will be loaded from session state" -Level "INFO" -LogFile $logFile

    # Load hosts from the resumed session state
    if ($resumedSessionData -and $resumedSessionData.State -and $resumedSessionData.State.hosts) {
        # Get host keys - works for both hashtables and PSCustomObjects
        $hostsObject = $resumedSessionData.State.hosts

        # Check if it's a PSCustomObject or hashtable
        if ($hostsObject -is [System.Collections.Hashtable]) {
            $targetHosts = $hostsObject.Keys
        } else {
            # It's a PSCustomObject, get properties
            $targetHosts = $hostsObject.PSObject.Properties.Name
        }

        Write-Log -Message "Found $($targetHosts.Count) hosts in session state" -Level "INFO" -LogFile $logFile

        # Rebuild targetHostsData from session state
        foreach ($hostKey in $targetHosts) {
            $hostData = $hostsObject.$hostKey
            $targetHostsData[$hostKey] = @{
                CIDRs = if ($hostData.source_cidr) { @($hostData.source_cidr) } else { @() }
                Type = "Host"  # Default type for resumed sessions
                Original = $hostKey
            }
        }

        Write-Log -Message "Loaded $($targetHosts.Count) hosts from session state" -Level "INFO" -LogFile $logFile
    } else {
        Write-Log -Message "No hosts found in session state" -Level "ERROR" -LogFile $logFile -ErrorLogFile $errorLogFile
        return
    }
}

# Process exclusion hosts from file and/or command line
$excludedHosts = @()

# Process exclusion file if provided
if ($ExcludeFile -and $ExcludeFile -ne "") {
    if (Test-Path $ExcludeFile) {
        Write-Log -Message "Processing exclusion file: $ExcludeFile" -Level "INFO" -LogFile $logFile

        $excludeFileLines = Get-Content $ExcludeFile
        foreach ($line in $excludeFileLines) {
            $entry = Resolve-HostEntry -Line $line -LogFile $logFile -ResolveHostname $ResolveHostnames

            if ($entry.Type -eq "Invalid") {
                Write-Log -Message "Invalid exclusion entry: $($entry.Original)" -Level "WARNING" -LogFile $logFile
            } elseif ($entry.Type -ne "Comment") {
                $excludedHosts += $entry.Hosts
            }
        }
    } else {
        Write-Log -Message "Exclusion file not found: $ExcludeFile (continuing without exclusions)" -Level "WARNING" -LogFile $logFile
    }
}

# Process exclusion hosts from command line if provided
if ($ExcludeHosts.Count -gt 0) {
    Write-Log -Message "Processing exclusion hosts from command line: $($ExcludeHosts.Count) entries" -Level "INFO" -LogFile $logFile
    foreach ($excludeEntry in $ExcludeHosts) {
        $entry = Resolve-HostEntry -Line $excludeEntry -LogFile $logFile -ResolveHostname $ResolveHostnames

        if ($entry.Type -eq "Invalid") {
            Write-Log -Message "Invalid exclusion entry: $($entry.Original)" -Level "WARNING" -LogFile $logFile
        } elseif ($entry.Type -ne "Comment") {
            $excludedHosts += $entry.Hosts
        }
    }
}

# Deduplicate excluded hosts
if ($excludedHosts.Count -gt 0) {
    $beforeExcludeDedup = $excludedHosts.Count
    $excludedHosts = $excludedHosts | Select-Object -Unique
    $excludeDuplicatesRemoved = $beforeExcludeDedup - $excludedHosts.Count

    Write-Log -Message "Total exclusion hosts after expansion: $beforeExcludeDedup" -Level "INFO" -LogFile $logFile
    if ($excludeDuplicatesRemoved -gt 0) {
        Write-Log -Message "Exclusion duplicates removed: $excludeDuplicatesRemoved" -Level "INFO" -LogFile $logFile
    }
    Write-Log -Message "Unique exclusion hosts: $($excludedHosts.Count)" -Level "INFO" -LogFile $logFile
}

# Process sensitive hosts from file and/or command line
$sensitiveHosts = @()
$sensitiveHostsData = @{}  # Host -> {CIDRs: [], Type: "", Original: ""}

# Process sensitive file if provided
if ($SensitiveFile -and $SensitiveFile -ne "") {
    if (Test-Path $SensitiveFile) {
        Write-Log -Message "Processing sensitive file: $SensitiveFile" -Level "INFO" -LogFile $logFile

        $sensitiveFileLines = Get-Content $SensitiveFile
        foreach ($line in $sensitiveFileLines) {
            $entry = Resolve-HostEntry -Line $line -LogFile $logFile -ResolveHostname $ResolveHostnames

            if ($entry.Type -eq "Invalid") {
                Write-Log -Message "Invalid sensitive entry: $($entry.Original)" -Level "WARNING" -LogFile $logFile
            } elseif ($entry.Type -ne "Comment") {
                foreach ($currentHost in $entry.Hosts) {
                    $sensitiveHosts += $currentHost

                    # Store metadata
                    if (-not $sensitiveHostsData.ContainsKey($currentHost)) {
                        $sensitiveHostsData[$currentHost] = @{
                            CIDRs = @()
                            Type = $entry.Type
                            Original = $entry.Original
                        }
                    }

                    if ($entry.SourceCIDR) {
                        $sensitiveHostsData[$currentHost].CIDRs += $entry.SourceCIDR
                    }
                }
            }
        }
    } else {
        Write-Log -Message "Sensitive file not found: $SensitiveFile (continuing without sensitive hosts)" -Level "WARNING" -LogFile $logFile
    }
}

# Process sensitive hosts from command line if provided
if ($SensitiveHosts.Count -gt 0) {
    Write-Log -Message "Processing sensitive hosts from command line: $($SensitiveHosts.Count) entries" -Level "INFO" -LogFile $logFile
    foreach ($sensitiveEntry in $SensitiveHosts) {
        $entry = Resolve-HostEntry -Line $sensitiveEntry -LogFile $logFile -ResolveHostname $ResolveHostnames

        if ($entry.Type -eq "Invalid") {
            Write-Log -Message "Invalid sensitive entry: $($entry.Original)" -Level "WARNING" -LogFile $logFile
        } elseif ($entry.Type -ne "Comment") {
            foreach ($currentHost in $entry.Hosts) {
                $sensitiveHosts += $currentHost

                # Store metadata
                if (-not $sensitiveHostsData.ContainsKey($currentHost)) {
                    $sensitiveHostsData[$currentHost] = @{
                        CIDRs = @()
                        Type = $entry.Type
                        Original = $entry.Original
                    }
                }

                if ($entry.SourceCIDR) {
                    $sensitiveHostsData[$currentHost].CIDRs += $entry.SourceCIDR
                }
            }
        }
    }
}

# Deduplicate sensitive hosts
if ($sensitiveHosts.Count -gt 0) {
    $beforeSensitiveDedup = $sensitiveHosts.Count
    $sensitiveHosts = $sensitiveHosts | Select-Object -Unique
    $sensitiveDuplicatesRemoved = $beforeSensitiveDedup - $sensitiveHosts.Count

    Write-Log -Message "Total sensitive hosts after expansion: $beforeSensitiveDedup" -Level "INFO" -LogFile $logFile
    if ($sensitiveDuplicatesRemoved -gt 0) {
        Write-Log -Message "Sensitive duplicates removed: $sensitiveDuplicatesRemoved" -Level "INFO" -LogFile $logFile
    }
    Write-Log -Message "Unique sensitive hosts: $($sensitiveHosts.Count)" -Level "INFO" -LogFile $logFile

    # Debug: Show sample of sensitive hosts
    if ($sensitiveHosts.Count -gt 0) {
        $sampleCount = [Math]::Min(5, $sensitiveHosts.Count)
        $sampleHosts = $sensitiveHosts[0..($sampleCount-1)] -join ', '
        Write-Log -Message "Sample sensitive hosts loaded: $sampleHosts" -Level "INFO" -LogFile $logFile
    }
}

# Apply exclusions and detect conflicts
$validHosts = @()
$excludedCount = 0
$conflicts = @()

# Create hashtable for faster lookups
$excludedSet = @{}
foreach ($h in $excludedHosts) { $excludedSet[$h] = $true }

$sensitiveSet = @{}
foreach ($h in $sensitiveHosts) { $sensitiveSet[$h] = $true }

# Merge sensitive hosts into target hosts if not already present
$addedSensitiveHosts = 0
foreach ($sh in $sensitiveHosts) {
    if (-not $targetHostsData.ContainsKey($sh)) {
        # Add sensitive host to target hosts
        $targetHostsData[$sh] = @{
            CIDRs = $sensitiveHostsData[$sh].CIDRs
            Type = $sensitiveHostsData[$sh].Type
            Original = $sensitiveHostsData[$sh].Original
        }
        $addedSensitiveHosts++
    }
}

if ($addedSensitiveHosts -gt 0) {
    Write-Log -Message "Added $addedSensitiveHosts sensitive hosts to target list (not in HostFile)" -Level "INFO" -LogFile $logFile
}

# Update targetHosts array
$targetHosts = $targetHostsData.Keys

# Debug: Check if sensitive hosts are in target hosts
$sensitiveInTarget = 0
foreach ($sh in $sensitiveHosts) {
    if ($targetHostsData.ContainsKey($sh)) {
        $sensitiveInTarget++
    }
}
Write-Log -Message "Sensitive hosts in final target list: $sensitiveInTarget / $($sensitiveHosts.Count)" -Level "INFO" -LogFile $logFile

if ($excludedHosts.Count -gt 0) {
    foreach ($currentHost in $targetHosts) {
        if ($excludedSet.ContainsKey($currentHost)) {
            $excludedCount++
            # Check if also in sensitive (conflict)
            if ($sensitiveSet.ContainsKey($currentHost)) {
                $conflicts += $currentHost
                Write-Log -Message "CONFLICT: $currentHost is in both sensitive and excluded lists (excluded wins)" -Level "WARNING" -LogFile $logFile
            }
        } else {
            $validHosts += $currentHost
        }
    }
    Write-Log -Message "Hosts excluded from scan: $excludedCount" -Level "INFO" -LogFile $logFile
    if ($conflicts.Count -gt 0) {
        Write-Log -Message "Conflicts detected: $($conflicts.Count) hosts in both sensitive and excluded" -Level "WARNING" -LogFile $logFile
    }
    Write-Log -Message "Final host count after exclusions: $($validHosts.Count)" -Level "INFO" -LogFile $logFile
} else {
    $validHosts = $targetHosts
    Write-Log -Message "No exclusions applied" -Level "INFO" -LogFile $logFile
}

if ($validHosts.Count -eq 0) {
    Write-Log -Message "No hosts remaining after exclusions" -Level "ERROR" -LogFile $logFile -ErrorLogFile $errorLogFile
    return
}

# Separate hosts into normal and sensitive groups
$normalHosts = @()
$sensitiveHostsToScan = @()

# Create hashtable for faster lookups
$validHostsSet = @{}
foreach ($h in $validHosts) { $validHostsSet[$h] = $true }

foreach ($currentHost in $validHosts) {
    if ($sensitiveSet.ContainsKey($currentHost)) {
        $sensitiveHostsToScan += $currentHost
    } else {
        $normalHosts += $currentHost
    }
}

Write-Log -Message "Host distribution: Normal=$($normalHosts.Count), Sensitive=$($sensitiveHostsToScan.Count)" -Level "INFO" -LogFile $logFile

# Debug: Show sample of sensitive hosts that made it through
if ($sensitiveHostsToScan.Count -gt 0) {
    $sampleCount = [Math]::Min(5, $sensitiveHostsToScan.Count)
    $sampleHosts = $sensitiveHostsToScan[0..($sampleCount-1)] -join ', '
    Write-Log -Message "Sample sensitive hosts: $sampleHosts" -Level "INFO" -LogFile $logFile
}

# Determine workflow steps or single scan
if ($isWorkflowMode) {
    $workflowDef = $scanWorkflows[$Workflow]
    $workflowSteps = $workflowDef.steps
    Write-Log -Message "Starting workflow: $($workflowDef.name) with $($workflowSteps.Count) steps" -Level "INFO" -LogFile $logFile
} else {
    # Single scan: create a pseudo-workflow with one step
    $workflowSteps = @(
        @{
            profile = $ScanType
            description = "Single scan"
            condition = "always"
        }
    )
}

# Workflow execution loop
$workflowStepNumber = 1

# Initialize timing tracking for entire scan session
$scanStartTime = Get-Date

foreach ($workflowStep in $workflowSteps) {
    $currentProfile = $workflowStep.profile
    $stepCondition = if ($workflowStep.condition) { $workflowStep.condition } else { $WorkflowCondition }

    if ($isWorkflowMode) {
        Write-Host "`n========================================" -ForegroundColor Magenta
        Write-Host "  Workflow S$workflowStepNumber/$($workflowSteps.Count): $currentProfile" -ForegroundColor Magenta
        Write-Host "  $($workflowStep.description)" -ForegroundColor Gray
        Write-Host "========================================`n" -ForegroundColor Magenta
        Write-Log -Message "Starting workflow S$workflowStepNumber/$($workflowSteps.Count): $currentProfile - $($workflowStep.description)" -Level "INFO" -LogFile $logFile
    }

    $scanCommand = $scanProfiles[$currentProfile].command
    $currentScanType = $currentProfile

    # Use workflow-aware base directory
    if ($isWorkflowMode) {
        $currentBaseDir = $workflowsFolder
    } else {
        $currentBaseDir = $OutputDir
    }

    # Define session directory and state file
    # ALWAYS use .sessions/ structure for consistency
    $sessionDir = Initialize-Session -SessionName $sessionId -OutputDir $OutputDir -ScanType $currentScanType -Workflow $Workflow

    if ($isWorkflowMode) {
        $stateFile = Join-Path $sessionDir "scan-state-$Workflow-S$workflowStepNumber-$currentProfile.json"
    } else {
        $stateFile = Join-Path $sessionDir "scan-state.json"
    }

    $logFile = Join-Path $sessionDir "scan.log"
    $errorLogFile = Join-Path $sessionDir "scan-errors.log"
    $resultsFile = Join-Path $sessionDir "scan-results.json"

    # Initialize tracking for alive hosts and network progress (per workflow step)
    $aliveHostsCount = 0
    $script:networkProgress = @{}

    # Initialize network progress tracking for each CIDR
    foreach ($cidr in $allCIDRs) {
        $script:networkProgress[$cidr] = @{
            Total = 0
            Scanned = 0
            Alive = 0
        }
    }

# Load or initialize state
# If resuming session, load the existing state
if ($resumingSession -and $resumedSessionData) {
    $existingState = $resumedSessionData.State
} else {
    $existingState = Load-StateFile -StateFile $stateFile
}

$state = @{
    session_id = $sessionId
    session_type = if ($SessionName -or $ResumeSession) { "custom" } else { "auto" }
    scan_type = $currentScanType
    workflow = if ($isWorkflowMode) { $Workflow } else { $null }
    workflow_step = $workflowStepNumber
    workflow_total_steps = $workflowSteps.Count
    start_time = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
    end_time = $null
    status = "in_progress"
    total_hosts = $validHosts.Count
    completed = 0
    failed = 0
    in_progress = 0
    pending = $validHosts.Count
    elapsed_seconds = 0
    output_dir = $OutputDir
    hosts = @{}
}

# Initialize host states with metadata
foreach ($currentHost in $validHosts) {
    $isSensitive = $sensitiveHostsToScan -contains $currentHost
    $hostData = $targetHostsData[$currentHost]

    # Determine most specific CIDR if host is from CIDR(s)
    $sourceCIDR = $null
    $alternativeCIDRs = @()
    if ($hostData.CIDRs.Count -gt 0) {
        $sourceCIDR = Get-MostSpecificCIDR -IPAddress $currentHost -CIDRList $hostData.CIDRs
        $alternativeCIDRs = $hostData.CIDRs | Where-Object { $_ -ne $sourceCIDR }
    }

    # Determine output folder
    $outputFolder = Get-OutputFolder -TargetHost $currentHost -SourceCIDR $sourceCIDR -BaseDir $currentBaseDir -WorkflowName $(if ($isWorkflowMode) { $Workflow } else { "" }) -WorkflowStep $workflowStepNumber -StepProfile $currentProfile

    $state.hosts[$currentHost] = @{
        status = "pending"
        attempts = 0
        last_update = ""
        error = ""
        sensitive = $isSensitive
        scan_type = $currentScanType
        timing = if ($isSensitive) { $SensitiveTiming } else { "T4" }
        scripts = if ($isSensitive) { $SensitiveScripts } else { "default+vuln" }
        source_cidr = $sourceCIDR
        alternative_cidrs = $alternativeCIDRs
        output_folder = $outputFolder
    }

    # Count hosts per CIDR for network progress tracking
    if ($sourceCIDR -and $script:networkProgress.ContainsKey($sourceCIDR)) {
        $script:networkProgress[$sourceCIDR].Total++
    }
}

# Handle existing state
$hostsToScan = @()

# Check if existingState has actual content (not just empty hashtable)
$hasValidState = $existingState -and
                 ($existingState.Count -gt 0) -and
                 ($existingState.hosts -or $existingState.session_id -or
                  ($existingState.completed -gt 0) -or ($existingState.failed -gt 0))

if ($hasValidState -and -not $Force) {
    Write-Log -Message "Found previous scan state from session: $($existingState.session_id)" -Level "INFO" -LogFile $logFile

    # Show session information to user
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Previous Scan Session Detected                                    ║" -ForegroundColor Cyan
    Write-Host "╠════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan

    # Session name (max 55 chars)
    $sessionIdToShow = if ($existingState.session_id) { $existingState.session_id } else { $sessionId }
    $sessionDisplay = if ($sessionIdToShow.Length -gt 55) {
        $sessionIdToShow.Substring(0, 52) + "..."
    } else {
        $sessionIdToShow
    }
    Write-Host "║  Session : " -NoNewline -ForegroundColor Cyan
    Write-Host ($sessionDisplay.PadRight(55)) -NoNewline -ForegroundColor White
    Write-Host "║" -ForegroundColor Cyan

    # Path (max 55 chars, truncate from the left to show filename)
    $pathStr = if ($stateFile) { $stateFile.ToString() } else { "(unknown)" }
    $pathDisplay = if ($pathStr.Length -gt 55) {
        "..." + $pathStr.Substring($pathStr.Length - 52)
    } else {
        $pathStr
    }
    Write-Host "║  Path    : " -NoNewline -ForegroundColor Cyan
    Write-Host ($pathDisplay.PadRight(55)) -NoNewline -ForegroundColor White
    Write-Host "║" -ForegroundColor Cyan

    Write-Host "╚════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # Verify scan_type matches
    if ($existingState.scan_type -and $existingState.scan_type -ne $currentScanType) {
        Write-Host "`n[WARNING] Previous state was for scan type '$($existingState.scan_type)' but current scan is '$currentScanType'" -ForegroundColor Yellow
        Write-Host "[INFO] This typically shouldn't happen. State file: $stateFile" -ForegroundColor Cyan
        Write-Log -Message "WARNING: Scan type mismatch - Previous: $($existingState.scan_type), Current: $currentScanType" -Level "WARNING" -LogFile $logFile
    }

    # Determine action based on parameters or user choice
    $action = ""
    if ($Resume) {
        $action = "Resume (pending only)"
    } elseif ($ResumeRetryFailed) {
        $action = "Resume and retry failed"
    } elseif ($ResumeRetryDead) {
        $action = "Resume and retry dead"
    } elseif ($RetryFailed) {
        $action = "Retry failed only"
    } elseif ($RetryDead) {
        $action = "Retry dead only"
    } else {
        # Interactive choice
        $options = @(
            "Resume (pending only)",
            "Resume and retry failed",
            "Resume and retry dead",
            "Retry failed only",
            "Retry dead only",
            "Force (start fresh)",
            "Cancel"
        )
        $action = Get-UserChoice -Prompt "What would you like to do?" -Options $options -Default "Resume (pending only)"

        if ($action -eq "Cancel") {
            Write-Host "`nScan cancelled by user." -ForegroundColor Yellow
            return
        }
    }

    Write-Log -Message "Action selected: $action" -Level "INFO" -LogFile $logFile

    # Build list of hosts to scan based on action
    switch ($action) {
        "Resume (pending only)" {
            foreach ($currentHost in $validHosts) {
                $hostState = $existingState.hosts.$currentHost
                if (-not $hostState -or $hostState.status -eq "pending" -or $hostState.status -eq "in_progress") {
                    $hostsToScan += $currentHost
                    # If was in_progress, preserve state to continue tracking attempts
                    if ($hostState -and $hostState.status -eq "in_progress") {
                        $state.hosts[$currentHost] = $hostState
                        $state.in_progress--
                    }
                } elseif ($hostState.status -eq "completed") {
                    $state.hosts[$currentHost] = $hostState
                } elseif ($hostState.status -eq "failed") {
                    $state.hosts[$currentHost] = $hostState
                }
            }
        }
        "Resume and retry failed" {
            foreach ($currentHost in $validHosts) {
                $hostState = $existingState.hosts.$currentHost
                if (-not $hostState -or $hostState.status -eq "pending" -or $hostState.status -eq "failed" -or $hostState.status -eq "in_progress") {
                    $hostsToScan += $currentHost
                    if ($hostState -and ($hostState.status -eq "failed" -or $hostState.status -eq "in_progress")) {
                        $state.hosts[$currentHost] = $hostState
                        if ($hostState.status -eq "in_progress") {
                            $state.in_progress--
                        }
                    }
                } elseif ($hostState.status -eq "completed") {
                    $state.hosts[$currentHost] = $hostState
                }
            }
        }
        "Resume and retry dead" {
            foreach ($currentHost in $validHosts) {
                $hostState = $existingState.hosts.$currentHost

                if (-not $hostState -or $hostState.status -eq "pending" -or $hostState.status -eq "in_progress") {
                    # Host new or pending → add to scan list
                    $hostsToScan += $currentHost
                    if ($hostState -and $hostState.status -eq "in_progress") {
                        $state.hosts[$currentHost] = $hostState
                        $state.in_progress--
                    }
                }
                elseif ($hostState.status -eq "failed") {
                    # Failed host → retry
                    $hostsToScan += $currentHost
                    $state.hosts[$currentHost] = $hostState
                    $state.failed--
                }
                elseif ($hostState.status -eq "completed") {
                    # Completed host → check if has open ports
                    $isDeadHost = $false

                    if ($hostState.scan_file -and (Test-Path $hostState.scan_file)) {
                        # .nmap file exists → check content
                        $hasOpenPorts = Test-HostHasOpenPorts -XmlFile $hostState.scan_file
                        if (-not $hasOpenPorts) {
                            $isDeadHost = $true
                        }
                    } else {
                        # .nmap file does NOT exist → consider "dead"
                        $isDeadHost = $true
                    }

                    if ($isDeadHost) {
                        # NO open ports → RESCAN
                        $hostsToScan += $currentHost
                        $state.hosts[$currentHost] = $hostState
                        $state.hosts[$currentHost].status = "pending"
                    } else {
                        # Has open ports → SKIP
                        $state.hosts[$currentHost] = $hostState
                    }
                }
            }
        }
        "Retry failed only" {
            foreach ($currentHost in $validHosts) {
                $hostState = $existingState.hosts.$currentHost
                if ($hostState -and $hostState.status -eq "failed") {
                    $hostsToScan += $currentHost
                    $state.hosts[$currentHost] = $hostState
                } elseif ($hostState.status -eq "completed") {
                    $state.hosts[$currentHost] = $hostState
                } elseif (-not $hostState -or $hostState.status -eq "pending" -or $hostState.status -eq "in_progress") {
                    $state.hosts[$currentHost] = @{
                        status = "skipped"
                        attempts = 0
                        last_update = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
                        error = "Skipped (retry failed mode)"
                    }
                }
            }
        }
        "Retry dead only" {
            foreach ($currentHost in $validHosts) {
                $hostState = $existingState.hosts.$currentHost

                if ($hostState -and $hostState.status -eq "failed") {
                    # Failed host → SKIP (mark as skipped)
                    $state.hosts[$currentHost] = @{
                        status = "skipped"
                        attempts = 0
                        last_update = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
                        error = "Skipped (retry dead only mode)"
                    }
                }
                elseif ($hostState -and $hostState.status -eq "completed") {
                    # Completed host → check if has open ports
                    $isDeadHost = $false

                    if ($hostState.scan_file -and (Test-Path $hostState.scan_file)) {
                        # .nmap file exists → check content
                        $hasOpenPorts = Test-HostHasOpenPorts -XmlFile $hostState.scan_file
                        if (-not $hasOpenPorts) {
                            $isDeadHost = $true
                        }
                    } else {
                        # .nmap file does NOT exist → consider "dead"
                        $isDeadHost = $true
                    }

                    if ($isDeadHost) {
                        # NO open ports → RESCAN
                        $hostsToScan += $currentHost
                        $state.hosts[$currentHost] = $hostState
                        $state.hosts[$currentHost].status = "pending"
                    } else {
                        # Has open ports → SKIP
                        $state.hosts[$currentHost] = $hostState
                    }
                }
                elseif (-not $hostState -or $hostState.status -eq "pending" -or $hostState.status -eq "in_progress") {
                    # Pending/in-progress host → SKIP (mark as skipped)
                    $state.hosts[$currentHost] = @{
                        status = "skipped"
                        attempts = 0
                        last_update = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
                        error = "Skipped (retry dead only mode)"
                    }
                }
            }
        }
        "Force (start fresh)" {
            # Archive old state files
            $archiveTimestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
            if (Test-Path $stateFile) {
                Move-Item $stateFile "$logsFolder\scan-state_$archiveTimestamp.json" -Force
                Write-Log -Message "Archived old state file" -Level "INFO" -LogFile $logFile
            }
            # Force mode implies Overwrite mode
            $OverwriteMode = "Overwrite"
            Write-Log -Message "Force mode: Setting OverwriteMode to 'Overwrite'" -Level "INFO" -LogFile $logFile
            $hostsToScan = $validHosts
        }
    }
} else {
    # Fresh start or Force mode
    if ($Force -and $existingState) {
        # Archive old state files
        $archiveTimestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
        if (Test-Path $stateFile) {
            Move-Item $stateFile "$logsFolder\scan-state_$archiveTimestamp.json" -Force
            Write-Log -Message "Archived old state file (Force mode)" -Level "INFO" -LogFile $logFile
        }
        # Force mode implies Overwrite mode
        $OverwriteMode = "Overwrite"
        Write-Log -Message "Force mode: Setting OverwriteMode to 'Overwrite'" -Level "INFO" -LogFile $logFile
    }
    $hostsToScan = $validHosts
}

if ($hostsToScan.Count -eq 0) {
    Write-Log -Message "No hosts to scan. All hosts already processed." -Level "SUCCESS" -LogFile $logFile
    return
}

# Ask once for overwrite mode if set to "Ask" and there are existing results
if ($OverwriteMode -eq "Ask") {
    $hostsWithExistingResults = 0
    foreach ($targetHost in $hostsToScan) {
        $hostMeta = $state.hosts[$targetHost]
        if ($hostMeta) {
            $hostFolder = $hostMeta.output_folder
            $fileName = "$currentScanType"
            if ($hostFolder -and (Test-Path "$hostFolder\$fileName.nmap")) {
                $hostsWithExistingResults++
            }
        }
    }

    if ($hostsWithExistingResults -gt 0) {
        Write-Host "`n$hostsWithExistingResults host(s) have existing scan results." -ForegroundColor Yellow
        $response = Read-Host "Do you want to overwrite all existing results? (y/N)"
        if ($response -eq "y" -or $response -eq "Y") {
            $OverwriteMode = "Overwrite"
            Write-Log -Message "User chose to overwrite all existing results" -Level "INFO" -LogFile $logFile
        } else {
            $OverwriteMode = "Skip"
            Write-Log -Message "User chose to skip all hosts with existing results" -Level "INFO" -LogFile $logFile
        }
    } else {
        # No existing results, set to Overwrite to avoid checks later
        $OverwriteMode = "Overwrite"
    }
}

Write-Log -Message "Scan configuration:" -Level "INFO" -LogFile $logFile
Write-Log -Message "  - Total hosts: $($validHosts.Count)" -Level "INFO" -LogFile $logFile
Write-Log -Message "  - Hosts to scan: $($hostsToScan.Count)" -Level "INFO" -LogFile $logFile
Write-Log -Message "  - Scan type: $currentScanType" -Level "INFO" -LogFile $logFile
Write-Log -Message "  - Max concurrent: $MaxConcurrent" -Level "INFO" -LogFile $logFile
Write-Log -Message "  - Max retries: $MaxRetries" -Level "INFO" -LogFile $logFile
Write-Log -Message "  - Retry delay: $RetryDelay seconds" -Level "INFO" -LogFile $logFile
Write-Log -Message "  - Overwrite mode: $OverwriteMode" -Level "INFO" -LogFile $logFile
Write-Log -Message "  - Verbose mode: $VerboseMode" -Level "INFO" -LogFile $logFile

# Save initial state
Save-StateFile -StateFile $stateFile -State $state

# Initialize results file
if (-not (Test-Path $resultsFile)) {
    @{
        scan_session = $sessionId
        scans = @()
    } | ConvertTo-Json -Depth 10 | Set-Content -Path $resultsFile
}

# Ctrl+C handler
$global:cleanupJobs = @()
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Write-Host "`n`n[INFO] Scan interrupted by user (Ctrl+C)" -ForegroundColor Yellow

    # Show network summary if available
    if ($script:networkProgress -and $script:networkProgress.Count -gt 0) {
        Show-NetworkSummary -NetworkProgress $script:networkProgress -Title "Network Scan Summary (Interrupted)"
    }

    Write-Host "`n[INFO] Cleaning up background jobs..." -ForegroundColor Yellow
    Get-Job | Stop-Job
    Get-Job | Remove-Job -Force

    Write-Host "[INFO] Cleanup completed. Exiting...`n" -ForegroundColor Yellow
}

# Main scanning loop with parallel execution
$completedCount = $state.completed
$failedCount = $state.failed
$jobQueue = @{}

# Timing tracking for individual scans
$scanDurations = @()  # Array to store completed scan durations in seconds
$jobStartTimes = @{}  # Hashtable to track when each job started

Write-Host ""

foreach ($currentHost in $hostsToScan) {
    # Wait if max concurrent jobs reached
    $progressUpdateCounter = 0
    while ($jobQueue.Count -ge $MaxConcurrent) {
        Start-Sleep -Milliseconds 500
        $progressUpdateCounter++

        # Update progress bar every ~60 seconds (120 iterations * 500ms)
        if ($progressUpdateCounter % 120 -eq 0) {
            if ($isWorkflowMode) {
                Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost "" -WorkflowStep $workflowStepNumber -WorkflowTotalSteps $workflowSteps.Count -StepProfile $currentProfile -NetworkProgress $script:networkProgress -AliveHosts $aliveHostsCount -HostStateInfo $state.hosts -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations
            } else {
                Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost "" -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations -HostStateInfo $state.hosts
            }
        }

        # Check completed jobs
        $completedJobs = $jobQueue.GetEnumerator() | Where-Object { $_.Value.Job.State -ne "Running" }
        foreach ($job in $completedJobs) {
            $jobHost = $job.Key
            $jobData = $job.Value
            $jobResult = Receive-Job -Job $jobData.Job
            Remove-Job -Job $jobData.Job -Force

            # Process result
            $scanSuccess = $jobResult.Success
            $attempts = $jobData.Attempts

            if ($scanSuccess) {
                # Check if host has open ports and update counters
                $nmapFile = "$($jobData.HostFolder)\$($jobData.FileName).nmap"

                Update-HostState -State $state -TargetHost $jobHost -Status "completed" -Attempts $attempts -ScanFile $nmapFile
                $completedCount++
                Write-Log -Message "Scan completed: $jobHost | $currentScanType | Attempt: $attempts | Duration: $($jobResult.Duration)" -Level "SUCCESS" -LogFile $logFile

                # Track scan duration for ETA calculation
                if ($jobStartTimes.ContainsKey($jobHost)) {
                    $duration = (Get-Date) - $jobStartTimes[$jobHost]
                    $scanDurations += $duration.TotalSeconds
                    $jobStartTimes.Remove($jobHost)
                }
                if (Test-HostHasOpenPorts -XmlFile $nmapFile) {
                    $aliveHostsCount++
                    $hostCIDR = $state.hosts[$jobHost].source_cidr
                    if ($hostCIDR -and $script:networkProgress.ContainsKey($hostCIDR)) {
                        $script:networkProgress[$hostCIDR].Alive++
                    }
                }

                # Update network scanned counter
                $hostCIDR = $state.hosts[$jobHost].source_cidr
                if ($hostCIDR -and $script:networkProgress.ContainsKey($hostCIDR)) {
                    $script:networkProgress[$hostCIDR].Scanned++
                }

                # Verbose: Show nmap output after completion
                if ($VerboseMode) {
                    $stdoutFile = "$($jobData.HostFolder)\$($jobData.FileName).stdout"
                    if (Test-Path $stdoutFile) {
                        $nmapOutput = Get-Content $stdoutFile -Raw
                        if ($nmapOutput) {
                            Write-Host "`n--- Nmap Output for $jobHost ---" -ForegroundColor Cyan
                            Write-Host $nmapOutput -ForegroundColor DarkGray
                            Write-Host "--- End Output ---`n" -ForegroundColor Cyan
                        }
                    }
                }

                # Add to results
                Add-ScanResult -ResultsFile $resultsFile -ScanResult @{
                    host = $jobHost
                    scan_type = $currentScanType
                    status = "completed"
                    start_time = $jobResult.StartTime
                    end_time = $jobResult.EndTime
                    duration_seconds = $jobResult.DurationSeconds
                    attempts = $attempts
                    output_files = @("$($jobData.HostFolder)\$($jobData.FileName).nmap")
                }
            } else {
                # Check if retry needed
                if ($attempts -lt ($MaxRetries + 1)) {
                    Write-Log -Message "Scan failed: $jobHost | $currentScanType | Attempt: $attempts/$($MaxRetries + 1) | Error: $($jobResult.Error)" -Level "WARNING" -LogFile $logFile -ErrorLogFile $errorLogFile
                    Write-Log -Message "Retrying in $RetryDelay seconds..." -Level "INFO" -LogFile $logFile

                    Start-Sleep -Seconds $RetryDelay

                    # Retry
                    $newAttempts = $attempts + 1
                    Update-HostState -State $state -TargetHost $jobHost -Status "in_progress" -Attempts $newAttempts -Error $jobResult.Error
                    Save-StateFile -StateFile $stateFile -State $state

                    # Verbose: Show retry command
                    if ($VerboseMode) {
                        $fullNmapCommand = "$($jobData.ScanCommand) -oA `"$($jobData.HostFolder)\$($jobData.FileName)`" $jobHost"
                        Write-Log -Message "Retry command: $fullNmapCommand" -Level "VERBOSE" -LogFile $logFile
                    }

                    $retryJob = Start-NmapScanJob -TargetHost $jobHost -ScanCommand $jobData.ScanCommand -OutputPath $jobData.HostFolder -FileName $jobData.FileName -Attempts $newAttempts -Unprivileged $Unprivileged

                    $jobQueue[$jobHost] = @{
                        Job = $retryJob
                        Attempts = $newAttempts
                        HostFolder = $jobData.HostFolder
                        FileName = $jobData.FileName
                        ScanCommand = $jobData.ScanCommand
                    }
                    $jobStartTimes[$jobHost] = Get-Date
                } else {
                    # Max retries reached
                    Update-HostState -State $state -TargetHost $jobHost -Status "failed" -Attempts $attempts -Error $jobResult.Error
                    $failedCount++
                    Write-Log -Message "Scan failed (max retries): $jobHost | $currentScanType | Attempts: $attempts | Error: $($jobResult.Error)" -Level "ERROR" -LogFile $logFile -ErrorLogFile $errorLogFile

                    # Add to results
                    Add-ScanResult -ResultsFile $resultsFile -ScanResult @{
                        host = $jobHost
                        scan_type = $currentScanType
                        status = "failed"
                        start_time = $jobResult.StartTime
                        end_time = $jobResult.EndTime
                        duration_seconds = $jobResult.DurationSeconds
                        attempts = $attempts
                        error = $jobResult.Error
                    }
                }
            }

            # Save state and update progress
            Save-StateFile -StateFile $stateFile -State $state
            if ($isWorkflowMode) {
                Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost $jobHost -WorkflowStep $workflowStepNumber -WorkflowTotalSteps $workflowSteps.Count -StepProfile $currentProfile -NetworkProgress $script:networkProgress -AliveHosts $aliveHostsCount -HostStateInfo $state.hosts -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations
            } else {
                Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost $jobHost -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations -HostStateInfo $state.hosts
            }

            # Remove from queue
            $jobQueue.Remove($jobHost)
        }
    }

    # Get host metadata from state
    $hostMeta = $state.hosts[$currentHost]
    $hostFolder = $hostMeta.output_folder
    $fileName = "$currentScanType"
    $isSensitive = $hostMeta.sensitive

    # Determine scan command (normal or sensitive)
    $baseScanCommand = $scanProfiles[$currentScanType].command
    if ($isSensitive) {
        # Modify command for sensitive hosts
        $currentScanCommand = $baseScanCommand -replace '-T\d+', "-$SensitiveTiming"

        # Handle script parameter replacement
        if ($SensitiveScripts -eq "none") {
            $currentScanCommand = $currentScanCommand -replace '--script=[^\s]+', ''
            $currentScanCommand = $currentScanCommand -replace '\s+', ' '
        }
    } else {
        $currentScanCommand = $baseScanCommand
    }

    # Check if results already exist
    $skipHost = $false
    if (Test-Path "$hostFolder\$fileName.nmap") {
        # If host was in_progress, always overwrite incomplete results
        if ($hostMeta.status -eq "in_progress") {
            Write-Log -Message "Overwriting incomplete scan for $currentHost (was in_progress)" -Level "INFO" -LogFile $logFile
        } else {
            $existingNmapFile = "$hostFolder\$fileName.nmap"
            switch ($OverwriteMode) {
                "Skip" {
                    Write-Log -Message "Skipping $currentHost (results already exist)" -Level "INFO" -LogFile $logFile
                    Update-HostState -State $state -TargetHost $currentHost -Status "completed" -Attempts 0 -ScanFile $existingNmapFile
                    $completedCount++
                    Save-StateFile -StateFile $stateFile -State $state
                    $skipHost = $true
                }
                "Overwrite" {
                    Write-Log -Message "Overwriting existing results for $currentHost" -Level "WARNING" -LogFile $logFile
                }
            }
        }
    }

    if ($skipHost) {
        continue
    }

    # Create folder
    try {
        New-Item -Path $hostFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Log -Message "Failed to create folder for $currentHost : $_" -Level "ERROR" -LogFile $logFile -ErrorLogFile $errorLogFile
        Update-HostState -State $state -TargetHost $currentHost -Status "failed" -Attempts 1 -Error "Failed to create output folder"
        $failedCount++
        Save-StateFile -StateFile $stateFile -State $state
        continue
    }

    # Start scan job
    Update-HostState -State $state -TargetHost $currentHost -Status "in_progress" -Attempts 1
    Save-StateFile -StateFile $stateFile -State $state

    $scanTypeLabel = if ($isSensitive) { "$currentScanType (Sensitive: $SensitiveTiming, $SensitiveScripts)" } else { $currentScanType }
    Write-Log -Message "Scan started: $currentHost | $scanTypeLabel" -Level "INFO" -LogFile $logFile

    # Verbose: Show full nmap command
    if ($VerboseMode) {
        $fullNmapCommand = "$currentScanCommand -oA `"$hostFolder\$fileName`" $currentHost"
        Write-Log -Message "Command: $fullNmapCommand" -Level "VERBOSE" -LogFile $logFile
    }

    $job = Start-NmapScanJob -TargetHost $currentHost -ScanCommand $currentScanCommand -OutputPath $hostFolder -FileName $fileName -Attempts 1 -Unprivileged $Unprivileged

    $jobQueue[$currentHost] = @{
        Job = $job
        Attempts = 1
        HostFolder = $hostFolder
        FileName = $fileName
        ScanCommand = $scanCommand
    }
    $jobStartTimes[$currentHost] = Get-Date

    if ($isWorkflowMode) {
        Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost $currentHost -WorkflowStep $workflowStepNumber -WorkflowTotalSteps $workflowSteps.Count -StepProfile $currentProfile -NetworkProgress $script:networkProgress -AliveHosts $aliveHostsCount -HostStateInfo $state.hosts -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations
    } else {
        Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost $currentHost -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations -HostStateInfo $state.hosts
    }
}

# Wait for remaining jobs to complete
$progressUpdateCounter = 0
while ($jobQueue.Count -gt 0) {
    Start-Sleep -Milliseconds 500
    $progressUpdateCounter++

    # Update progress bar every ~60 seconds (120 iterations * 500ms)
    if ($progressUpdateCounter % 120 -eq 0) {
        if ($isWorkflowMode) {
            Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost "" -WorkflowStep $workflowStepNumber -WorkflowTotalSteps $workflowSteps.Count -StepProfile $currentProfile -NetworkProgress $script:networkProgress -AliveHosts $aliveHostsCount -HostStateInfo $state.hosts -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations
        } else {
            Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost "" -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations -HostStateInfo $state.hosts
        }
    }

    $completedJobs = $jobQueue.GetEnumerator() | Where-Object { $_.Value.Job.State -ne "Running" }
    foreach ($job in $completedJobs) {
        $jobHost = $job.Key
        $jobData = $job.Value
        $jobResult = Receive-Job -Job $jobData.Job
        Remove-Job -Job $jobData.Job -Force

        $scanSuccess = $jobResult.Success
        $attempts = $jobData.Attempts

        if ($scanSuccess) {
            # Check if host has open ports and update counters
            $nmapFile = "$($jobData.HostFolder)\$($jobData.FileName).nmap"

            Update-HostState -State $state -TargetHost $jobHost -Status "completed" -Attempts $attempts -ScanFile $nmapFile
            $completedCount++
            Write-Log -Message "Scan completed: $jobHost | $currentScanType | Attempt: $attempts | Duration: $($jobResult.Duration)" -Level "SUCCESS" -LogFile $logFile
            if (Test-HostHasOpenPorts -NmapFilePath $nmapFile) {
                $aliveHostsCount++
                $hostCIDR = $state.hosts[$jobHost].source_cidr
                if ($hostCIDR -and $script:networkProgress.ContainsKey($hostCIDR)) {
                    $script:networkProgress[$hostCIDR].Alive++
                }
            }

            # Update network scanned counter
            $hostCIDR = $state.hosts[$jobHost].source_cidr
            if ($hostCIDR -and $script:networkProgress.ContainsKey($hostCIDR)) {
                $script:networkProgress[$hostCIDR].Scanned++
            }

            # Verbose: Show nmap output after completion
            if ($VerboseMode) {
                $stdoutFile = "$($jobData.HostFolder)\$($jobData.FileName).stdout"
                if (Test-Path $stdoutFile) {
                    $nmapOutput = Get-Content $stdoutFile -Raw
                    if ($nmapOutput) {
                        Write-Host "`n--- Nmap Output for $jobHost ---" -ForegroundColor Cyan
                        Write-Host $nmapOutput -ForegroundColor DarkGray
                        Write-Host "--- End Output ---`n" -ForegroundColor Cyan
                    }
                }
            }

            Add-ScanResult -ResultsFile $resultsFile -ScanResult @{
                host = $jobHost
                scan_type = $currentScanType
                status = "completed"
                start_time = $jobResult.StartTime
                end_time = $jobResult.EndTime
                duration_seconds = $jobResult.DurationSeconds
                attempts = $attempts
                output_files = @("$($jobData.HostFolder)\$($jobData.FileName).nmap")
            }
        } else {
            if ($attempts -lt ($MaxRetries + 1)) {
                Write-Log -Message "Scan failed: $jobHost | $currentScanType | Attempt: $attempts/$($MaxRetries + 1) | Error: $($jobResult.Error)" -Level "WARNING" -LogFile $logFile -ErrorLogFile $errorLogFile
                Write-Log -Message "Retrying in $RetryDelay seconds..." -Level "INFO" -LogFile $logFile

                Start-Sleep -Seconds $RetryDelay

                $newAttempts = $attempts + 1
                Update-HostState -State $state -TargetHost $jobHost -Status "in_progress" -Attempts $newAttempts -Error $jobResult.Error
                Save-StateFile -StateFile $stateFile -State $state

                # Verbose: Show retry command
                if ($VerboseMode) {
                    $fullNmapCommand = "$($jobData.ScanCommand) -oA `"$($jobData.HostFolder)\$($jobData.FileName)`" $jobHost"
                    Write-Log -Message "Retry command: $fullNmapCommand" -Level "VERBOSE" -LogFile $logFile
                }

                $retryJob = Start-NmapScanJob -TargetHost $jobHost -ScanCommand $jobData.ScanCommand -OutputPath $jobData.HostFolder -FileName $jobData.FileName -Attempts $newAttempts -Unprivileged $Unprivileged

                $jobQueue[$jobHost] = @{
                    Job = $retryJob
                    Attempts = $newAttempts
                    HostFolder = $jobData.HostFolder
                    FileName = $jobData.FileName
                    ScanCommand = $jobData.ScanCommand
                }
                $jobStartTimes[$jobHost] = Get-Date
            } else {
                Update-HostState -State $state -TargetHost $jobHost -Status "failed" -Attempts $attempts -Error $jobResult.Error
                $failedCount++
                Write-Log -Message "Scan failed (max retries): $jobHost | $currentScanType | Attempts: $attempts | Error: $($jobResult.Error)" -Level "ERROR" -LogFile $logFile -ErrorLogFile $errorLogFile

                Add-ScanResult -ResultsFile $resultsFile -ScanResult @{
                    host = $jobHost
                    scan_type = $currentScanType
                    status = "failed"
                    start_time = $jobResult.StartTime
                    end_time = $jobResult.EndTime
                    duration_seconds = $jobResult.DurationSeconds
                    attempts = $attempts
                    error = $jobResult.Error
                }
            }
        }

        Save-StateFile -StateFile $stateFile -State $state
        if ($isWorkflowMode) {
            Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost $jobHost -WorkflowStep $workflowStepNumber -WorkflowTotalSteps $workflowSteps.Count -StepProfile $currentProfile -NetworkProgress $script:networkProgress -AliveHosts $aliveHostsCount -HostStateInfo $state.hosts -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations
        } else {
            Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost $jobHost -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations -HostStateInfo $state.hosts
        }

        $jobQueue.Remove($jobHost)
    }
}

# Clear progress bars
if ($isWorkflowMode) {
    Write-Progress -Id 2 -Activity "Current step" -Completed
} else {
    Write-Progress -Activity "Scanning hosts" -Completed
}

# Final summary
$scriptEndTime = Get-Date
$totalDuration = $scriptEndTime - $scriptStartTime
$state.status = "completed"
$state.end_time = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
Save-StateFile -StateFile $stateFile -State $state

# Calculate detailed statistics
$normalSuccess = 0
$normalFailed = 0
$sensitiveSuccess = 0
$sensitiveFailed = 0
$networkHostsCount = 0
$individualHostsCount = 0
$normalNetworkSuccess = 0
$normalNetworkFailed = 0
$sensitiveNetworkSuccess = 0
$sensitiveNetworkFailed = 0
$normalIndividualSuccess = 0
$normalIndividualFailed = 0
$sensitiveIndividualSuccess = 0
$sensitiveIndividualFailed = 0

# Count unique networks
$uniqueNetworks = @{}

foreach ($currentHost in $validHosts) {
    $hostMeta = $state.hosts[$currentHost]
    $isSensitive = $hostMeta.sensitive
    $isFromCIDR = $null -ne $hostMeta.source_cidr -and $hostMeta.source_cidr -ne ""
    $isSuccess = $hostMeta.status -eq "completed"

    # Track unique networks
    if ($isFromCIDR) {
        $uniqueNetworks[$hostMeta.source_cidr] = $true
    }

    if ($isFromCIDR) {
        $networkHostsCount++
        if ($isSensitive) {
            if ($isSuccess) { $sensitiveNetworkSuccess++ } else { $sensitiveNetworkFailed++ }
        } else {
            if ($isSuccess) { $normalNetworkSuccess++ } else { $normalNetworkFailed++ }
        }
    } else {
        $individualHostsCount++
        if ($isSensitive) {
            if ($isSuccess) { $sensitiveIndividualSuccess++ } else { $sensitiveIndividualFailed++ }
        } else {
            if ($isSuccess) { $normalIndividualSuccess++ } else { $normalIndividualFailed++ }
        }
    }

    if ($isSensitive) {
        if ($isSuccess) { $sensitiveSuccess++ } else { $sensitiveFailed++ }
    } else {
        if ($isSuccess) { $normalSuccess++ } else { $normalFailed++ }
    }
}

$networkCount = $uniqueNetworks.Count
$conflictCount = if ($conflicts) { $conflicts.Count } else { 0 }

# Calculate Live and Dead hosts
$liveHostsCount = 0
$deadHostsCount = 0

foreach ($currentHost in $validHosts) {
    $hostMeta = $state.hosts[$currentHost]
    if ($hostMeta.status -eq "completed" -and $hostMeta.scan_file) {
        if (Test-HostHasOpenPorts -XmlFile $hostMeta.scan_file) {
            $liveHostsCount++
        } else {
            $deadHostsCount++
        }
    }
}

# Calculate metrics
$totalCompleted = $normalSuccess + $sensitiveSuccess
$totalFailed = $normalFailed + $sensitiveFailed

$avgTimePerHost = if ($totalCompleted -gt 0) {
    [math]::Round($totalDuration.TotalSeconds / $totalCompleted, 1)
} else {
    0
}

$throughput = if ($totalDuration.TotalMinutes -gt 0) {
    [math]::Round($totalCompleted / $totalDuration.TotalMinutes, 1)
} else {
    0
}

$successPercent = if ($validHosts.Count -gt 0) {
    [math]::Round($totalCompleted / $validHosts.Count * 100, 1)
} else {
    0
}

$failPercent = if ($validHosts.Count -gt 0) {
    [math]::Round($totalFailed / $validHosts.Count * 100, 1)
} else {
    0
}

$livePercent = if ($totalCompleted -gt 0) {
    [math]::Round($liveHostsCount / $totalCompleted * 100, 1)
} else {
    0
}

$deadPercent = if ($totalCompleted -gt 0) {
    [math]::Round($deadHostsCount / $totalCompleted * 100, 1)
} else {
    0
}

# Format duration (remove leading zeros)
$durationFormatted = if ($totalDuration.TotalHours -ge 1) {
    "{0}h {1:D2}m {2:D2}s" -f [math]::Floor($totalDuration.TotalHours), $totalDuration.Minutes, $totalDuration.Seconds
} else {
    "{0}m {1:D2}s" -f $totalDuration.Minutes, $totalDuration.Seconds
}

Show-ScanyxBanner
Write-Host "╭─────────────────────────────────────────────────╮" -ForegroundColor Cyan
Write-Host "│ SCAN SUMMARY                                    │" -ForegroundColor Cyan
Write-Host "╰─────────────────────────────────────────────────╯" -ForegroundColor Cyan

# Session info
Write-Host "📋 Session  : " -NoNewline -ForegroundColor Cyan
Write-Host "$sessionId" -ForegroundColor White
if ($isWorkflowMode) {
    Write-Host "   Workflow : " -NoNewline -ForegroundColor Cyan
    Write-Host "$Workflow" -ForegroundColor White
} else {
    Write-Host "   Type     : " -NoNewline -ForegroundColor Cyan
    Write-Host "$ScanType" -ForegroundColor White
}
Write-Host "   Duration : " -NoNewline -ForegroundColor Cyan
Write-Host "$durationFormatted " -NoNewline -ForegroundColor White
Write-Host "(avg: " -NoNewline -ForegroundColor DarkGray
Write-Host "${avgTimePerHost}s/host" -NoNewline -ForegroundColor Gray
Write-Host " | throughput: " -NoNewline -ForegroundColor DarkGray
Write-Host "$throughput hosts/min" -NoNewline -ForegroundColor Gray
Write-Host ")" -ForegroundColor DarkGray

# Output directory info
Write-Host "📁 Output   : " -NoNewline -ForegroundColor Cyan
if ($isWorkflowMode) {
    Write-Host "$OutputDir\$Workflow\" -ForegroundColor White
} else {
    Write-Host "$OutputDir\" -ForegroundColor White
}

Write-Host ""

# Results overview
Write-Host "📊 Results  : " -NoNewline -ForegroundColor Cyan
Write-Host "$totalCompleted/$($validHosts.Count) " -NoNewline -ForegroundColor White
Write-Host "✅ " -NoNewline -ForegroundColor Green
Write-Host "($successPercent%)" -NoNewline -ForegroundColor Green
Write-Host " | " -NoNewline -ForegroundColor DarkGray
Write-Host "$totalFailed " -NoNewline -ForegroundColor White
Write-Host "❌ " -NoNewline -ForegroundColor Red
Write-Host "($failPercent%)" -ForegroundColor Red

# Host status (Live/Dead)
Write-Host "🎯 Status   : " -NoNewline -ForegroundColor Cyan
Write-Host "$liveHostsCount " -NoNewline -ForegroundColor White
Write-Host "🟢 " -NoNewline -ForegroundColor Green
Write-Host "Live ($livePercent%)" -NoNewline -ForegroundColor Green
Write-Host " | " -NoNewline -ForegroundColor DarkGray
Write-Host "$deadHostsCount " -NoNewline -ForegroundColor White
Write-Host "🔴 " -NoNewline -ForegroundColor Red
Write-Host "Dead ($deadPercent%)" -ForegroundColor Red

Write-Host ""

# Source breakdown
Write-Host "📁 Source Breakdown" -ForegroundColor Cyan

# Networks section - only show if there are networks
if ($networkCount -gt 0) {
    Write-Host "   Networks : " -NoNewline -ForegroundColor White
    Write-Host "$networkCount CIDR(s) - $networkHostsCount hosts" -ForegroundColor White

    Write-Host "   ├─ Normal    : " -NoNewline -ForegroundColor White
    Write-Host "$($normalNetworkSuccess + $normalNetworkFailed) " -NoNewline -ForegroundColor White
    Write-Host "(✅ " -NoNewline -ForegroundColor Green
    Write-Host "$normalNetworkSuccess" -NoNewline -ForegroundColor Green
    Write-Host " | ❌ " -NoNewline -ForegroundColor Red
    Write-Host "$normalNetworkFailed" -NoNewline -ForegroundColor Red
    Write-Host ")" -ForegroundColor White

    Write-Host "   └─ Sensitive : " -NoNewline -ForegroundColor White
    Write-Host "$($sensitiveNetworkSuccess + $sensitiveNetworkFailed) " -NoNewline -ForegroundColor Yellow
    Write-Host "(✅ " -NoNewline -ForegroundColor Green
    Write-Host "$sensitiveNetworkSuccess" -NoNewline -ForegroundColor Green
    Write-Host " | ❌ " -NoNewline -ForegroundColor Red
    Write-Host "$sensitiveNetworkFailed" -NoNewline -ForegroundColor Red
    Write-Host ")" -ForegroundColor Yellow

    Write-Host ""
}

# Individual hosts section - only show if there are individual hosts
if ($individualHostsCount -gt 0) {
    Write-Host "   Individual: " -NoNewline -ForegroundColor White
    Write-Host "$individualHostsCount hosts" -ForegroundColor White

    Write-Host "   ├─ Normal    : " -NoNewline -ForegroundColor White
    Write-Host "$($normalIndividualSuccess + $normalIndividualFailed) " -NoNewline -ForegroundColor White
    Write-Host "(✅ " -NoNewline -ForegroundColor Green
    Write-Host "$normalIndividualSuccess" -NoNewline -ForegroundColor Green
    Write-Host " | ❌ " -NoNewline -ForegroundColor Red
    Write-Host "$normalIndividualFailed" -NoNewline -ForegroundColor Red
    Write-Host ")" -ForegroundColor White

    Write-Host "   └─ Sensitive : " -NoNewline -ForegroundColor White
    Write-Host "$($sensitiveIndividualSuccess + $sensitiveIndividualFailed) " -NoNewline -ForegroundColor Yellow
    Write-Host "(✅ " -NoNewline -ForegroundColor Green
    Write-Host "$sensitiveIndividualSuccess" -NoNewline -ForegroundColor Green
    Write-Host " | ❌ " -NoNewline -ForegroundColor Red
    Write-Host "$sensitiveIndividualFailed" -NoNewline -ForegroundColor Red
    Write-Host ")" -ForegroundColor Yellow
}

Write-Host ""

# Other info
Write-Host "📌 Other    : " -NoNewline -ForegroundColor Cyan
Write-Host "Excluded: " -NoNewline -ForegroundColor DarkGray
Write-Host "$($excludedHosts.Count)" -NoNewline -ForegroundColor Gray
Write-Host " | Conflicts: " -NoNewline -ForegroundColor DarkGray
Write-Host "$conflictCount" -ForegroundColor Gray

Write-Host ""

Write-Log -Message "Scan session completed | Total: $($validHosts.Count) | Normal: $($normalSuccess + $normalFailed) (success: $normalSuccess, failed: $normalFailed) | Sensitive: $($sensitiveSuccess + $sensitiveFailed) (success: $sensitiveSuccess, failed: $sensitiveFailed) | Excluded: $($excludedHosts.Count) | Duration: $durationFormatted" -Level "SUCCESS" -LogFile $logFile

if ($failedCount -gt 0) {
    Write-Host "[INFO] To retry failed hosts, run:" -ForegroundColor Yellow
    if ($isWorkflowMode) {
        Write-Host "  .\scanyx.ps1 -HostFile $HostFile -Workflow $Workflow -RetryFailed`n" -ForegroundColor Yellow
    } else {
        Write-Host "  .\scanyx.ps1 -HostFile $HostFile -ScanType $ScanType -RetryFailed`n" -ForegroundColor Yellow
    }
}

# Next steps suggestion with XNP
Write-Host ""
Write-Host "🚀 Next Steps" -ForegroundColor Cyan
Write-Host "   To analyze and merge scan results, you can use XtremeNmapParser (XNP):" -ForegroundColor White
Write-Host ""
if ($isWorkflowMode) {
    Write-Host "   python3 xnp.py -d `"$OutputDir\$Workflow`" -M -R --open -C all" -ForegroundColor Yellow
} else {
    Write-Host "   python3 xnp.py -d `"$OutputDir`" -M -R --open -C all" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "   📖 XNP Repository: " -NoNewline -ForegroundColor DarkGray
Write-Host "https://github.com/xtormin/XtremeNmapParser" -ForegroundColor Cyan

Write-Host ""
Write-Host "─────────────────────────────────────────────────`n" -ForegroundColor Cyan

    # End of workflow step
    if ($isWorkflowMode) {
        Write-Log -Message "Completed workflow S$workflowStepNumber/$($workflowSteps.Count): $currentProfile" -Level "SUCCESS" -LogFile $logFile
    }

    $workflowStepNumber++
} # End of workflow loop

# Clear all progress bars after workflow completes
if ($isWorkflowMode) {
    Write-Progress -Id 1 -Activity "Workflow Progress" -Completed
    Write-Progress -Id 2 -Activity "Current step" -Completed

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "  Workflow Complete: $($workflowDef.name)" -ForegroundColor Green
    Write-Host "  All $($workflowSteps.Count) steps finished" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green
    Write-Log -Message "Workflow completed: $Workflow" -Level "SUCCESS" -LogFile $logFile
}

#endregion

#endregion

} # End of Invoke-Scanyx function

# Create alias for shorter invocation
Set-Alias -Name scanyx -Value Invoke-Scanyx

# When loaded via iex or Import-Module, the function is now available
# Users should call: Invoke-Scanyx -HostFile hosts.txt -ScanType tcp-1000
# Or use the alias: scanyx -HostFile hosts.txt -ScanType tcp-1000

# Note: Auto-execution has been disabled to support loading the script in memory.
# If you want to run the script directly from a file, use:
#   powershell -ExecutionPolicy Bypass -File scanyx.ps1 -HostFile hosts.txt -ScanType tcp-1000
