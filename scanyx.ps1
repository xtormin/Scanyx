<#
.SYNOPSIS
SCANYX (Scan Analysis eXecution) - Advanced Nmap scanner with parallel execution, state persistence, and comprehensive logging.

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
Specifies the scan profile to use. Profiles are loaded from scan-profiles.json in the script directory.
Default profiles include: tcp-1000, tcp-full, udp-common, udp-1000, udp-full.
You can add custom profiles by editing scan-profiles.json.

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
Default: scan-profiles.json in script directory.
Allows using different configurations for different projects or scan scenarios.

.PARAMETER VerboseMode
Enable verbose mode to display the full nmap command being executed for each host and show the complete nmap output after each scan completes.
Useful for debugging and understanding the exact commands being run and their output.

.EXAMPLE
.\network_scan_logger.ps1 -HostFile .\hosts.txt -ScanType tcp-1000
Execute a TCP top 1000 ports scan with default settings.

.EXAMPLE
.\network_scan_logger.ps1 -HostFile .\hosts.txt -ScanType tcp-full -MaxConcurrent 10 -OverwriteMode Skip
Execute a full TCP scan with 10 concurrent scans, skipping existing results.

.EXAMPLE
.\network_scan_logger.ps1 -HostFile .\hosts.txt -ScanType udp-common -Resume
Resume a previous scan session, continuing only with pending hosts.

.EXAMPLE
.\network_scan_logger.ps1 -HostFile .\hosts.txt -ScanType tcp-1000 -ResumeRetryFailed
Resume and retry failed hosts from previous session.

.EXAMPLE
.\network_scan_logger.ps1 -HostFile .\hosts.txt -ExcludeFile .\excluded.txt -ScanType tcp-1000
Scan hosts from hosts.txt excluding those listed in excluded.txt.

.EXAMPLE
.\network_scan_logger.ps1 -HostFile .\networks.txt -ExcludeFile .\gateways.txt -ResolveHostnames -ScanType tcp-full
Scan CIDR ranges from networks.txt, excluding hosts in gateways.txt with hostname resolution.

.EXAMPLE
.\network_scan_logger.ps1 -HostFile .\hosts.txt -SensitiveFile .\production.txt -ScanType tcp-1000
Scan hosts with normal timing, but use T2 timing and default scripts for sensitive hosts.

.EXAMPLE
.\network_scan_logger.ps1 -HostFile .\networks.txt -SensitiveFile .\critical.txt -SensitiveTiming T1 -SensitiveScripts none -ScanType tcp-full
Scan with very slow timing (T1) and no NSE scripts for critical/sensitive hosts.

.EXAMPLE
.\network_scan_logger.ps1 -HostFile .\hosts.txt -ScanType tcp-1000 -VerboseMode
Execute a scan with verbose mode enabled to see the exact nmap commands being run.

.EXAMPLE
.\network_scan_logger.ps1 -Hosts "192.168.1.0/24","10.0.0.50" -ScanType tcp-1000
Scan hosts provided directly via command line without using a file.

.EXAMPLE
.\network_scan_logger.ps1 -Hosts "192.168.0.0/24" -ExcludeHosts "192.168.0.1","192.168.0.254" -ScanType tcp-1000
Scan a network excluding specific hosts, all provided via command line.

.EXAMPLE
.\network_scan_logger.ps1 -HostFile .\hosts.txt -Hosts "192.168.5.0/24" -ExcludeHosts "192.168.5.1" -SensitiveHosts "192.168.5.10" -ScanType tcp-1000
Combine file-based and command line hosts, exclusions, and sensitive hosts.

.EXAMPLE
# Create custom scan profile by editing scan-profiles.json:
# {
#   "custom-stealth": {
#     "name": "Stealth Scan",
#     "description": "Slow and stealthy scan",
#     "command": "nmap -v -T2 -Pn -sS --host-timeout 15m"
#   }
# }
# Then use: .\network_scan_logger.ps1 -HostFile .\hosts.txt -ScanType custom-stealth

.NOTES
Author: Jennifer Torres (@xtormin)
Version: 2.7
Requires: Nmap installed and available in PATH

Scan profiles are loaded from scan-profiles.json in the script directory.
If the file doesn't exist, it will be created with default profiles.
#>

[CmdletBinding(DefaultParameterSetName='Normal')]
param (
    # Path to the file containing the list of hosts to scan
    [Parameter(Mandatory = $false)]
    [string]$HostFile = "",

    # Array of hosts to scan (IPs, CIDRs, hostnames)
    [Parameter(Mandatory = $false)]
    [string[]]$Hosts = @(),

    # Type of scan to perform (loaded from scan-profiles.json)
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

    # Retry only failed hosts
    [Parameter(Mandatory = $false)]
    [switch]$RetryFailed,

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
    [switch]$VerboseMode
)

#region Functions

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

    # Check if valid IP address
    $ipPattern = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if ($Address -match $ipPattern) {
        return $true
    }

    # Check if valid hostname/FQDN
    $hostnamePattern = '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    if ($Address -match $hostnamePattern) {
        return $true
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
        # Valid range: /8 to /32
        if ($mask -ge 8 -and $mask -le 32) {
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

        return $hosts
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
            Hosts = @($Line)
            Original = $Line
            SourceCIDR = $null
        }
    }

    # Check if hostname
    $hostnamePattern = '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    if ($Line -match $hostnamePattern) {
        $hosts = @($Line)

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
        [array]$CIDRList
    )

    if ($CIDRList.Count -eq 0) {
        return $null
    }

    # Filter CIDRs that contain this IP
    $matchingCIDRs = @()
    foreach ($cidr in $CIDRList) {
        $parts = $cidr -split '/'
        $networkIP = $parts[0]
        $maskBits = [int]$parts[1]

        # Convert IP and network to integers
        $ipBytes = $IPAddress.Split('.')
        $netBytes = $networkIP.Split('.')
        $ipInt = ([long]$ipBytes[0] -shl 24) + ([long]$ipBytes[1] -shl 16) + ([long]$ipBytes[2] -shl 8) + [long]$ipBytes[3]
        $netInt = ([long]$netBytes[0] -shl 24) + ([long]$netBytes[1] -shl 16) + ([long]$netBytes[2] -shl 8) + [long]$netBytes[3]

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
        [string]$TargetHost,
        [string]$SourceCIDR,
        [string]$BaseDir,
        [string]$WorkflowName = "",
        [int]$WorkflowStep = 0,
        [string]$StepProfile = ""
    )

    if ($WorkflowName -and $WorkflowName -ne "") {
        # Workflow mode: BaseDir/SN-profile/networks|hosts/...
        $stepFolder = "S$WorkflowStep-$StepProfile"
        if ($SourceCIDR) {
            $cidrFolder = $SourceCIDR -replace '/', '-'
            return "$BaseDir\$stepFolder\networks\$cidrFolder"
        } else {
            return "$BaseDir\$stepFolder\hosts\$TargetHost"
        }
    } else {
        # Single scan mode: traditional structure
        if ($SourceCIDR) {
            # From CIDR: goes to networks/ folder
            $cidrFolder = $SourceCIDR -replace '/', '-'
            return "$BaseDir\networks\$cidrFolder"
        } else {
            # Individual host: goes to hosts/ folder
            return "$BaseDir\hosts\$TargetHost"
        }
    }
}

function Build-SensitiveScanCommand {
    param(
        [string]$BaseScanCommand,
        [string]$Timing,
        [string]$Scripts
    )

    # Replace timing: -T4 → -T{timing}
    $modifiedCommand = $BaseScanCommand -replace '-T\d', "-$Timing"

    # Replace scripts based on selection
    $scriptParam = switch ($Scripts) {
        "default"       { "--script=default" }
        "vuln"          { "--script=vuln" }
        "none"          { "" }
        "default+vuln"  { "--script=default,vuln" }
    }

    if ($Scripts -eq "none") {
        # Remove --script parameter entirely
        $modifiedCommand = $modifiedCommand -replace '--script=[^\s]+', ''
    } else {
        # Replace existing --script parameter
        $modifiedCommand = $modifiedCommand -replace '--script=[^\s]+', $scriptParam
    }

    return $modifiedCommand.Trim() -replace '\s+', ' '
}

function Save-StateFile {
    param(
        [string]$StateFile,
        [hashtable]$State
    )

    try {
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
            return $json | ConvertFrom-Json
        } catch {
            Write-Warning "Failed to load state file: $_"
            return $null
        }
    }
    return $null
}

function Update-HostState {
    param(
        [hashtable]$State,
        [string]$TargetHost,
        [string]$Status,
        [int]$Attempts,
        [string]$Error = ""
    )

    $State.hosts[$TargetHost] = @{
        status = $Status
        attempts = $Attempts
        last_update = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
        error = $Error
    }

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
    param([string]$NmapFilePath)

    if (-not (Test-Path $NmapFilePath)) {
        return $false
    }

    try {
        $content = Get-Content $NmapFilePath -Raw -ErrorAction Stop
        # Search for lines indicating open ports
        # Format: "22/tcp   open  ssh" or "53/udp   open  domain"
        # Pattern matches: number/(tcp|udp) followed by whitespace and "open"
        return $content -match "\d+/(tcp|udp)\s+open"
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
        [hashtable]$HostStateInfo = @{}
    )

    $percent = if ($Total -gt 0) { [math]::Round(($Completed / $Total) * 100, 1) } else { 0 }
    $successful = $Completed - $Failed

    # Check if we're in workflow mode
    $isWorkflow = $WorkflowStep -gt 0 -and $WorkflowTotalSteps -gt 0

    if ($isWorkflow) {
        # Workflow mode: Show two progress bars (workflow progress + current step progress)

        # Calculate workflow progress
        $workflowPercent = [math]::Round((($WorkflowStep - 1) / $WorkflowTotalSteps) * 100, 1)

        # Build main status with alive hosts and network info
        $mainStatus = "Step $WorkflowStep/$WorkflowTotalSteps: $StepProfile | Alive: $AliveHosts/$Total hosts"

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

        # Build secondary status with current host network info
        $secondaryStatus = "Progress: $Completed/$Total ($percent%) | Success: $successful | Failed: $Failed"

        if ($CurrentHost -ne "") {
            $secondaryStatus += " | Current: $CurrentHost"

            # If current host belongs to a network, show network progress
            if ($HostStateInfo.ContainsKey($CurrentHost)) {
                $hostCIDR = $HostStateInfo[$CurrentHost].source_cidr
                if ($hostCIDR -and $NetworkProgress.ContainsKey($hostCIDR)) {
                    $netProg = $NetworkProgress[$hostCIDR]
                    $secondaryStatus += " | Network: $hostCIDR ($($netProg.Alive)/$($netProg.Total) alive)"
                }
            }
        }

        # Secondary progress bar: Current step hosts
        Write-Progress -Id 2 `
                       -ParentId 1 `
                       -Activity "Current step: $StepProfile" `
                       -Status $secondaryStatus `
                       -PercentComplete $percent
    } else {
        # Single scan mode: Show single progress bar
        Write-Progress -Activity "Scanning hosts" `
                       -Status "Progress: $Completed/$Total ($percent%) | Success: $successful | Failed: $Failed | Current: $CurrentHost" `
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

    # Check if config file exists
    if (Test-Path $ConfigFile) {
        try {
            $json = Get-Content -Path $ConfigFile -Raw -ErrorAction Stop
            $loadedConfig = $json | ConvertFrom-Json

            # Convert profiles
            $profiles = @{}
            if ($loadedConfig.PSObject.Properties.Name -contains 'profiles') {
                foreach ($prop in $loadedConfig.profiles.PSObject.Properties) {
                    $profiles[$prop.Name] = @{
                        name = $prop.Value.name
                        description = $prop.Value.description
                        command = $prop.Value.command
                    }
                }
            } else {
                # Old format: root level profiles
                foreach ($prop in $loadedConfig.PSObject.Properties) {
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
            if ($loadedConfig.PSObject.Properties.Name -contains 'workflows') {
                foreach ($prop in $loadedConfig.workflows.PSObject.Properties) {
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
        } catch {
            Write-Warning "Failed to load scan configuration from $ConfigFile : $_"
            Write-Warning "Using default configuration"
            return $defaultConfig
        }
    } else {
        # Create default config file
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

#endregion

#region Main Script

# Script start
$scriptStartTime = Get-Date
$sessionId = Get-Date -Format "yyyy-MM-dd_HHmmss"

# Convert OutputDir to absolute path to ensure it works in background jobs
$OutputDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Network Scan Logger v2.7" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Validate Nmap installation
if (-not (Test-NmapInstalled)) {
    Write-Host "[ERROR] Nmap is not installed or not in PATH. Please install Nmap first." -ForegroundColor Red
    exit 1
}

# Load scan configuration (profiles and workflows)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ConfigFile -or $ConfigFile -eq "") {
    $configFile = Join-Path $scriptDir "scan-profiles.json"
} else {
    $configFile = $ConfigFile
}
$scanConfig = Load-ScanConfiguration -ConfigFile $configFile
$scanProfiles = $scanConfig.profiles
$scanWorkflows = $scanConfig.workflows

# Validate mutually exclusive resume/retry/force parameters
$resumeParams = @($Resume.IsPresent, $ResumeRetryFailed.IsPresent, $RetryFailed.IsPresent, $Force.IsPresent)
$resumeParamsCount = ($resumeParams | Where-Object { $_ }).Count
if ($resumeParamsCount -gt 1) {
    Write-Host "[ERROR] Parameters -Resume, -ResumeRetryFailed, -RetryFailed, and -Force are mutually exclusive. Use only one." -ForegroundColor Red
    exit 1
}

# Validate that either ScanType or Workflow is provided (mutually exclusive)
if ((-not $ScanType -or $ScanType -eq "") -and (-not $Workflow -or $Workflow -eq "")) {
    Write-Host "[ERROR] Either -ScanType or -Workflow parameter must be provided." -ForegroundColor Red
    Write-Host "`nAvailable scan profiles:" -ForegroundColor Yellow
    foreach ($profile in $scanProfiles.GetEnumerator() | Sort-Object Key) {
        Write-Host "  - $($profile.Key): $($profile.Value.name)" -ForegroundColor Cyan
    }
    Write-Host "`nAvailable workflows:" -ForegroundColor Yellow
    foreach ($wf in $scanWorkflows.GetEnumerator() | Sort-Object Key) {
        Write-Host "  - $($wf.Key): $($wf.Value.name)" -ForegroundColor Cyan
        Write-Host "    $($wf.Value.description)" -ForegroundColor Gray
    }
    exit 1
}

if ($ScanType -and $ScanType -ne "" -and $Workflow -and $Workflow -ne "") {
    Write-Host "[ERROR] Cannot use both -ScanType and -Workflow. Choose one." -ForegroundColor Red
    exit 1
}

# Validate ScanType or Workflow
$isWorkflowMode = $false
if ($Workflow -and $Workflow -ne "") {
    $isWorkflowMode = $true
    if (-not $scanWorkflows.ContainsKey($Workflow)) {
        Write-Host "[ERROR] Invalid workflow: $Workflow" -ForegroundColor Red
        Write-Host "`nAvailable workflows:" -ForegroundColor Yellow
        foreach ($wf in $scanWorkflows.GetEnumerator() | Sort-Object Key) {
            Write-Host "  - $($wf.Key): $($wf.Value.name)" -ForegroundColor Cyan
            Write-Host "    $($wf.Value.description)" -ForegroundColor Gray
        }
        Write-Host "`nYou can customize workflows by editing: $configFile`n" -ForegroundColor Yellow
        exit 1
    }

    # Validate that all profiles in workflow exist
    $workflowDef = $scanWorkflows[$Workflow]
    foreach ($step in $workflowDef.steps) {
        if (-not $scanProfiles.ContainsKey($step.profile)) {
            Write-Host "[ERROR] Workflow '$Workflow' references unknown profile: $($step.profile)" -ForegroundColor Red
            exit 1
        }
    }

    Write-Host "[INFO] Using workflow: $($workflowDef.name) ($($workflowDef.steps.Count) steps)" -ForegroundColor Green
} else {
    if (-not $scanProfiles.ContainsKey($ScanType)) {
        Write-Host "[ERROR] Invalid scan type: $ScanType" -ForegroundColor Red
        Write-Host "`nAvailable scan profiles:" -ForegroundColor Yellow
        foreach ($profile in $scanProfiles.GetEnumerator() | Sort-Object Key) {
            Write-Host "  - $($profile.Key): $($profile.Value.name)" -ForegroundColor Cyan
            Write-Host "    $($profile.Value.description)" -ForegroundColor Gray
        }
        Write-Host "`nYou can customize scan profiles by editing: $configFile`n" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "[INFO] Using scan profile: $($scanProfiles[$ScanType].name)" -ForegroundColor Green
}

# Validate that at least one host source is provided
if ((-not $HostFile -or $HostFile -eq "") -and ($Hosts.Count -eq 0)) {
    Write-Host "[ERROR] Either -HostFile or -Hosts parameter must be provided." -ForegroundColor Red
    exit 1
}

# Validate host file if provided
if ($HostFile -and $HostFile -ne "" -and -not (Test-Path $HostFile)) {
    Write-Host "[ERROR] Host file not found: $HostFile" -ForegroundColor Red
    exit 1
}

# Create output directories
if ($isWorkflowMode) {
    # Workflow mode: create workflows base folder
    $workflowsFolder = "$OutputDir\$Workflow"
    $logsFolder = $workflowsFolder
    try {
        New-Item -Path $workflowsFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "[ERROR] Failed to create workflow directories: $_" -ForegroundColor Red
        exit 1
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
        Write-Host "[ERROR] Failed to create output directories: $_" -ForegroundColor Red
        exit 1
    }
}

# Define log files
$logFile = "$logsFolder\scan.log"
$errorLogFile = "$logsFolder\scan-errors.log"
$resultsFile = "$logsFolder\scan-results.json"
# Note: $stateFile will be defined inside the workflow loop to support per-step state files

# Process target hosts from file and/or command line
$targetHostsData = @{}  # Host -> {CIDR: [], Type: ""}
$allCIDRs = @()
$invalidEntries = @()
$totalExpanded = 0
$totalEntriesProcessed = 0

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
    exit 1
}

# Warn if large CIDR expansion
if ($totalExpanded -gt 5000) {
    Write-Log -Message "WARNING: Expanded CIDR ranges to $totalExpanded hosts. This may take a long time." -Level "WARNING" -LogFile $logFile
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
    exit 1
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

    # Define state file (workflow mode: per-step state file, single scan: single state file)
    if ($isWorkflowMode) {
        $stateFile = "$logsFolder\scan-state-S$workflowStepNumber-$currentProfile.json"
    } else {
        $stateFile = "$logsFolder\scan-state.json"
    }

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
$existingState = Load-StateFile -StateFile $stateFile
$state = @{
    session_id = $sessionId
    scan_type = $currentScanType
    workflow_name = if ($isWorkflowMode) { $Workflow } else { "" }
    workflow_step = $workflowStepNumber
    workflow_total_steps = $workflowSteps.Count
    start_time = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
    status = "in_progress"
    total_hosts = $validHosts.Count
    completed = 0
    failed = 0
    in_progress = 0
    pending = $validHosts.Count
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
if ($existingState -and -not $Force) {
    Write-Log -Message "Found previous scan state from session: $($existingState.session_id)" -Level "INFO" -LogFile $logFile

    # Determine action based on parameters or user choice
    $action = ""
    if ($Resume) {
        $action = "Resume (pending only)"
    } elseif ($ResumeRetryFailed) {
        $action = "Resume and retry failed"
    } elseif ($RetryFailed) {
        $action = "Retry failed only"
    } else {
        # Interactive choice
        $options = @(
            "Resume (pending only)",
            "Resume and retry failed",
            "Retry failed only",
            "Force (start fresh)",
            "Cancel"
        )
        $action = Get-UserChoice -Prompt "Previous scan state detected. What would you like to do?" -Options $options -Default "Resume (pending only)"

        if ($action -eq "Cancel") {
            Write-Host "`nScan cancelled by user." -ForegroundColor Yellow
            exit 0
        }
    }

    Write-Log -Message "Action selected: $action" -Level "INFO" -LogFile $logFile

    # Build list of hosts to scan based on action
    switch ($action) {
        "Resume (pending only)" {
            foreach ($currentHost in $validHosts) {
                $hostState = $existingState.hosts.$currentHost
                if (-not $hostState -or $hostState.status -eq "pending") {
                    $hostsToScan += $currentHost
                } elseif ($hostState.status -eq "completed") {
                    $state.hosts[$currentHost] = $hostState
                    $state.completed++
                    $state.pending--
                } elseif ($hostState.status -eq "failed") {
                    $state.hosts[$currentHost] = $hostState
                    $state.failed++
                    $state.pending--
                }
            }
        }
        "Resume and retry failed" {
            foreach ($currentHost in $validHosts) {
                $hostState = $existingState.hosts.$currentHost
                if (-not $hostState -or $hostState.status -eq "pending" -or $hostState.status -eq "failed") {
                    $hostsToScan += $currentHost
                    if ($hostState -and $hostState.status -eq "failed") {
                        $state.hosts[$currentHost] = $hostState
                    }
                } elseif ($hostState.status -eq "completed") {
                    $state.hosts[$currentHost] = $hostState
                    $state.completed++
                    $state.pending--
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
                    $state.completed++
                    $state.pending--
                } elseif (-not $hostState -or $hostState.status -eq "pending") {
                    $state.hosts[$currentHost] = @{
                        status = "skipped"
                        attempts = 0
                        last_update = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
                        error = "Skipped (retry failed mode)"
                    }
                    $state.pending--
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
    exit 0
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

Write-Host ""

foreach ($currentHost in $hostsToScan) {
    # Wait if max concurrent jobs reached
    while ($jobQueue.Count -ge $MaxConcurrent) {
        Start-Sleep -Milliseconds 500

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
                Update-HostState -State $state -TargetHost $jobHost -Status "completed" -Attempts $attempts
                $completedCount++
                Write-Log -Message "Scan completed: $jobHost | $currentScanType | Attempt: $attempts | Duration: $($jobResult.Duration)" -Level "SUCCESS" -LogFile $logFile

                # Check if host has open ports and update counters
                $nmapFile = "$($jobData.HostFolder)\$($jobData.FileName).nmap"
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

                    $retryJob = Start-Job -ScriptBlock {
                        param($TargetHost, $ScanCommand, $OutputPath, $FileName, $Attempts)

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
                            if ($using:Unprivileged -and $arg -eq "-sS") {
                                $nmapArgs += "-sT"
                            } else {
                                $nmapArgs += $arg
                            }
                        }

                        # Add --unprivileged if specified
                        if ($using:Unprivileged) {
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
                    } -ArgumentList $jobHost, $jobData.ScanCommand, $jobData.HostFolder, $jobData.FileName, $newAttempts

                    $jobQueue[$jobHost] = @{
                        Job = $retryJob
                        Attempts = $newAttempts
                        HostFolder = $jobData.HostFolder
                        FileName = $jobData.FileName
                        ScanCommand = $jobData.ScanCommand
                    }
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
                Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost $jobHost -WorkflowStep $workflowStepNumber -WorkflowTotalSteps $workflowSteps.Count -StepProfile $currentProfile -NetworkProgress $script:networkProgress -AliveHosts $aliveHostsCount -HostStateInfo $state.hosts
            } else {
                Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost $jobHost
            }

            # Remove from queue
            $jobQueue.Remove($jobHost)
        }
    }

    # Get host metadata from state
    $hostMeta = $state.hosts[$currentHost]
    $hostFolder = $hostMeta.output_folder
    $fileName = "$($currentHost)_$($currentScanType)"
    $isSensitive = $hostMeta.sensitive

    # Determine scan command (normal or sensitive)
    $baseScanCommand = $scanProfiles[$currentScanType].command
    if ($isSensitive) {
        $currentScanCommand = Build-SensitiveScanCommand -BaseScanCommand $baseScanCommand -Timing $SensitiveTiming -Scripts $SensitiveScripts
    } else {
        $currentScanCommand = $baseScanCommand
    }

    # Check if results already exist
    $skipHost = $false
    if (Test-Path "$hostFolder\$fileName.nmap") {
        switch ($OverwriteMode) {
            "Skip" {
                Write-Log -Message "Skipping $currentHost (results already exist)" -Level "INFO" -LogFile $logFile
                Update-HostState -State $state -TargetHost $currentHost -Status "completed" -Attempts 0
                $completedCount++
                Save-StateFile -StateFile $stateFile -State $state
                $skipHost = $true
            }
            "Overwrite" {
                Write-Log -Message "Overwriting existing results for $currentHost" -Level "WARNING" -LogFile $logFile
            }
            "Ask" {
                $response = Read-Host "Results exist for $currentHost. Overwrite? (y/N)"
                if ($response -ne "y" -and $response -ne "Y") {
                    Write-Log -Message "Skipping $currentHost (user chose not to overwrite)" -Level "INFO" -LogFile $logFile
                    Update-HostState -State $state -TargetHost $currentHost -Status "completed" -Attempts 0
                    $completedCount++
                    Save-StateFile -StateFile $stateFile -State $state
                    $skipHost = $true
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

    $job = Start-Job -ScriptBlock {
        param($TargetHost, $ScanCommand, $OutputPath, $FileName, $Attempts)

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
            if ($using:Unprivileged -and $arg -eq "-sS") {
                $nmapArgs += "-sT"
            } else {
                $nmapArgs += $arg
            }
        }

        # Add --unprivileged if specified
        if ($using:Unprivileged) {
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
    } -ArgumentList $currentHost, $currentScanCommand, $hostFolder, $fileName, 1

    $jobQueue[$currentHost] = @{
        Job = $job
        Attempts = 1
        HostFolder = $hostFolder
        FileName = $fileName
        ScanCommand = $scanCommand
    }

    if ($isWorkflowMode) {
        Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost $currentHost -WorkflowStep $workflowStepNumber -WorkflowTotalSteps $workflowSteps.Count -StepProfile $currentProfile -NetworkProgress $script:networkProgress -AliveHosts $aliveHostsCount -HostStateInfo $state.hosts
    } else {
        Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost $currentHost
    }
}

# Wait for remaining jobs to complete
while ($jobQueue.Count -gt 0) {
    Start-Sleep -Milliseconds 500

    $completedJobs = $jobQueue.GetEnumerator() | Where-Object { $_.Value.Job.State -ne "Running" }
    foreach ($job in $completedJobs) {
        $jobHost = $job.Key
        $jobData = $job.Value
        $jobResult = Receive-Job -Job $jobData.Job
        Remove-Job -Job $jobData.Job -Force

        $scanSuccess = $jobResult.Success
        $attempts = $jobData.Attempts

        if ($scanSuccess) {
            Update-HostState -State $state -TargetHost $jobHost -Status "completed" -Attempts $attempts
            $completedCount++
            Write-Log -Message "Scan completed: $jobHost | $currentScanType | Attempt: $attempts | Duration: $($jobResult.Duration)" -Level "SUCCESS" -LogFile $logFile

            # Check if host has open ports and update counters
            $nmapFile = "$($jobData.HostFolder)\$($jobData.FileName).nmap"
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

                $retryJob = Start-Job -ScriptBlock {
                    param($TargetHost, $ScanCommand, $OutputPath, $FileName, $Attempts)

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
                        if ($using:Unprivileged -and $arg -eq "-sS") {
                            $nmapArgs += "-sT"
                        } else {
                            $nmapArgs += $arg
                        }
                    }

                    # Add --unprivileged if specified
                    if ($using:Unprivileged) {
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
                } -ArgumentList $jobHost, $jobData.ScanCommand, $jobData.HostFolder, $jobData.FileName, $newAttempts

                $jobQueue[$jobHost] = @{
                    Job = $retryJob
                    Attempts = $newAttempts
                    HostFolder = $jobData.HostFolder
                    FileName = $jobData.FileName
                    ScanCommand = $jobData.ScanCommand
                }
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
            Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost $jobHost -WorkflowStep $workflowStepNumber -WorkflowTotalSteps $workflowSteps.Count -StepProfile $currentProfile -NetworkProgress $script:networkProgress -AliveHosts $aliveHostsCount -HostStateInfo $state.hosts
        } else {
            Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $hostsToScan.Count -Failed $failedCount -CurrentHost $jobHost
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

foreach ($currentHost in $validHosts) {
    $hostMeta = $state.hosts[$currentHost]
    $isSensitive = $hostMeta.sensitive
    $isFromCIDR = $null -ne $hostMeta.source_cidr -and $hostMeta.source_cidr -ne ""
    $isSuccess = $hostMeta.status -eq "completed"

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

$conflictCount = if ($conflicts) { $conflicts.Count } else { 0 }

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Scan Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Session ID      : $sessionId" -ForegroundColor White
if ($isWorkflowMode) {
    Write-Host "Workflow        : $Workflow" -ForegroundColor White
} else {
    Write-Host "Scan Type       : $ScanType" -ForegroundColor White
}
Write-Host ""
Write-Host "Total Hosts     : $($validHosts.Count)" -ForegroundColor White
Write-Host "  Networks (CIDR): $networkHostsCount" -ForegroundColor White
Write-Host "    - Normal     : $($normalNetworkSuccess + $normalNetworkFailed) (success: $normalNetworkSuccess, failed: $normalNetworkFailed)" -ForegroundColor White
Write-Host "    - Sensitive  : $($sensitiveNetworkSuccess + $sensitiveNetworkFailed) (success: $sensitiveNetworkSuccess, failed: $sensitiveNetworkFailed)" -ForegroundColor White
Write-Host "  Individual     : $individualHostsCount" -ForegroundColor White
Write-Host "    - Normal     : $($normalIndividualSuccess + $normalIndividualFailed) (success: $normalIndividualSuccess, failed: $normalIndividualFailed)" -ForegroundColor White
Write-Host "    - Sensitive  : $($sensitiveIndividualSuccess + $sensitiveIndividualFailed) (success: $sensitiveIndividualSuccess, failed: $sensitiveIndividualFailed)" -ForegroundColor White
Write-Host ""
Write-Host "Total Normal    : $($normalSuccess + $normalFailed) (success: $normalSuccess, failed: $normalFailed)" -ForegroundColor Cyan
Write-Host "Total Sensitive : $($sensitiveSuccess + $sensitiveFailed) (success: $sensitiveSuccess, failed: $sensitiveFailed)" -ForegroundColor Yellow
Write-Host "Excluded        : $($excludedHosts.Count)" -ForegroundColor DarkGray
Write-Host "Conflicts       : $conflictCount" -ForegroundColor Magenta
Write-Host ""
$durationFormatted = "{0:hh}h {0:mm}m {0:ss}s" -f $totalDuration
Write-Host "Total Duration  : $durationFormatted" -ForegroundColor White
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Log -Message "Scan session completed | Total: $($validHosts.Count) | Normal: $($normalSuccess + $normalFailed) (success: $normalSuccess, failed: $normalFailed) | Sensitive: $($sensitiveSuccess + $sensitiveFailed) (success: $sensitiveSuccess, failed: $sensitiveFailed) | Excluded: $($excludedHosts.Count) | Duration: $durationFormatted" -Level "SUCCESS" -LogFile $logFile

if ($failedCount -gt 0) {
    Write-Host "[INFO] To retry failed hosts, run:" -ForegroundColor Yellow
    if ($isWorkflowMode) {
        Write-Host "  .\network_scan_logger.ps1 -HostFile $HostFile -Workflow $Workflow -RetryFailed`n" -ForegroundColor Yellow
    } else {
        Write-Host "  .\network_scan_logger.ps1 -HostFile $HostFile -ScanType $ScanType -RetryFailed`n" -ForegroundColor Yellow
    }
}

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
