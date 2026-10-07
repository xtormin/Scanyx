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
Attempt to resolve hostnames to IPs so that exclusions match a host written as a
name against a target written as an IP, and vice versa. Affects exclusion matching
only: targets and sensitive hosts are still scanned exactly as written, never once
per resolved address. May be slow for large lists.

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

.PARAMETER ResumeRetryDead
Continue scanning pending hosts AND retry the ones that showed no evidence of a
response (verdict filtered, unreachable or unknown). Hosts that answered -- even
with every port closed -- are not retried, because a second scan would reproduce
the same answer. Use -ResumeRetryNoOpenPorts for the previous meaning.

.PARAMETER RetryDead
Only retry hosts that showed no evidence of a response (skips pending, failed,
and anything that answered). See -ResumeRetryDead for the change in meaning.

.PARAMETER ResumeRetryNoOpenPorts
Continue scanning pending hosts AND retry every completed host without an open
port, including the ones that answered on every closed port. This is what
-ResumeRetryDead meant before liveness was classified by evidence.

.PARAMETER RetryNoOpenPorts
Only retry completed hosts without an open port. The pre-liveness -RetryDead.

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

.PARAMETER StopAt
Schedule a time at which the scan stops, for engagement windows that must be respected.
Accepts a clock time ("23:30", "23:30:00"), a date and time ("2026-09-18 06:00",
"2026-09-18T06:00"), or a relative span ("+90m", "2h", "1h30m", "1d2h").
A clock time that has already passed today is taken as that hour tomorrow.
When the time arrives, Scanyx launches no further scans, stops the ones still running,
leaves them pending and prints the command to resume the session later.

.PARAMETER StopMode
What happens to the scans still running when -StopAt arrives.
- Hard: stop them as well, so no traffic leaves the machine after that time (default)
- Drain: launch nothing new, but let the ones already running finish
Only meaningful together with -StopAt.

.PARAMETER Schedule
Recurring window the scan may run in, for scans that take more than one sitting.
Format: "<days> <HH:mm>-<HH:mm>", several windows separated by ';'.
Days accept Spanish and English spellings (L,M,X,J,V,S,D / Mon..Sun), ranges (L-V,
Mon-Fri) and keywords (diario, laborables, finde, daily, weekdays, weekend).
Omitting the days means every day. A range that ends before it starts crosses
midnight ("V 22:00-06:00" opens Friday night and closes Saturday morning).
When the window closes Scanyx stops as it would for -StopAt, waits for the next
opening and carries on where it left off, until the work is done or -Until passes.

.PARAMETER Until
End of the engagement: nothing runs past it. A bare date means the end of that day.
Accepts "2026-09-18", "18/09/2026", "2026-09-18 17:00" and relative spans ("+3d").

.PARAMETER StartAt
Hold the scan until a scheduled time, in the same formats as -StopAt.
Scanyx waits in this process: no cron, launchd or at(1) is involved, so the session
has to stay alive (tmux/nohup, and a machine that does not go to sleep).
Everything it needs to ask is asked before the wait begins.

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
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-full -SessionName night-window -StopAt 06:00
Scan until 06:00 and then stop, leaving whatever is left pending for a later resume.

.EXAMPLE
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-full -SessionName night-window -StartAt 22:00 -StopAt 06:00 -StopMode Drain
Wait until 22:00, scan the agreed window, and at 06:00 launch nothing new while
letting the scans already running finish.

.EXAMPLE
.\scanyx.ps1 -HostFile .\hosts.txt -ScanType tcp-full -SessionName engagement -Schedule "L,J,V 08:00-17:00" -Until "2026-09-18"
Scan only on Monday, Thursday and Friday between 08:00 and 17:00, pausing and
resuming on its own until the work is done or the 18th ends.

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

function Get-NmapPath {
    # Resolve nmap to a full path. Under sudo, secure_path drops /opt/homebrew/bin
    # and /usr/local/bin, so passing a bare "nmap" to Start-Process can fail.
    try {
        return (Get-Command nmap -ErrorAction Stop).Source
    } catch {
        return "nmap"
    }
}

function ConvertTo-ScanyxDateTime {
    # ConvertFrom-Json on PowerShell 7 turns ISO-8601 strings into [DateTime]
    # objects, and interpolating one yields an invariant "MM/dd/yyyy" string that
    # [DateTime]::Parse then rejects under a non-English culture (es-ES reads it
    # as day 09, month 16). Accept both shapes and never parse culture-dependent.
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }

    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::None
    foreach ($culture in @([System.Globalization.CultureInfo]::InvariantCulture,
                           [System.Globalization.CultureInfo]::CurrentCulture)) {
        if ([datetime]::TryParse([string]$Value, $culture, $styles, [ref]$parsed)) {
            return $parsed
        }
    }
    return $null
}

function Format-Duration {
    # Adaptive: a scan shorter than a minute must not read as "00:00", and a
    # scan longer than a day must not wrap around. One formatter for the
    # progress bar and the final summary so they never disagree.
    param([TimeSpan]$TimeSpan)

    if ($TimeSpan.TotalSeconds -lt 0) { return "0s" }

    if ($TimeSpan.TotalDays -ge 1) {
        return "{0}d {1:D2}h" -f [math]::Floor($TimeSpan.TotalDays), $TimeSpan.Hours
    }
    if ($TimeSpan.TotalHours -ge 1) {
        return "{0}h {1:D2}m" -f [math]::Floor($TimeSpan.TotalHours), $TimeSpan.Minutes
    }
    if ($TimeSpan.TotalMinutes -ge 1) {
        return "{0}m {1:D2}s" -f [math]::Floor($TimeSpan.TotalMinutes), $TimeSpan.Seconds
    }
    return "{0}s" -f [math]::Floor($TimeSpan.TotalSeconds)
}

function Resolve-StopTime {
    # A scheduled stop is a promise about the engagement window: nothing of ours
    # touches the client's network after that hour. Parse it with explicit
    # formats instead of the current culture (see ConvertTo-ScanyxDateTime), and
    # never hand back a moment that has already gone by.
    #
    # Accepts: "23:30", "23:30:00", "2026-09-18 06:00", "2026-09-18T06:00",
    #          and relative spans such as "+90m", "2h", "1h30m", "1d2h".
    # A bare clock time that already passed today means that hour tomorrow.
    param(
        [string]$Value,
        [DateTime]$Now = [DateTime]::MinValue
    )

    if ($Now -eq [DateTime]::MinValue) { $Now = Get-Date }

    $result = @{ Ok = $true; Time = $null; Error = "" }
    if ([string]::IsNullOrWhiteSpace($Value)) { return $result }

    $raw = $Value.Trim()

    # Relative span. The lookahead keeps a bare number ("30") out of here, so it
    # falls through and is reported instead of silently meaning something.
    if ($raw -match '^\+?(?=\d)(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$') {
        $days    = if ($Matches[1]) { [int]$Matches[1] } else { 0 }
        $hours   = if ($Matches[2]) { [int]$Matches[2] } else { 0 }
        $minutes = if ($Matches[3]) { [int]$Matches[3] } else { 0 }
        $seconds = if ($Matches[4]) { [int]$Matches[4] } else { 0 }

        $span = New-TimeSpan -Days $days -Hours $hours -Minutes $minutes -Seconds $seconds
        if ($span.TotalSeconds -le 0) {
            $result.Ok = $false
            $result.Error = "A relative stop time must be greater than zero: '$Value'"
            return $result
        }
        $result.Time = $Now.Add($span)
        return $result
    }

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $styles    = [System.Globalization.DateTimeStyles]::None
    $parsed    = [datetime]::MinValue

    [string[]]$clockFormats = @('HH:mm', 'H:mm', 'HH:mm:ss', 'H:mm:ss')
    if ([datetime]::TryParseExact($raw, $clockFormats, $invariant, $styles, [ref]$parsed)) {
        $target = $Now.Date.AddHours($parsed.Hour).AddMinutes($parsed.Minute).AddSeconds($parsed.Second)
        # 02:00 asked for at 23:00 means the small hours of tomorrow, not a
        # deadline that fired eleven hours ago.
        if ($target -le $Now) { $target = $target.AddDays(1) }
        $result.Time = $target
        return $result
    }

    [string[]]$dateFormats = @('yyyy-MM-dd HH:mm', 'yyyy-MM-dd HH:mm:ss',
                     'yyyy-MM-ddTHH:mm', 'yyyy-MM-ddTHH:mm:ss',
                     'yyyy/MM/dd HH:mm', 'dd/MM/yyyy HH:mm')
    if ([datetime]::TryParseExact($raw, $dateFormats, $invariant, $styles, [ref]$parsed)) {
        if ($parsed -le $Now) {
            $result.Ok = $false
            $result.Error = "The stop time $($parsed.ToString('yyyy-MM-dd HH:mm:ss')) is already in the past."
            return $result
        }
        $result.Time = $parsed
        return $result
    }

    $result.Ok = $false
    $result.Error = "Could not read '$Value' as a stop time."
    return $result
}

function Get-TimeRemainingText {
    # How long is left before a scheduled stop, in the same units as everything
    # else Scanyx prints.
    param(
        [DateTime]$Target,
        [DateTime]$Now = [DateTime]::MinValue
    )

    if ($Now -eq [DateTime]::MinValue) { $Now = Get-Date }

    $left = $Target - $Now
    if ($left.TotalSeconds -le 0) { return "due now" }
    return Format-Duration -TimeSpan $left
}

function Get-ResumeCommand {
    # The exact line that picks this session up again. Printed before the scan
    # starts as well as after it ends, because the run that most needs it is the
    # one that was cut short - by a scheduled stop, by Ctrl+C, or by the ride home.
    param(
        [string]$SessionId,
        [string]$OutputDir = "",
        [bool]$Elevated = $false,
        [string]$Schedule = ""
    )

    $prefix = if ($Elevated -and ($IsLinux -or $IsMacOS)) { "sudo " } else { "" }
    $command = "$prefix$(Get-InvocationHint) -ResumeSession `"$SessionId`""
    if ($OutputDir -and $OutputDir -ne "") {
        $command += " -OutputDir `"$OutputDir`""
    }
    # The window the client agreed to still applies tomorrow; the deadline that
    # ended this run does not, so -Until is deliberately left out.
    if ($Schedule -and $Schedule -ne "") {
        $command += " -Schedule `"$Schedule`""
    }
    return "$command -Resume"
}

# How long before a scheduled stop the run says so, in minutes. Descending.
$Global:ScanyxStopWarnings = @(30, 10, 1)

function Get-DueStopWarnings {
    # Which of the warning thresholds have just come due. Thresholds already
    # behind us when the run starts come back together, so a scan launched eight
    # minutes before the deadline announces itself once instead of three times.
    param(
        [DateTime]$StopTime,
        [hashtable]$Fired = @{},
        [DateTime]$Now = [DateTime]::MinValue,
        [int[]]$Thresholds = $null
    )

    if ($Now -eq [DateTime]::MinValue) { $Now = Get-Date }
    if ($null -eq $Thresholds) { $Thresholds = $Global:ScanyxStopWarnings }

    $minutesLeft = ($StopTime - $Now).TotalMinutes
    if ($minutesLeft -le 0) { return @() }

    $due = @()
    foreach ($threshold in $Thresholds) {
        if ($minutesLeft -le $threshold -and -not $Fired.ContainsKey($threshold)) {
            $due += $threshold
        }
    }
    return @($due | Sort-Object -Descending)
}

# Day-of-week tokens, Spanish and English, mapped to [DayOfWeek] values
# (0 = Sunday). "M" is martes and "X" miercoles, as everyone writes them here.
$Global:ScanyxDayTokens = @{
    'd' = 0; 'do' = 0; 'dom' = 0; 'domingo' = 0; 'sun' = 0; 'sunday' = 0
    'l' = 1; 'lu' = 1; 'lun' = 1; 'lunes' = 1; 'mon' = 1; 'monday' = 1
    'm' = 2; 'ma' = 2; 'mar' = 2; 'martes' = 2; 'tue' = 2; 'tues' = 2; 'tuesday' = 2
    'x' = 3; 'mi' = 3; 'mie' = 3; 'miercoles' = 3; 'wed' = 3; 'wednesday' = 3
    'j' = 4; 'ju' = 4; 'jue' = 4; 'jueves' = 4; 'thu' = 4; 'thur' = 4; 'thurs' = 4; 'thursday' = 4
    'v' = 5; 'vi' = 5; 'vie' = 5; 'viernes' = 5; 'fri' = 5; 'friday' = 5
    's' = 6; 'sa' = 6; 'sab' = 6; 'sabado' = 6; 'sat' = 6; 'saturday' = 6
}

function ConvertTo-ScanyxDayNumber {
    # One day token to its [DayOfWeek] number, or $null if it is not a day.
    param([string]$Token)

    if ([string]::IsNullOrWhiteSpace($Token)) { return $null }

    # Accents are how people actually type "miércoles" and "sábado"
    $key = $Token.Trim().ToLowerInvariant()
    $key = $key -replace '[áà]', 'a' -replace '[éè]', 'e' -replace '[íì]', 'i' -replace '[óò]', 'o' -replace '[úùü]', 'u'
    $key = $key.TrimEnd('.')

    if ($Global:ScanyxDayTokens.ContainsKey($key)) { return $Global:ScanyxDayTokens[$key] }
    return $null
}

function ConvertTo-ScanyxDaySet {
    # The days named by "L,J,V", "L-V", "Mon-Fri", "diario", "finde"...
    # Returns a sorted array of [DayOfWeek] numbers, or $null if unreadable.
    param([string]$Days)

    if ([string]::IsNullOrWhiteSpace($Days)) { return @(0, 1, 2, 3, 4, 5, 6) }

    $set = @{}
    foreach ($piece in ($Days -split '[,;/+ ]+' | Where-Object { $_ })) {
        $token = $piece.Trim().ToLowerInvariant()

        switch -regex ($token) {
            '^(diario|diaria|todos|todo|daily|all|every|\*|l-d|lun-dom|mon-sun)$' {
                foreach ($d in 0..6) { $set[$d] = $true }
                continue
            }
            '^(laborables|laborable|entresemana|weekday|weekdays|semana)$' {
                foreach ($d in 1..5) { $set[$d] = $true }
                continue
            }
            '^(finde|findes|fin-de-semana|weekend|weekends)$' {
                $set[6] = $true; $set[0] = $true
                continue
            }
            default {
                if ($token -match '^([a-zñáéíóúü.]+)-([a-zñáéíóúü.]+)$') {
                    $from = ConvertTo-ScanyxDayNumber -Token $Matches[1]
                    $to   = ConvertTo-ScanyxDayNumber -Token $Matches[2]
                    if ($null -eq $from -or $null -eq $to) { return $null }
                    # A range may wrap the week: V-L is Fri, Sat, Sun, Mon
                    $day = $from
                    $set[$day] = $true
                    while ($day -ne $to) {
                        $day = ($day + 1) % 7
                        $set[$day] = $true
                    }
                } else {
                    $day = ConvertTo-ScanyxDayNumber -Token $token
                    if ($null -eq $day) { return $null }
                    $set[$day] = $true
                }
            }
        }
    }

    if ($set.Count -eq 0) { return $null }
    return @($set.Keys | Sort-Object)
}

function ConvertFrom-ScheduleSpec {
    # "L,J,V 08:00-17:00" or "L-V 08:00-17:00; S 10:00-14:00" into windows the
    # scan loop can ask about. Days are optional and default to every day.
    # A range whose end is not after its start crosses midnight: "V 22:00-06:00"
    # opens Friday night and closes Saturday morning.
    param([string]$Spec)

    $result = @{ Ok = $true; Windows = @(); Error = "" }
    if ([string]::IsNullOrWhiteSpace($Spec)) { return $result }

    $windows = @()
    foreach ($chunk in ($Spec -split ';' | Where-Object { $_.Trim() })) {
        $text = $chunk.Trim()

        # The time range is the anchor; whatever precedes it names the days.
        if ($text -notmatch '(\d{1,2}:\d{2})\s*(?:-|–|—|a|to|hasta)\s*(\d{1,2}:\d{2})\s*$') {
            $result.Ok = $false
            $result.Error = "'$text' has no time range. Expected something like 'L-V 08:00-17:00'."
            return $result
        }

        $startText = $Matches[1]
        $endText   = $Matches[2]
        $daysText  = $text.Substring(0, $text.Length - $Matches[0].Length).Trim()

        $startParts = $startText -split ':'
        $endParts   = $endText   -split ':'
        $startSpan  = New-TimeSpan -Hours ([int]$startParts[0]) -Minutes ([int]$startParts[1])
        $endSpan    = New-TimeSpan -Hours ([int]$endParts[0])   -Minutes ([int]$endParts[1])

        if ($startSpan.TotalHours -ge 24 -or $endSpan.TotalHours -gt 24) {
            $result.Ok = $false
            $result.Error = "'$text' has an hour outside 00:00-24:00."
            return $result
        }
        if ($startSpan -eq $endSpan) {
            $result.Ok = $false
            $result.Error = "'$text' opens and closes at the same time."
            return $result
        }

        $days = ConvertTo-ScanyxDaySet -Days $daysText
        if ($null -eq $days) {
            $result.Ok = $false
            $result.Error = "Could not read '$daysText' as days of the week."
            return $result
        }

        $windows += @{
            Days            = $days
            Start           = $startSpan
            End             = $endSpan
            CrossesMidnight = ($endSpan -lt $startSpan)
        }
    }

    if ($windows.Count -eq 0) {
        $result.Ok = $false
        $result.Error = "Empty schedule."
        return $result
    }

    $result.Windows = $windows
    return $result
}

function Get-ScheduleWindowFor {
    # The window instance that contains $Now, as @{ Open; Close }, or $null.
    # Yesterday is checked too: a window that crosses midnight is still open at
    # 02:00 even though its day is the one before.
    param(
        [array]$Windows,
        [DateTime]$Now = [DateTime]::MinValue
    )

    if (-not $Windows -or $Windows.Count -eq 0) { return $null }
    if ($Now -eq [DateTime]::MinValue) { $Now = Get-Date }

    $best = $null
    foreach ($offset in -1..0) {
        $date = $Now.Date.AddDays($offset)
        foreach ($window in $Windows) {
            if ($window.Days -notcontains [int]$date.DayOfWeek) { continue }
            $open  = $date.Add($window.Start)
            $close = if ($window.CrossesMidnight) { $date.AddDays(1).Add($window.End) } else { $date.Add($window.End) }
            if ($Now -ge $open -and $Now -lt $close) {
                # Overlapping windows extend one another rather than cutting short
                if ($null -eq $best -or $close -gt $best.Close) {
                    $best = @{ Open = $open; Close = $close }
                }
            }
        }
    }
    return $best
}

function Get-NextScheduleOpen {
    # When the schedule next opens after $Now. $null if it never does within a
    # fortnight, which in practice only happens with an empty schedule.
    param(
        [array]$Windows,
        [DateTime]$Now = [DateTime]::MinValue
    )

    if (-not $Windows -or $Windows.Count -eq 0) { return $null }
    if ($Now -eq [DateTime]::MinValue) { $Now = Get-Date }

    $next = $null
    foreach ($offset in 0..14) {
        $date = $Now.Date.AddDays($offset)
        foreach ($window in $Windows) {
            if ($window.Days -notcontains [int]$date.DayOfWeek) { continue }
            $open = $date.Add($window.Start)
            if ($open -gt $Now -and ($null -eq $next -or $open -lt $next)) { $next = $open }
        }
        if ($next) { return $next }
    }
    return $next
}

function Resolve-DeadlineTime {
    # The end of the engagement. A bare date means the end of that day: "until
    # the 18th" is not "until the 18th at midnight", which would be the 17th.
    param(
        [string]$Value,
        [DateTime]$Now = [DateTime]::MinValue
    )

    if ($Now -eq [DateTime]::MinValue) { $Now = Get-Date }

    $result = @{ Ok = $true; Time = $null; Error = "" }
    if ([string]::IsNullOrWhiteSpace($Value)) { return $result }

    $raw = $Value.Trim()
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $styles    = [System.Globalization.DateTimeStyles]::None
    $parsed    = [datetime]::MinValue

    [string[]]$dateOnly = @('yyyy-MM-dd', 'dd/MM/yyyy', 'yyyy/MM/dd', 'd/M/yyyy')
    if ([datetime]::TryParseExact($raw, $dateOnly, $invariant, $styles, [ref]$parsed)) {
        $endOfDay = $parsed.Date.AddDays(1).AddSeconds(-1)
        if ($endOfDay -le $Now) {
            $result.Ok = $false
            $result.Error = "The deadline $($parsed.ToString('yyyy-MM-dd')) is already in the past."
            return $result
        }
        $result.Time = $endOfDay
        return $result
    }

    return Resolve-StopTime -Value $raw -Now $Now
}

function Start-ScanyxDelay {
    # Sleep, but not past a deadline. A 60-second retry delay - or an hour, the
    # parameter allows it - must not carry a run twenty minutes past the hour
    # its window closed.
    param(
        [int]$Seconds,
        $StopTime = $null
    )

    if ($Seconds -le 0) { return }

    $deadline = (Get-Date).AddSeconds($Seconds)
    if ($StopTime -and $StopTime -lt $deadline) { $deadline = $StopTime }

    while ((Get-Date) -lt $deadline) {
        $left = ($deadline - (Get-Date)).TotalSeconds
        if ($left -le 0) { break }
        Start-Sleep -Seconds ([math]::Max(1, [math]::Min(5, [int][math]::Ceiling($left))))
    }
}

function Start-DueRetries {
    # Launch the retries whose delay has run out, while there is a free slot and
    # the deadline has not passed. A failed scan waits here instead of in a
    # sleep: sleeping inside the loop that collects jobs froze every other scan,
    # and the progress bar with them, for RetryDelay seconds per failure. The
    # tables are hashtables and therefore shared with the caller by reference.
    param(
        [hashtable]$RetryQueue,
        [hashtable]$JobQueue,
        [hashtable]$JobStartTimes,
        [int]$MaxConcurrent,
        $StopTime = $null,
        [bool]$Unprivileged = $false,
        [string]$NmapPath = "nmap",
        [bool]$Verbatim = $false,
        $Now = $null
    )

    if (-not $Now) { $Now = Get-Date }
    if ($RetryQueue.Count -eq 0) { return 0 }
    if ($StopTime -and $Now -ge $StopTime) { return 0 }

    $due = @($RetryQueue.GetEnumerator() |
        Where-Object { $_.Value.NotBefore -le $Now } |
        Sort-Object { $_.Value.NotBefore })

    $launched = 0
    foreach ($entry in $due) {
        if ($JobQueue.Count -ge $MaxConcurrent) { break }

        $retryHost = $entry.Key
        $r = $entry.Value
        $job = Start-NmapScanJob -TargetHost $retryHost -ScanCommand $r.ScanCommand -OutputPath $r.HostFolder -FileName $r.FileName -Attempts $r.Attempts -Unprivileged $Unprivileged -NmapPath $NmapPath -Verbatim $Verbatim -ResultFile $r.ResultFile

        $JobQueue[$retryHost] = @{
            Job = $job
            Attempts = $r.Attempts
            HostFolder = $r.HostFolder
            FileName = $r.FileName
            ScanCommand = $r.ScanCommand
            ResultFile = $r.ResultFile
        }
        $JobStartTimes[$retryHost] = $Now
        $RetryQueue.Remove($retryHost)
        $launched++
    }
    return $launched
}

function Show-StopWarning {
    # Announce an approaching stop once per threshold. $Fired is a hashtable and
    # therefore shared with the caller by reference: what is said here is not
    # said again by the next loop.
    param(
        $StopTime,
        [hashtable]$Fired,
        [string]$StopMode = "Hard",
        [string]$LogFile = ""
    )

    if (-not $StopTime) { return }

    $due = @(Get-DueStopWarnings -StopTime $StopTime -Fired $Fired)
    if ($due.Count -eq 0) { return }
    foreach ($threshold in $due) { $Fired[$threshold] = $true }

    $left = Get-TimeRemainingText -Target $StopTime
    $consequence = if ($StopMode -eq "Drain") {
        "nothing new will be launched after it; the scans already running will finish"
    } else {
        "the run stops then, the scans still running included"
    }

    Write-Host ""
    Write-Host "[WARNING] Scheduled stop in $left (at $($StopTime.ToString('HH:mm:ss'))) - $consequence" -ForegroundColor Yellow
    if ($LogFile) {
        Write-Log -Message "Scheduled stop in $left (at $($StopTime.ToString('yyyy-MM-dd HH:mm:ss')))" -Level "WARNING" -LogFile $LogFile
    }
}

function Write-ResumeFile {
    # The resume line, on disk next to the session it resumes. Terminal
    # scrollback is lost, reused or scrolled past; the session directory is the
    # thing the consultant still has tomorrow morning.
    param(
        [string]$SessionDir,
        [string]$ResumeCommand,
        [string]$SessionId,
        [string]$Status = "in_progress"
    )

    if ([string]::IsNullOrWhiteSpace($SessionDir) -or [string]::IsNullOrWhiteSpace($ResumeCommand)) {
        return ""
    }

    $path = [IO.Path]::Combine($SessionDir, "resume.txt")
    $lines = @(
        "# Scanyx - resume this session",
        "# Session : $SessionId",
        "# Status  : $Status",
        "# Written : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))",
        "#",
        "# Run it from the Scanyx directory (the one holding scanyx.sh / scanyx.ps1).",
        "",
        $ResumeCommand,
        ""
    )

    try {
        Set-Content -Path $path -Value $lines -Encoding UTF8 -ErrorAction Stop
        return $path
    } catch {
        Write-Warning "Failed to write the resume file: $_"
        return ""
    }
}

function Wait-ForScheduledStart {
    # Hold until the window opens. This is the whole scheduler: no cron, no
    # launchd, no at(1) - which also means the process has to stay alive, so say
    # so rather than let someone close the laptop and find nothing ran.
    param(
        [DateTime]$StartTime,
        $StopTime = $null,
        [int]$RefreshSeconds = 5,
        [string]$LogFile = ""
    )

    $now = Get-Date
    if ($StartTime -le $now) { return $now }

    $wait = $StartTime - $now
    Write-Host ""
    Write-Host "⏳ Waiting for the scheduled start" -ForegroundColor Cyan
    Write-Host "   Start at : " -NoNewline -ForegroundColor Cyan
    Write-Host "$($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) " -NoNewline -ForegroundColor Yellow
    Write-Host "(in $(Format-Duration -TimeSpan $wait))" -ForegroundColor Gray
    if ($StopTime) {
        Write-Host "   Stop at  : " -NoNewline -ForegroundColor Cyan
        Write-Host "$($StopTime.ToString('yyyy-MM-dd HH:mm:ss')) " -NoNewline -ForegroundColor Yellow
        Write-Host "(window: $(Format-Duration -TimeSpan ($StopTime - $StartTime)))" -ForegroundColor Gray
    }
    Write-Host "   This process does the waiting itself: leave it running." -ForegroundColor DarkGray
    if ($IsLinux -or $IsMacOS) {
        Write-Host "   For a long wait use tmux/screen or nohup, and keep the machine awake" -ForegroundColor DarkGray
        Write-Host "   (macOS: caffeinate -i ./scanyx.sh ...)." -ForegroundColor DarkGray
    } else {
        Write-Host "   For a long wait keep the window open and the machine awake." -ForegroundColor DarkGray
    }
    Write-Host "   Ctrl+C cancels; nothing has been scanned yet." -ForegroundColor DarkGray
    if ($LogFile) {
        Write-Log -Message "Waiting for the scheduled start at $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) ($(Format-Duration -TimeSpan $wait) from now)" -Level "INFO" -LogFile $LogFile
    }

    # A countdown rewritten in place is right in front of a person and wrong in
    # a file: carriage returns do not erase anything in a log, they just pile up.
    $liveCountdown = $true
    try { $liveCountdown = -not [Console]::IsOutputRedirected } catch { $liveCountdown = $false }

    while ((Get-Date) -lt $StartTime) {
        $left = $StartTime - (Get-Date)
        if ($liveCountdown) {
            $line = "   Starting in $(Format-Duration -TimeSpan $left)   (now $((Get-Date).ToString('HH:mm:ss')))"
            Write-Host "`r$($line.PadRight(70))" -NoNewline -ForegroundColor DarkGray
        }
        $sleep = [math]::Min($RefreshSeconds, [math]::Max(1, [int][math]::Ceiling($left.TotalSeconds)))
        Start-Sleep -Seconds $sleep
    }

    if ($liveCountdown) { Write-Host "`r$(' ' * 70)`r" -NoNewline }
    $started = Get-Date
    Write-Host "   Started at $($started.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Green
    Write-Host ""
    if ($LogFile) {
        Write-Log -Message "Scheduled start reached: scanning begins now" -Level "INFO" -LogFile $LogFile
    }
    return $started
}

function Get-SensitiveScanCommand {
    # The command actually used for a host marked sensitive. Shared by the
    # pre-flight preview and the scan loop so the preview can never drift from
    # what really runs.
    param(
        [string]$BaseCommand,
        [string]$Timing = "T2",
        [string]$Scripts = "default"
    )

    $cmd = $BaseCommand -replace '-T\d+', "-$Timing"
    if ($Scripts -eq "none") {
        $cmd = $cmd -replace '--script=[^\s]+', ''
        $cmd = $cmd -replace '\s+', ' '
    }
    return $cmd.Trim()
}

function Get-TargetBreakdown {
    # How many hosts each source network contributed, plus the individually
    # listed ones. A wrong mask is the expensive mistake, so the pre-flight
    # shows the expansion rather than just a grand total.
    param(
        [array]$ValidHosts,
        [hashtable]$TargetHostsData
    )

    $perCidr = @{}
    $individual = @()

    foreach ($h in $ValidHosts) {
        $meta = $TargetHostsData[$h]
        $cidrs = if ($meta -and $meta.CIDRs) { @($meta.CIDRs) } else { @() }
        if ($cidrs.Count -gt 0) {
            foreach ($c in $cidrs) {
                if (-not $perCidr.ContainsKey($c)) { $perCidr[$c] = 0 }
                $perCidr[$c]++
            }
        } else {
            $individual += $h
        }
    }

    return @{
        Networks   = $perCidr
        Individual = @($individual)
    }
}

function Format-CommandForDisplay {
    # Wrap a long nmap command so the pre-flight stays readable in an 80-col
    # terminal instead of forcing a horizontal scroll.
    param([string]$Command, [int]$Width = 74, [string]$Indent = "                ")

    $words = $Command -split '\s+' | Where-Object { $_ }
    $lines = @()
    $current = ""
    foreach ($w in $words) {
        if ($current -eq "") {
            $current = $w
        } elseif (($current.Length + 1 + $w.Length) -le $Width) {
            $current = "$current $w"
        } else {
            $lines += $current
            $current = $w
        }
    }
    if ($current -ne "") { $lines += $current }

    $out = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($i -eq 0) { $out += $lines[$i] } else { $out += "$Indent$($lines[$i])" }
    }
    return $out
}

#region Command-list mode

# One token of an nmap command line. Shared by the parser and the job so that
# what the pre-flight shows and what nmap receives come from the same split.
$Global:ScanyxCommandTokenRegex = [regex]'(?:[^\s"'']+|"[^"]*"|''[^'']*'')+'

function Split-NmapCommandLine {
    # Tokenise a command line the same way the scan job does, so the parser
    # and the executor can never disagree about where the arguments are.
    param([string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) { return @() }
    return @($Global:ScanyxCommandTokenRegex.Matches($Command) |
             ForEach-Object { $_.Value.Trim('"').Trim("'") })
}

function Get-CommandUnitId {
    # Content-addressed identity: reordering the list must not lose progress,
    # and editing a line must make it a new unit so it runs again.
    # The label prefix keeps the id readable in the progress bar and the log
    # while staying valid as both a folder name and a JSON property name.
    param(
        [string]$Command,
        [string]$Label = ""
    )

    $normalised = ($Command -replace '\s+', ' ').Trim()
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($normalised))
    } finally {
        $sha.Dispose()
    }
    $hash = -join ($bytes[0..3] | ForEach-Object { $_.ToString('x2') })

    $slug = $Label -replace '[^A-Za-z0-9._-]', '-'
    $slug = ($slug -replace '-+', '-').Trim('-')
    if ($slug.Length -gt 40) { $slug = $slug.Substring(0, 40).Trim('-') }

    if ([string]::IsNullOrWhiteSpace($slug)) { return $hash }
    return "$slug-$hash"
}

function Test-LooksLikeTarget {
    # Good enough to flag a line whose last token is clearly not a target.
    # Deliberately permissive: nmap accepts far more than we want to model.
    param([string]$Token)

    if ([string]::IsNullOrWhiteSpace($Token)) { return $false }
    if ($Token.StartsWith('-')) { return $false }
    if ($Token -match '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$') { return $true }   # IPv4 / CIDR
    if ($Token -match '^\d{1,3}(\.\d{1,3}){0,2}\.[\d,\-]+$')  { return $true } # 10.0.0.1-20
    if ($Token -match '^[A-Za-z0-9]([A-Za-z0-9\-\.]*[A-Za-z0-9])?$') { return $true } # hostname
    if ($Token -match '^[0-9a-fA-F:]+$' -and $Token.Contains(':')) { return $true }   # IPv6
    return $false
}

function ConvertFrom-NmapCommandLine {
    # Parse one line of a command list into a unit of work.
    # Returns a hashtable even for rejected lines: the caller reports them
    # rather than silently dropping work the consultant asked for.
    param(
        [string]$Line,
        [int]$LineNumber = 0,
        [string]$BaseDirectory = ".",
        # Where to put output for a line that names no output file of its own
        [string]$FallbackOutputDir = ""
    )

    $unit = @{
        LineNumber = $LineNumber
        Raw        = $Line
        Command    = ""
        Label      = ""
        Target     = ""
        OutputFlag = $null
        OutputBase = $null
        ResultFile = $null
        ExecCommand = ""
        Id         = ""
        Errors     = @()
        Warnings   = @()
    }

    # A trailing "#" comment is the label. Splitting on the first "#" is safe
    # because nmap has no argument in which "#" is meaningful.
    $text = $Line
    $hashIndex = $text.IndexOf('#')
    if ($hashIndex -ge 0) {
        $unit.Label = $text.Substring($hashIndex + 1).Trim()
        $text = $text.Substring(0, $hashIndex)
    }
    $text = $text.Trim()
    $unit.Command = $text

    if ([string]::IsNullOrWhiteSpace($text)) {
        $unit.Errors += "Empty command"
        return $unit
    }

    # We exec argv directly with no shell, so a shell operator would silently
    # reach nmap as a bogus argument instead of doing what the author meant.
    if ($text -match '[;&|`<>]' -or $text -match '\$\(') {
        $unit.Errors += "Shell metacharacters are not supported (the command is executed directly, without a shell)"
        return $unit
    }

    $tokens = Split-NmapCommandLine -Command $text
    if ($tokens.Count -eq 0) {
        $unit.Errors += "Empty command"
        return $unit
    }

    $first = $tokens[0]
    $firstLeaf = ($first -split '[/\\]')[-1]
    if ($firstLeaf -ne 'nmap' -and $firstLeaf -ne 'nmap.exe') {
        $unit.Errors += "Line must start with nmap (found '$first')"
        return $unit
    }

    $rest = @($tokens | Select-Object -Skip 1)

    # Output flags. nmap refuses -oA together with another -oA or with
    # -oN/-oX/-oG, so we must detect the author's choice and never add ours.
    $outputFlags = @('-oA', '-oN', '-oX', '-oG', '-oS')
    $found = @()
    for ($i = 0; $i -lt $rest.Count; $i++) {
        if ($outputFlags -contains $rest[$i]) {
            if ($i + 1 -lt $rest.Count) {
                $found += @{ Flag = $rest[$i]; Value = $rest[$i + 1] }
            } else {
                $unit.Errors += "$($rest[$i]) has no value"
            }
        }
    }

    if ($found.Count -gt 1) {
        $flagNames = ($found | ForEach-Object { $_.Flag }) -join ', '
        if (($found | Where-Object { $_.Flag -eq '-oA' })) {
            $unit.Errors += "nmap rejects -oA combined with other output flags ($flagNames)"
            return $unit
        }
        $unit.Warnings += "Several output flags ($flagNames); using $($found[0].Flag) to detect open ports"
    }

    if ($found.Count -ge 1) {
        $unit.OutputFlag = $found[0].Flag
        # Relative paths must be pinned here: a background job does not
        # reliably inherit the working directory across PowerShell hosts.
        $raw = $found[0].Value
        $unit.OutputBase = if ([IO.Path]::IsPathRooted($raw)) {
            [IO.Path]::GetFullPath($raw)
        } else {
            [IO.Path]::GetFullPath([IO.Path]::Combine($BaseDirectory, $raw))
        }

        $unit.ResultFile = switch ($unit.OutputFlag) {
            '-oA' { "$($unit.OutputBase).nmap" }
            default { $unit.OutputBase }
        }

        # The line keeps its relative path for display and identity, but what
        # we execute carries the absolute one: a background job does not
        # reliably inherit the working directory across PowerShell hosts, and
        # nmap would otherwise write somewhere we never look.
        $execTokens = @()
        $replaceNext = $false
        foreach ($tok in $tokens) {
            if ($replaceNext) {
                $execTokens += $unit.OutputBase
                $replaceNext = $false
                continue
            }
            $execTokens += $tok
            if ($tok -eq $unit.OutputFlag) { $replaceNext = $true }
        }
        $unit.ExecCommand = ($execTokens -join ' ')

        if ($unit.OutputFlag -eq '-oG') {
            $unit.Warnings += "Grepable-only output: open-port detection is less reliable than with -oA"
        }
    }

    # Target: the last token that is not a flag and not a flag's value. Cheap
    # and correct for the "flags first, target last" convention; when it is
    # wrong we only lose a display name, never correctness of the scan.
    $last = $rest[-1]
    if (Test-LooksLikeTarget -Token $last) {
        $isValueOfFlag = $rest.Count -ge 2 -and $rest[-2].StartsWith('-')
        if ($isValueOfFlag) {
            $unit.Warnings += "Could not identify the target: last token '$last' looks like a value for $($rest[-2])"
        } else {
            $unit.Target = $last
        }
    } else {
        $unit.Warnings += "Could not identify the target from the last token ('$last')"
    }

    if ($rest -contains '-iL' -or $rest -contains '-iR') {
        $unit.Warnings += "Targets come from -iL/-iR, so this unit covers more than one host"
    }

    if ([string]::IsNullOrWhiteSpace($unit.Label)) {
        $unit.Label = if ($unit.Target) { $unit.Target } else { "line$LineNumber" }
    }

    # Identity comes from the line as written, so it stays stable no matter
    # where the output ends up.
    $unit.Id = Get-CommandUnitId -Command $unit.Command -Label $unit.Label

    if ([string]::IsNullOrWhiteSpace($unit.ExecCommand)) {
        if ($FallbackOutputDir) {
            # No output flag: give the line one, or nmap writes nothing to disk
            # and there is no result to track, resume from, or test for open ports.
            $unit.OutputBase = [IO.Path]::Combine($FallbackOutputDir, $unit.Id, "scan")
            $unit.OutputFlag = '-oA'
            $unit.ResultFile = "$($unit.OutputBase).nmap"
            $unit.ExecCommand = "$($unit.Command) -oA $($unit.OutputBase)"
        } else {
            $unit.ExecCommand = $unit.Command
        }
    }
    return $unit
}

function Test-NmapOutputMatchesCommand {
    # nmap records its own argv in the first line of .nmap output. Comparing it
    # is what makes "already scanned" mean "already scanned with this exact
    # command", so editing a line re-runs it even though the previous version
    # wrote to the same -oA path.
    param(
        [string]$ResultFile,
        [string]$Command
    )

    if ([string]::IsNullOrWhiteSpace($ResultFile) -or -not (Test-Path $ResultFile)) { return $false }

    try {
        $firstLine = Get-Content $ResultFile -TotalCount 1 -ErrorAction Stop
    } catch { return $false }

    if (-not $firstLine -or $firstLine -notmatch '\sas:\s+(.*)$') { return $false }
    $recorded = $Matches[1].Trim()

    # Drop the executable from both sides: the recorded one is a resolved path.
    $stripExe = {
        param($c)
        $t = @(Split-NmapCommandLine -Command $c)
        if ($t.Count -le 1) { return "" }
        return (($t | Select-Object -Skip 1) -join ' ')
    }

    return ((& $stripExe $recorded) -eq (& $stripExe $Command))
}

function Read-CommandList {
    # Turn the consultant's list into units of work, reporting every problem
    # up front instead of failing halfway through a long run.
    param(
        [string[]]$Lines,
        [string]$BaseDirectory = ".",
        [string]$FallbackOutputDir = ""
    )

    $units = @()
    $rejected = @()
    $lineNumber = 0

    foreach ($line in $Lines) {
        $lineNumber++
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed.StartsWith('#')) { continue }   # whole-line comment

        $unit = ConvertFrom-NmapCommandLine -Line $line -LineNumber $lineNumber -BaseDirectory $BaseDirectory -FallbackOutputDir $FallbackOutputDir
        if ($unit.Errors.Count -gt 0) { $rejected += $unit } else { $units += $unit }
    }

    # Two lines writing to the same place would clobber each other, and a
    # duplicate line is wasted scanning time. Both are worth saying out loud.
    $seenId = @{}
    $seenOutput = @{}
    foreach ($u in $units) {
        if ($seenId.ContainsKey($u.Id)) {
            $u.Warnings += "Duplicate of line $($seenId[$u.Id])"
        } else {
            $seenId[$u.Id] = $u.LineNumber
        }

        if ($u.OutputBase) {
            $key = $u.OutputBase.ToLowerInvariant()
            if ($seenOutput.ContainsKey($key)) {
                $u.Warnings += "Writes to the same output path as line $($seenOutput[$key])"
            } else {
                $seenOutput[$key] = $u.LineNumber
            }
        }
    }

    return @{
        Units    = @($units)
        Rejected = @($rejected)
    }
}

#endregion

function Get-InvocationHint {
    # How the user launches Scanyx on this platform, for copy-paste hints.
    # $IsLinux/$IsMacOS do not exist on Windows PowerShell 5.1 (they are $null there).
    if ($IsLinux -or $IsMacOS) { return "./scanyx.sh" } else { return ".\scanyx.ps1" }
}

function Test-IsElevated {
    # Root on Unix, Administrator on Windows.
    # Not [Environment]::IsPrivilegedProcess: that is .NET 7+ and breaks PS 5.1.
    if ($IsLinux -or $IsMacOS) {
        try { return ((& id -u) -eq '0') } catch { return $false }
    }
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

# Nmap flags that need raw sockets (root on Linux/macOS).
# Degradable ones have an unprivileged equivalent; blocking ones do not.
$Global:ScanyxRootFlags = @{
    Degradable = @('-sS','-sA','-sF','-sN','-sX','-sW','-sM','-sY','-sZ','-O','-A',
                   '--traceroute','--osscan-guess','--spoof-mac','-D','-S','-f')
    Blocking   = @('-sU','-sO')
}

function Get-RootRequiredFlags {
    param([string]$Command)

    $result = @{ Degradable = @(); Blocking = @() }
    if ([string]::IsNullOrWhiteSpace($Command)) { return $result }

    # Tokenise so that -sU is not matched inside --script=vuln or a filename
    $tokens = $Command -split '\s+' | Where-Object { $_ }

    foreach ($token in $tokens) {
        $bare = ($token -split '=')[0]
        if ($Global:ScanyxRootFlags.Blocking -contains $bare) {
            $result.Blocking += $bare
        } elseif ($Global:ScanyxRootFlags.Degradable -contains $bare) {
            $result.Degradable += $bare
        }
    }

    $result.Degradable = @($result.Degradable | Select-Object -Unique)
    $result.Blocking   = @($result.Blocking   | Select-Object -Unique)
    return $result
}

function ConvertTo-UnprivilegedCommand {
    param([string]$Command)

    $flags = Get-RootRequiredFlags -Command $Command
    # -sU / -sO cannot be degraded: nmap has no connect()-style UDP or IP-proto scan
    if ($flags.Blocking.Count -gt 0) { return $null }

    $tokens = $Command -split '\s+' | Where-Object { $_ }
    $out = @()
    foreach ($token in $tokens) {
        switch -Regex ($token) {
            '^-sS$'                        { $out += '-sT'; break }
            # -A implies -O and --traceroute, both of which need root
            '^-A$'                         { $out += '-sV'; $out += '-sC'; break }
            '^(-O|--traceroute|--osscan-guess)$' { break }
            default                        { $out += $token }
        }
    }
    if ($out -notcontains '--unprivileged') { $out += '--unprivileged' }
    return ($out -join ' ')
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
            ResolvedIPs = @()
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
            ResolvedIPs = @()
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
            ResolvedIPs = @()
            Original = $Line
            SourceCIDR = $null
        }
    }

    # Check if hostname
    $hostnamePattern = '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    if ($Line -match $hostnamePattern) {
        $hosts = ,$Line

        # IPs this hostname resolves to, kept OUT of .Hosts on purpose.
        # For a target list the hostname itself is the host to scan, so appending
        # its addresses here would scan the same machine once per A record.
        # Only exclusion matching needs every spelling of a host, and that caller
        # concatenates .Hosts + .ResolvedIPs itself.
        $resolvedHostIPs = @()

        # Optionally resolve to IP
        if ($ResolveHostname) {
            try {
                $resolved = [System.Net.Dns]::GetHostAddresses($Line)
                $resolvedIPs = $resolved | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }
                if ($resolvedIPs.Count -gt 0) {
                    $resolvedHostIPs = @($resolvedIPs)
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
            ResolvedIPs = $resolvedHostIPs
            Original = $Line
            SourceCIDR = $null
        }
    }

    # Invalid entry
    return @{
        Type = "Invalid"
        Hosts = @()
        ResolvedIPs = @()
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
        return [IO.Path]::Combine($BaseDir, $hostKey, $ScanType)
    }

    if ($WorkflowName -and $WorkflowName -ne "") {
        # Workflow mode: BaseDir/SN-profile/networks|hosts/host/
        $stepFolder = "S$WorkflowStep-$StepProfile"
        if ($SourceCIDR) {
            $cidrFolder = $SourceCIDR -replace '/', '-'
            return [IO.Path]::Combine($BaseDir, $stepFolder, "networks", $cidrFolder, $hostKey)
        } else {
            return [IO.Path]::Combine($BaseDir, $stepFolder, "hosts", $hostKey)
        }
    } else {
        # Single scan mode: each host has its own folder
        if ($SourceCIDR) {
            # From CIDR: goes to networks/cidr/host/ folder
            $cidrFolder = $SourceCIDR -replace '/', '-'
            return [IO.Path]::Combine($BaseDir, "networks", $cidrFolder, $hostKey)
        } else {
            # Individual host: goes to hosts/host/ folder
            return [IO.Path]::Combine($BaseDir, "hosts", $hostKey)
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
        [string]$ScanFile = "",
        [string]$Liveness = "",
        [string]$LivenessReason = "",
        [int]$OpenPortCount = -1
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
        # Command-list mode: without these the unit would lose the very command
        # it is supposed to run on its first state transition.
        if ($existingHost.command) { $hostState.command = $existingHost.command }
        if ($existingHost.exec_command) { $hostState.exec_command = $existingHost.exec_command }
        if ($existingHost.label) { $hostState.label = $existingHost.label }
        if ($existingHost.line_number) { $hostState.line_number = $existingHost.line_number }
        if ($existingHost.result_file) { $hostState.result_file = $existingHost.result_file }
        if ($existingHost.target) { $hostState.target = $existingHost.target }
        # A failed retry must not erase a verdict earned on the previous attempt.
        if ($existingHost.liveness) { $hostState.liveness = $existingHost.liveness }
        if ($existingHost.liveness_reason) { $hostState.liveness_reason = $existingHost.liveness_reason }
        if ($null -ne $existingHost.open_port_count) { $hostState.open_port_count = $existingHost.open_port_count }
        if ($existingHost.output_flag) { $hostState.output_flag = $existingHost.output_flag }
    }

    # Explicit values win over whatever was preserved above.
    if ($Liveness) { $hostState.liveness = $Liveness }
    if ($LivenessReason) { $hostState.liveness_reason = $LivenessReason }
    if ($OpenPortCount -ge 0) { $hostState.open_port_count = $OpenPortCount }

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

function Get-ScanResultsLogPath {
    # The append-only companion of scan-results.json, in the same directory.
    param([string]$ResultsFile)

    if ([string]::IsNullOrWhiteSpace($ResultsFile)) { return "" }
    $dir = [IO.Path]::GetDirectoryName($ResultsFile)
    $name = [IO.Path]::GetFileNameWithoutExtension($ResultsFile)
    if ([string]::IsNullOrWhiteSpace($dir)) { return "$name.jsonl" }
    return [IO.Path]::Combine($dir, "$name.jsonl")
}

function Add-ScanResult {
    # One appended line per result. The previous version re-read and rewrote
    # the whole JSON document on every scan, which is quadratic in the number
    # of scans and leaves a truncated file if the run is killed mid-write.
    # scan-results.json keeps its shape: it is rendered once, at the end.
    param(
        [string]$ResultsFile,
        [hashtable]$ScanResult
    )

    try {
        $logPath = Get-ScanResultsLogPath -ResultsFile $ResultsFile
        if (-not $logPath) { return }

        # A process killed mid-append leaves a line with no terminator. Without
        # this, the next record would be glued onto it and both would be lost.
        if (Test-Path $logPath) {
            $stream = $null
            try {
                $stream = [IO.File]::Open($logPath, 'Open', 'ReadWrite')
                if ($stream.Length -gt 0) {
                    $null = $stream.Seek(-1, 'End')
                    if ($stream.ReadByte() -ne 10) {
                        $nl = [Text.Encoding]::UTF8.GetBytes("`n")
                        $stream.Write($nl, 0, $nl.Length)
                    }
                }
            } finally {
                if ($stream) { $stream.Dispose() }
            }
        }

        # -Compress keeps one result on one line; embedded newlines in error
        # text are escaped by ConvertTo-Json, so a line is always one record.
        $line = $ScanResult | ConvertTo-Json -Depth 10 -Compress
        Add-Content -Path $logPath -Value $line -Encoding UTF8 -ErrorAction Stop

        # Render scan-results.json every so often. The clean paths (end of run,
        # Ctrl+C) render it too, but a hard kill fires no handler at all, and
        # the artifact would otherwise stay the empty skeleton written at start.
        # Throttled by time rather than by count, so the cost does not grow
        # with the size of the list.
        if (-not $script:lastResultsExport) { $script:lastResultsExport = @{} }
        $last = $script:lastResultsExport[$logPath]
        if (-not $last -or ((Get-Date) - $last).TotalSeconds -ge 30) {
            Export-ScanResults -ResultsFile $ResultsFile
            $script:lastResultsExport[$logPath] = Get-Date
        }
    } catch {
        Write-Warning "Failed to save scan result: $_"
    }
}

function Export-ScanResults {
    # Render the append-only log into scan-results.json. Called when the run
    # ends and again if it is interrupted, so the artifact is never left behind
    # by a scan that did finish.
    param(
        [string]$ResultsFile,
        [string]$SessionId = ""
    )

    try {
        $logPath = Get-ScanResultsLogPath -ResultsFile $ResultsFile
        if (-not $logPath -or -not (Test-Path $logPath)) { return }

        $scans = @()
        foreach ($line in (Get-Content -Path $logPath -ErrorAction Stop)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try {
                $scans += ($line | ConvertFrom-Json)
            } catch {
                # A partial last line means the process died mid-append; the
                # records before it are still good, so keep them.
                Write-Warning "Skipping unreadable scan result line: $_"
            }
        }

        $session = $SessionId
        if ([string]::IsNullOrWhiteSpace($session) -and (Test-Path $ResultsFile)) {
            try {
                $existing = Get-Content -Path $ResultsFile -Raw | ConvertFrom-Json
                if ($existing.scan_session) { $session = $existing.scan_session }
            } catch { }
        }

        @{
            scan_session = $session
            scans = $scans
        } | ConvertTo-Json -Depth 10 | Set-Content -Path $ResultsFile -Encoding UTF8
    } catch {
        Write-Warning "Failed to write $ResultsFile : $_"
    }
}

# ---------------------------------------------------------------------------
# Host liveness classification
#
# Every profile carries -Pn, so nmap's own host status is always
# `state="up" reason="user-set"` and says nothing. The evidence that separates
# "powered off", "alive with every port closed" and "firewall drops everything"
# lives in the per-port `reason` attributes and in the <extraports> summary.
#
# Those survive `--open` only while a host has at least one open port. With zero
# open ports `--open` drops the entire <host> element -- which is precisely the
# "alive, every port closed" case -- so the TCP profiles no longer pass it. It
# costs almost nothing: on a full -p- scan nmap collapses the 65500 closed ports
# into one <extraports count="65500"> element.
#
#   open        at least one port strictly open
#   alive       no open port, but the target's own stack answered
#   filtered    probed, every answer was no-response: no evidence either way
#   unreachable only third-party ICMP (a router said no)
#   unknown     no usable evidence at all (missing/unreadable output)
#
# There is deliberately no `down`: under -Pn it cannot be earned. It belongs to
# the host-discovery pre-pass.
# ---------------------------------------------------------------------------

function Get-NormalizedNmapReason {
    param([string]$Reason)

    if ([string]::IsNullOrWhiteSpace($Reason)) { return "" }
    $r = $Reason.Trim().ToLowerInvariant()

    # <extrareasons> pluralises in some nmap versions ("resets", "no-responses",
    # "port-unreaches"). Capture before the second -match: it overwrites $Matches.
    if ($r -match '^(.*[^s])es$') {
        $stem = $Matches[1]
        if ($stem -match '(ch|sh|ss|x|z)$') { return $stem }
    }
    if ($r -match '^(.+?[^s])s$') { return $Matches[1] }
    return $r
}

function Get-NmapXmlPath {
    param(
        [string]$ResultFile,
        [string]$OutputFlag = ""
    )

    if ([string]::IsNullOrWhiteSpace($ResultFile)) { return "" }

    # Command-list mode: the author's own output flag decides whether an XML
    # file can exist at all. -oN/-oG/-oS produce none, so there is nothing to look for.
    switch ($OutputFlag) {
        "-oX" { if (Test-Path -LiteralPath $ResultFile) { return $ResultFile } else { return "" } }
        "-oN" { return "" }
        "-oG" { return "" }
        "-oS" { return "" }
    }

    $candidate = switch ([IO.Path]::GetExtension($ResultFile).ToLowerInvariant()) {
        ".xml"   { $ResultFile }
        ".nmap"  { [IO.Path]::ChangeExtension($ResultFile, ".xml") }
        ".gnmap" { [IO.Path]::ChangeExtension($ResultFile, ".xml") }
        default  { "$ResultFile.xml" }
    }

    if ($candidate -and (Test-Path -LiteralPath $candidate)) { return $candidate }
    return ""
}

function ConvertFrom-NmapXmlHost {
    # Pure extraction: no verdict logic, no I/O. With an empty $TargetHost this
    # aggregates every <host> in the document, which is what a -iL command-list
    # line produces.
    param(
        [xml]$Xml,
        [string]$TargetHost = ""
    )

    $facts = @{
        OpenCount     = 0
        ClosedCount   = 0
        FilteredCount = 0
        PortElements  = 0
        Reasons       = @{}
        HasClosedPort = $false
        Srtt          = $null
        StatusReason  = ""
        TraceLastHop  = ""
        HostAddress   = ""
        FirstOpen     = $null
        HostCount     = 0
        TimedOut      = $false
    }

    if (-not $Xml -or -not $Xml.nmaprun) { return $facts }

    $hostNodes = @($Xml.nmaprun.host) | Where-Object { $_ }
    if ($TargetHost) {
        $matched = @($hostNodes | Where-Object {
            $_.address -and (@($_.address) | Where-Object { $_.addr -eq $TargetHost })
        })
        # A hostname target never matches an <address addr="">; falling back to
        # every host beats reporting "no evidence" for a scan that has plenty.
        if ($matched.Count -gt 0) { $hostNodes = $matched }
    }

    $addReason = {
        param($Name, $Count)
        $r = Get-NormalizedNmapReason $Name
        if (-not $r) { return }
        if (-not $facts.Reasons.ContainsKey($r)) { $facts.Reasons[$r] = 0 }
        $facts.Reasons[$r] += [math]::Max([int]$Count, 1)
    }

    foreach ($h in $hostNodes) {
        $facts.HostCount++

        if ($h.status -and $h.status.reason) { $facts.StatusReason = [string]$h.status.reason }
        # --host-timeout fired: nmap gave up before probing, so an absent port
        # table means "we never looked", not "nothing answered".
        if ([string]$h.timedout -eq 'true') { $facts.TimedOut = $true }

        if (-not $facts.HostAddress -and $h.address) {
            $ipv4 = @($h.address) | Where-Object { $_.addrtype -eq 'ipv4' } | Select-Object -First 1
            if ($ipv4) { $facts.HostAddress = [string]$ipv4.addr }
        }

        # <times srtt> exists only when the target actually answered something.
        if ($h.times -and $h.times.srtt) {
            $srtt = 0.0
            if ([double]::TryParse([string]$h.times.srtt, [ref]$srtt) -and $srtt -gt 0) { $facts.Srtt = $srtt }
        }

        if ($h.trace -and $h.trace.hop) {
            $hops = @($h.trace.hop)
            $last = $hops[$hops.Count - 1]
            if ($last -and $last.ipaddr) { $facts.TraceLastHop = [string]$last.ipaddr }
        }

        if (-not $h.ports) { continue }

        foreach ($p in @($h.ports.port)) {
            if (-not $p -or -not $p.state) { continue }
            $facts.PortElements++
            $state = [string]$p.state.state
            & $addReason ([string]$p.state.reason) 1

            switch ($state) {
                'open' {
                    $facts.OpenCount++
                    if (-not $facts.FirstOpen) {
                        $facts.FirstOpen = @{
                            port   = [string]$p.portid
                            proto  = [string]$p.protocol
                            reason = [string]$p.state.reason
                        }
                    }
                }
                'closed'     { $facts.ClosedCount++; $facts.HasClosedPort = $true }
                'unfiltered' { $facts.HasClosedPort = $true }
                # filtered, open|filtered, closed|filtered
                default      { $facts.FilteredCount++ }
            }
        }

        # Under --open the individual closed ports are gone but this summary
        # survives, and it is what proves the host answered.
        foreach ($ep in @($h.ports.extraports)) {
            if (-not $ep) { continue }
            $count = 0
            [void][int]::TryParse([string]$ep.count, [ref]$count)
            $facts.PortElements += $count

            switch ([string]$ep.state) {
                'closed'     { $facts.ClosedCount += $count; if ($count -gt 0) { $facts.HasClosedPort = $true } }
                'unfiltered' { if ($count -gt 0) { $facts.HasClosedPort = $true } }
                default      { $facts.FilteredCount += $count }
            }

            foreach ($er in @($ep.extrareasons)) {
                if (-not $er -or -not $er.reason) { continue }
                $rc = 0
                [void][int]::TryParse([string]$er.count, [ref]$rc)
                & $addReason ([string]$er.reason) $rc
            }
        }
    }

    return $facts
}

function Resolve-LivenessVerdict {
    # The precedence table, first match wins. Pure: hashtable in, verdict out,
    # so the table can be tested cell by cell without an XML file per case.
    param(
        [hashtable]$Facts,
        [string]$TargetHost = ""
    )

    # The target's own stack answered.
    $aliveReasons = @(
        'syn-ack', 'reset', 'conn-refused', 'port-unreach', 'udp-response',
        'proto-response', 'echo-reply', 'syn', 'arp-response', 'localhost-response'
    )
    # Someone else answered for it. port-unreach (ICMP 3/3) is the target;
    # host-unreach and net-unreach (3/1, 3/0) are a router -- that split is the
    # whole point of the classification.
    $networkReasons = @(
        'host-unreach', 'net-unreach', 'proto-unreach', 'admin-prohibited',
        'host-prohibited', 'net-prohibited', 'tcp-response-from-other-host'
    )

    if (-not $Facts) { return @{ Verdict = 'unknown'; Evidence = 'no scan data' } }

    $reasonKeys  = @()
    if ($Facts.Reasons) { $reasonKeys = @($Facts.Reasons.Keys) }
    $aliveHits   = @($reasonKeys | Where-Object { $aliveReasons -contains $_ })
    $networkHits = @($reasonKeys | Where-Object { $networkReasons -contains $_ })

    # 1. open
    if ([int]$Facts.OpenCount -gt 0) {
        $why = "$($Facts.OpenCount) open"
        if ($Facts.FirstOpen) {
            $why += " ($($Facts.FirstOpen.port)/$($Facts.FirstOpen.proto)"
            if ($Facts.FirstOpen.reason) { $why += " $($Facts.FirstOpen.reason)" }
            $why += ")"
        }
        if ([int]$Facts.ClosedCount -gt 0)   { $why += "; $($Facts.ClosedCount) closed" }
        if ([int]$Facts.FilteredCount -gt 0) { $why += "; $($Facts.FilteredCount) filtered" }
        return @{ Verdict = 'open'; Evidence = $why }
    }

    # 2. alive -- any evidence the target itself responded
    $aliveWhy = @()
    if ($Facts.HasClosedPort -and [int]$Facts.ClosedCount -gt 0) { $aliveWhy += "$($Facts.ClosedCount) closed" }
    if ($aliveHits.Count -gt 0) { $aliveWhy += ($aliveHits -join ', ') }
    if ($null -ne $Facts.Srtt)  {
        # Persisted field: keep it locale-independent so the JSON does not change
        # shape with the operator's culture.
        $aliveWhy += ("srtt " + ([math]::Round($Facts.Srtt / 1000, 2)).ToString([cultureinfo]::InvariantCulture) + " ms")
    }

    $traceTarget = if ($TargetHost) { $TargetHost } else { [string]$Facts.HostAddress }
    if ($Facts.TraceLastHop -and $traceTarget -and $Facts.TraceLastHop -eq $traceTarget) {
        $aliveWhy += "traceroute reached target"
    }

    $statusReason = Get-NormalizedNmapReason ([string]$Facts.StatusReason)
    if ($statusReason -and $statusReason -notin @('user-set', 'no-response')) {
        $aliveWhy += "host status: $statusReason"
    }

    if ($aliveWhy.Count -gt 0) {
        return @{ Verdict = 'alive'; Evidence = "no open ports; " + ($aliveWhy -join '; ') }
    }

    # 3. unreachable -- only a third party answered
    if ($networkHits.Count -gt 0) {
        $why = $networkHits -join ', '
        if ($networkHits -contains 'admin-prohibited') { $why += " (source ambiguous)" }
        return @{ Verdict = 'unreachable'; Evidence = $why }
    }

    # 4. filtered -- probed, nothing came back
    if ([int]$Facts.PortElements -gt 0) {
        if ($Facts.TimedOut) {
            return @{ Verdict = 'unknown'; Evidence = "scan timed out after $($Facts.PortElements) port(s), none answered" }
        }
        return @{ Verdict = 'filtered'; Evidence = "$($Facts.FilteredCount) filtered, no response" }
    }

    # 5. unknown
    if ($Facts.TimedOut) {
        return @{ Verdict = 'unknown'; Evidence = 'scan timed out before any port was probed' }
    }
    return @{ Verdict = 'unknown'; Evidence = 'no usable evidence' }
}

function Get-LivenessVerdictFromText {
    # Fallback for .nmap / .gnmap when there is no usable XML.
    param([string]$Content)

    $empty = @{ Verdict = 'unknown'; Evidence = 'empty output'; OpenCount = 0; ClosedCount = 0; FilteredCount = 0 }
    if ([string]::IsNullOrWhiteSpace($Content)) { return $empty }

    $isGrepable = ($Content -match '(?m)^# Nmap .* scan initiated') -and ($Content -match '\tPorts:')

    if ($isGrepable) {
        $open     = ([regex]::Matches($Content, '\d+/open/(tcp|udp)')).Count
        $closed   = ([regex]::Matches($Content, '\d+/closed/(tcp|udp)')).Count
        $filtered = ([regex]::Matches($Content, '\d+/(open\|)?filtered/(tcp|udp)')).Count
    } else {
        # The trailing \s is what keeps "53/udp open|filtered domain" out: a bare
        # `open` prefix used to be counted as an open port, so an unresponsive
        # UDP host was reported alive.
        $open     = ([regex]::Matches($Content, '(?m)^\s*\d+/(tcp|udp)\s+open(\s|$)')).Count
        $closed   = ([regex]::Matches($Content, '(?m)^\s*\d+/(tcp|udp)\s+closed(\s|$)')).Count
        $filtered = ([regex]::Matches($Content, '(?m)^\s*\d+/(tcp|udp)\s+(open\|)?filtered(\s|$)')).Count

        $notShownClosed = [regex]::Match($Content, '(?i)Not shown:\s*(\d+)\s+closed')
        if ($notShownClosed.Success) { $closed += [int]$notShownClosed.Groups[1].Value }

        $notShownFiltered = [regex]::Match($Content, '(?i)Not shown:\s*(\d+)\s+filtered')
        if ($notShownFiltered.Success) { $filtered += [int]$notShownFiltered.Groups[1].Value }
    }

    $counts = @{ OpenCount = $open; ClosedCount = $closed; FilteredCount = $filtered }

    if ($open -gt 0) {
        return $counts + @{ Verdict = 'open'; Evidence = "$open open (text output)" }
    }
    if ($closed -gt 0) {
        return $counts + @{ Verdict = 'alive'; Evidence = "no open ports; $closed closed (text output)" }
    }
    # "Host is up (0.0012s latency)." -- the parenthetical only appears when the
    # target answered. Under -Pn an unresponsive host prints a bare "Host is up."
    if ($Content -match '(?i)Host is up\s*\(') {
        return $counts + @{ Verdict = 'alive'; Evidence = 'no open ports; host answered (latency reported)' }
    }
    if ($Content -match '(?i)(host-unreach|net-unreach|admin-prohibited|Host seems down)') {
        return $counts + @{ Verdict = 'unreachable'; Evidence = 'network-level rejection (text output)' }
    }
    if ($filtered -gt 0 -or $Content -match '(?i)Host is up\.') {
        return $counts + @{ Verdict = 'filtered'; Evidence = "$filtered filtered, no response (text output)" }
    }

    return $counts + @{ Verdict = 'unknown'; Evidence = 'no usable evidence (text output)' }
}

function Get-HostLivenessVerdict {
    # Public entry point. XML first, text fallback, never throws.
    param(
        [string]$ResultFile,
        [string]$TargetHost = "",
        [string]$OutputFlag = "",
        [int]$MaxXmlBytes = 33554432
    )

    $result = @{
        Verdict = 'unknown'; Evidence = 'no scan output'; Source = 'none'
        OpenCount = 0; ClosedCount = 0; FilteredCount = 0; SrttMs = $null
    }
    if ([string]::IsNullOrWhiteSpace($ResultFile)) { return $result }

    # Prefer the .xml sibling -oA already writes; otherwise fall back to whatever
    # the caller handed us, which may itself be XML (that is how the tests call it).
    $xmlPath = Get-NmapXmlPath -ResultFile $ResultFile -OutputFlag $OutputFlag
    $raw     = ""
    $source  = ""

    $readPath = if ($xmlPath) { $xmlPath } else { $ResultFile }
    if (-not (Test-Path -LiteralPath $readPath)) { return $result }

    try {
        $size = (Get-Item -LiteralPath $readPath -ErrorAction Stop).Length
        if ($size -gt $MaxXmlBytes -and $xmlPath) {
            Write-Warning "Skipping XML parse of $xmlPath ($([math]::Round($size / 1MB)) MB); using text output instead"
            $xmlPath = ""
            $readPath = $ResultFile
            if (-not (Test-Path -LiteralPath $readPath)) { return $result }
        }
        $raw = Get-Content -LiteralPath $readPath -Raw -ErrorAction Stop
    } catch {
        return $result
    }

    if ([string]::IsNullOrWhiteSpace($raw)) { return $result }

    $looksXml = $xmlPath -or ($raw -match '<\?xml') -or ($raw -match '<nmaprun')

    if ($looksXml) {
        $doc = $null
        try {
            if ($raw -match '</nmaprun>') {
                $doc = [xml]$raw
                $source = 'xml'
            } else {
                # nmap flushes <host> elements as they finish, so a killed run
                # leaves a valid prefix plus a partial tail. Dropping trailing
                # bytes can only lose a host, never invent a verdict.
                $lastHost = $raw.LastIndexOf('</host>')
                if ($lastHost -ge 0) {
                    $doc = [xml]($raw.Substring(0, $lastHost + 7) + [Environment]::NewLine + '</nmaprun>')
                    $source = 'xml-repaired'
                }
            }
        } catch {
            $doc = $null
        }

        if ($doc) {
            $facts   = ConvertFrom-NmapXmlHost -Xml $doc -TargetHost $TargetHost
            $verdict = Resolve-LivenessVerdict -Facts $facts -TargetHost $TargetHost
            return @{
                Verdict       = $verdict.Verdict
                Evidence      = $verdict.Evidence
                Source        = $source
                OpenCount     = [int]$facts.OpenCount
                ClosedCount   = [int]$facts.ClosedCount
                FilteredCount = [int]$facts.FilteredCount
                SrttMs        = $(if ($null -ne $facts.Srtt) { [math]::Round($facts.Srtt / 1000, 3) } else { $null })
            }
        }

        # Unrepairable XML: if we were reading a sibling, the text output may
        # still be intact.
        if ($xmlPath -and $xmlPath -ne $ResultFile -and (Test-Path -LiteralPath $ResultFile)) {
            try { $raw = Get-Content -LiteralPath $ResultFile -Raw -ErrorAction Stop } catch { return $result }
        }
    }

    $text = Get-LivenessVerdictFromText -Content $raw
    return @{
        Verdict       = $text.Verdict
        Evidence      = $text.Evidence
        Source        = $(if (($raw -match '(?m)^# Nmap .* scan initiated') -and ($raw -match '\tPorts:')) { 'grepable' } else { 'text' })
        OpenCount     = [int]$text.OpenCount
        ClosedCount   = [int]$text.ClosedCount
        FilteredCount = [int]$text.FilteredCount
        SrttMs        = $null
    }
}

function Get-PersistedLiveness {
    # The verdict recorded in state, or one recomputed from disk exactly once for
    # a state file written before liveness existed. Never throws.
    param(
        $HostState,
        [string]$TargetHost = ""
    )

    if (-not $HostState) { return "" }

    $stored = ""
    try { $stored = [string]$HostState.liveness } catch { $stored = "" }
    if ($stored) { return $stored }

    $scanFile = ""
    try { $scanFile = [string]$HostState.scan_file } catch { $scanFile = "" }
    if (-not $scanFile) { return "" }

    $outputFlag = ""
    try { $outputFlag = [string]$HostState.output_flag } catch { $outputFlag = "" }

    try {
        return (Get-HostLivenessVerdict -ResultFile $scanFile -TargetHost $TargetHost -OutputFlag $outputFlag).Verdict
    } catch {
        return ""
    }
}

function Test-HostNeedsRescan {
    # Shared predicate for the four retry-dead branches.
    param(
        $HostState,
        [ValidateSet('NoResponse', 'NoOpenPorts')]
        [string]$Mode = 'NoResponse'
    )

    $verdict = Get-PersistedLiveness -HostState $HostState
    # Unclassifiable, or the output file is gone: rescan, as before.
    if (-not $verdict) { return $true }

    switch ($Mode) {
        'NoResponse'  { return ($verdict -in @('filtered', 'unreachable', 'unknown')) }
        'NoOpenPorts' { return ($verdict -ne 'open') }
    }
    return $true
}

function Format-LivenessCounters {
    # filtered + unreachable + unknown collapse into one "no response" figure:
    # five counters would push the ETA off a narrow terminal.
    param(
        [hashtable]$Counts = @{},
        [int]$Width = 120
    )

    $open   = [int]$Counts['open']
    $alive  = [int]$Counts['alive']
    $noResp = [int]$Counts['filtered'] + [int]$Counts['unreachable'] + [int]$Counts['unknown']

    if ($Width -ge 100) {
        return " | Open: $open | Alive: $alive | NoResp: $noResp"
    }
    return " | O:$open A:$alive N:$noResp"
}

function Test-HostHasOpenPorts {
    # Kept as a thin wrapper over the verdict: callers that only need "is there
    # anything to attack here" keep working unchanged.
    param([string]$XmlFile)

    if ([string]::IsNullOrWhiteSpace($XmlFile)) { return $false }
    if (-not (Test-Path $XmlFile)) { return $false }

    return ((Get-HostLivenessVerdict -ResultFile $XmlFile).Verdict -eq 'open')
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
        [hashtable]$LivenessCounts = @{},
        [hashtable]$ActiveJobs = @{},
        [DateTime]$ScanStartTime = [DateTime]::MinValue,
        [array]$CompletedDurations = @(),
        [int]$Concurrency = 1,
        [DateTime]$StopTime = [DateTime]::MinValue,
        [int]$PendingRetries = 0
    )

    $percent = if ($Total -gt 0) { [math]::Min([math]::Round(($Completed / $Total) * 100, 1), 100) } else { 0 }
    $successful = $Completed - $Failed

    # Liveness is tallied as each job finishes, so nothing here touches the disk.
    $openHosts = [int]$LivenessCounts['open']
    $livenessSummary = Format-LivenessCounters -Counts $LivenessCounts -Width $(
        try { $Host.UI.RawUI.WindowSize.Width } catch { 120 }
    )

    # Calculate elapsed time
    $elapsedStr = ""
    $etaStr = ""
    if ($ScanStartTime -ne [DateTime]::MinValue) {
        $elapsed = (Get-Date) - $ScanStartTime
        $elapsedStr = Format-Duration -TimeSpan $elapsed

        # Calculate ETA (only after 10 completed scans)
        if ($CompletedDurations.Count -ge 10 -and $Total -gt $Completed) {
            $avgDuration = ($CompletedDurations | Measure-Object -Average).Average
            $remainingHosts = $Total - $Completed
            # Hosts are scanned in parallel, so the remaining wall-clock time is
            # the serial estimate divided by how many run at once.
            $parallel = [math]::Max(1, [math]::Min($Concurrency, $remainingHosts))
            $estimatedSeconds = ($remainingHosts * $avgDuration) / $parallel
            $eta = [TimeSpan]::FromSeconds($estimatedSeconds)
            $etaStr = " / ~$(Format-Duration -TimeSpan $eta) ETA"
        }
    }

    # Wall clock and, when the run has a deadline, how long is left of it. The
    # elapsed counter above answers "how long have I been here"; this answers
    # "how much of the window is left", which is the one with a hard edge.
    $clockStr = " | Now: $((Get-Date).ToString('HH:mm:ss'))"
    if ($StopTime -ne [DateTime]::MinValue) {
        $clockStr += " | Stop: $($StopTime.ToString('HH:mm:ss')) (in $(Get-TimeRemainingText -Target $StopTime))"
    }

    # Failed scans waiting out their retry delay. Without this, a run whose
    # last hosts are all waiting to retry looks exactly like a stuck one.
    $retryStr = if ($PendingRetries -gt 0) { " | Retry: $PendingRetries" } else { "" }

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
        $mainStatus = "Step ${WorkflowStep}/${WorkflowTotalSteps}: ${StepProfile} | Open: ${openHosts}/${Total} hosts"

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
        $secondaryStatus = "$Completed/$Total ($percent%) | OK: $successful | Fail: $Failed$retryStr"
        $secondaryStatus += $livenessSummary

        if ($elapsedStr -ne "") {
            $secondaryStatus += " | Time: $elapsedStr$etaStr"
        }
        $secondaryStatus += $clockStr

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
        $statusMessage = "$Completed/$Total ($percent%) | OK: $successful | Fail: $Failed$retryStr"
        $statusMessage += $livenessSummary

        if ($elapsedStr -ne "") {
            $statusMessage += " | Time: $elapsedStr$etaStr"
        }
        $statusMessage += $clockStr

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
            Write-Host "  $([char]0x2713) $($net.Key): $($net.Value.Open)/$($net.Value.Total) with open ports ($($net.Value.Alive) responded)" -ForegroundColor Green
        }
    }

    # Show partially scanned networks
    if ($partial.Count -gt 0) {
        Write-Host "`nPartially Scanned Networks ($($partial.Count)):" -ForegroundColor Yellow
        foreach ($net in ($partial | Sort-Object Key)) {
            $percent = [math]::Round(($net.Value.Scanned / $net.Value.Total) * 100, 1)
            Write-Host "  $([char]0x26A0) $($net.Key): $($net.Value.Scanned)/$($net.Value.Total) scanned ($percent%) | $($net.Value.Open) open, $($net.Value.Alive) responded" -ForegroundColor Yellow
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
            $response = Invoke-WebRequest -Uri $ConfigPath -UseBasicParsing -ErrorAction Stop
            # .Content is a byte[] when the server does not advertise a text
            # content type (WebClient.DownloadString always returned a string)
            $content = if ($response.Content -is [byte[]]) {
                [System.Text.Encoding]::UTF8.GetString($response.Content)
            } else {
                $response.Content
            }
            $content = $content -replace "^\uFEFF", ""
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
            command = "nmap -v -T4 -Pn -sS --script=default,vuln -A --host-timeout 60m"
        }
        "tcp-full" = @{
            name = "TCP Full Port Scan"
            description = "Complete TCP scan of all 65535 ports"
            command = "nmap -v -T4 -Pn -sS --script=default,vuln -A --host-timeout 60m -p-"
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

# Global ScriptBlock for nmap scan jobs (reusable across retry and initial scans)
$Global:NmapScanScriptBlock = {
    param($TargetHost, $ScanCommand, $OutputPath, $FileName, $Attempts, $Unprivileged, $NmapPath, $Verbatim, $ResultFile)

    $startTime = Get-Date

    # Execute scan - Build argument list properly
    $nmapArgs = @()

    # Parse command into arguments (handle quoted strings)
    $cmdWithoutNmap = $ScanCommand -replace '^nmap\s+', ''
    $regex = [regex]'(?:[^\s"'']+|"[^"]*"|''[^'']*'')+'
    $argMatches = $regex.Matches($cmdWithoutNmap)
    foreach ($argMatch in $argMatches) {
        $arg = $argMatch.Value.Trim('"').Trim("'")
        # Replace -sS with -sT if unprivileged mode is enabled
        if ($Unprivileged -and $arg -eq "-sS") {
            $nmapArgs += "-sT"
        } else {
            $nmapArgs += $arg
        }
    }

    # Add --unprivileged if specified. ConvertTo-UnprivilegedCommand may have
    # already added it at the command-string level, so guard against duplicates.
    if ($Unprivileged -and $nmapArgs -notcontains "--unprivileged") {
        $nmapArgs += "--unprivileged"
    }

    # Command-list mode: the author's line already carries its own output flag
    # and target, and nmap refuses a second -oA, so add nothing.
    $outputFullPath = [IO.Path]::Combine($OutputPath, $FileName)
    if (-not $Verbatim) {
        # Never quote here: each argv element is passed to the process verbatim,
        # so quotes would end up inside the filename.
        $nmapArgs += @("-oA", $outputFullPath, $TargetHost)
    }

    # Use the resolved nmap path: under sudo, secure_path hides Homebrew's bin
    $nmapExe = if ($NmapPath) { $NmapPath } else { "nmap" }

    $stdoutFile = "$outputFullPath.stdout"
    $stderrFile = "$outputFullPath.stderr"

    # Native stderr must not be turned into a terminating error, and a non-zero
    # exit code is handled below rather than thrown (PS 7.4+ default).
    $ErrorActionPreference = "Continue"
    $PSNativeCommandUseErrorActionPreference = $false

    try {
        # The call operator, not Start-Process: on Linux/macOS, Start-Process
        # flattens -ArgumentList into a single string and the arguments are then
        # re-split on whitespace, so any path containing a space reaches nmap as
        # several bogus targets. "&" passes the array as argv.
        & $nmapExe @nmapArgs 1> $stdoutFile 2> $stderrFile
        $exitCode = $LASTEXITCODE
        $endTime = Get-Date
        $duration = $endTime - $startTime

        $errorOutput = if (Test-Path $stderrFile) {
            Get-Content $stderrFile -Raw
        } else { "" }

        # Add exit code to error message for debugging
        if ($exitCode -ne 0) {
            $errorOutput = "Nmap exited with code $exitCode. " + $errorOutput
        }

        # Verify that nmap actually created output files
        $expectedOutput = if ($Verbatim) { $ResultFile } else { "$outputFullPath.nmap" }
        $nmapFileExists = if ($expectedOutput) { Test-Path $expectedOutput } else { $exitCode -eq 0 }
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
        [bool]$Unprivileged,
        [string]$NmapPath = "nmap",
        [bool]$Verbatim = $false,
        [string]$ResultFile = ""
    )

    return Start-Job -ScriptBlock $Global:NmapScanScriptBlock -ArgumentList $TargetHost, $ScanCommand, $OutputPath, $FileName, $Attempts, $Unprivileged, $NmapPath, $Verbatim, $ResultFile
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
        Write-Host "`nNo sessions found in: " -NoNewline -ForegroundColor Yellow
        Write-Host "$OutputDir" -ForegroundColor White
        Write-Host ""
        Write-Host "The " -NoNewline -ForegroundColor Gray
        Write-Host ".sessions/" -NoNewline -ForegroundColor Cyan
        Write-Host " directory does not exist here." -ForegroundColor Gray
        Write-Host ""
        Write-Host "Suggestions:" -ForegroundColor Cyan
        Write-Host "  • Use " -NoNewline -ForegroundColor Gray
        Write-Host "-OutputDir <directory>" -NoNewline -ForegroundColor Yellow
        Write-Host " to look in a different directory" -ForegroundColor Gray
        Write-Host "  • Use " -NoNewline -ForegroundColor Gray
        Write-Host "-SessionName <name>" -NoNewline -ForegroundColor Yellow
        Write-Host " to create a new named session" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Example:" -ForegroundColor Cyan
        Write-Host "  $(Get-InvocationHint) -ListSessions -OutputDir <your-directory>" -ForegroundColor White
        Write-Host ""
        return @()
    }

    # Get all session directories
    $sessionDirs = Get-ChildItem -Path $sessionsDir -Directory

    if ($sessionDirs.Count -eq 0) {
        Write-Host "`nNo sessions found in: " -NoNewline -ForegroundColor Yellow
        Write-Host "$OutputDir" -ForegroundColor White
        Write-Host ""
        Write-Host "The directory exists but contains no sessions." -ForegroundColor Gray
        Write-Host ""
        Write-Host "Suggestions:" -ForegroundColor Cyan
        Write-Host "  • Use " -NoNewline -ForegroundColor Gray
        Write-Host "-SessionName <name>" -NoNewline -ForegroundColor Yellow
        Write-Host " to create a new named session" -ForegroundColor Gray
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
                $startTime = ConvertTo-ScanyxDateTime $state.start_time
                if ($startTime) {
                    $endTime = ConvertTo-ScanyxDateTime $state.end_time
                    if ($endTime) {
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
                Write-Warning "Failed to load session state: $($dir.Name) - $($_.Exception.Message)"
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
            $startParsed = ConvertTo-ScanyxDateTime $session.StartTime
            $startFormatted = if ($startParsed) { $startParsed.ToString("yyyy-MM-dd HH:mm:ss") } else { "?" }
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

        $relativePath = $session.StateFile.Replace($OutputDir, "").TrimStart([char[]]@('\', '/'))
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

    # Clear-Host writes escape codes; skip it when output is redirected (no TTY)
    if (-not [Console]::IsOutputRedirected) { try { Clear-Host } catch { } }
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

    Write-Host "  Use unprivileged mode (--unprivileged)? [y/N]: " -NoNewline -ForegroundColor Cyan
    $unprivileged = Read-Host
    $result.Unprivileged = ($unprivileged -match '^[YySs]')

    Write-Host "  Custom configuration file (optional): " -NoNewline -ForegroundColor Cyan
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
    Write-Host "│ CONFIGURATION SUMMARY                                                       │" -ForegroundColor Cyan
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
        Write-Host "  Session name   : " -NoNewline -ForegroundColor White
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

    $cmd = Get-InvocationHint

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
    Write-Host "  Run this scan now? [Y/n]: " -NoNewline -ForegroundColor Cyan
    $execute = Read-Host

    return ($execute -eq "" -or $execute -match '^[YySs]')
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

        # Resume and retry hosts that showed no evidence of a response
        # (filtered / unreachable / unclassifiable)
        [Parameter(Mandatory = $false)]
        [switch]$ResumeRetryDead,

        # Retry only failed hosts
        [Parameter(Mandatory = $false)]
        [switch]$RetryFailed,

        # Retry only hosts that showed no evidence of a response
        # (skip pending, failed, and anything that answered)
        [Parameter(Mandatory = $false)]
        [switch]$RetryDead,

        # Retry every completed host without an open port, including the ones
        # that answered on every closed port. The pre-liveness -RetryDead.
        [Parameter(Mandatory = $false)]
        [switch]$ResumeRetryNoOpenPorts,

        [Parameter(Mandatory = $false)]
        [switch]$RetryNoOpenPorts,

        # Force fresh start (archive old state)
        [Parameter(Mandatory = $false)]
        [switch]$Force,

        # Use unprivileged mode for nmap scans (adds --unprivileged flag)
        [Parameter(Mandatory = $false)]
        [switch]$Unprivileged,

        # On Linux/macOS, degrade root-only scans instead of prompting or aborting.
        # Intended for non-interactive use (CI, cron). Cannot rescue -sU / -sO.
        [Parameter(Mandatory = $false)]
        [switch]$AutoUnprivileged,

        # Skip the pre-flight confirmation and start scanning straight away
        [Parameter(Mandatory = $false)]
        [switch]$Yes,

        # Stop the scan at a scheduled time: a clock time ("23:30"), a date and
        # time ("2026-09-18 06:00") or a relative span ("+90m", "1h30m").
        # Nothing new is launched after it, whatever is running is stopped, and
        # the rest stays pending for -ResumeSession.
        [Parameter(Mandatory = $false)]
        [string]$StopAt = "",

        # What to do with the scans still running when -StopAt arrives:
        # Hard stops them too (nothing on the wire after that time), Drain lets
        # them finish and only stops new ones from starting.
        [Parameter(Mandatory = $false)]
        [ValidateSet("Hard", "Drain")]
        [string]$StopMode = "Hard",

        # Hold the scan until a scheduled time, same formats as -StopAt. The
        # wait happens in this process: no cron, so it has to stay alive.
        [Parameter(Mandatory = $false)]
        [string]$StartAt = "",

        # Recurring window the scan is allowed to run in, for work that takes
        # more than one sitting: "L-V 08:00-17:00", "L,J,V 08:00-17:00",
        # "Mon-Fri 08:00-17:00; S 10:00-14:00", "V 22:00-06:00".
        # Outside the window Scanyx waits and then carries on where it stopped.
        [Parameter(Mandatory = $false)]
        [string]$Schedule = "",

        # End of the engagement: nothing runs past it. A bare date means the end
        # of that day. "2026-09-18", "18/09/2026", "2026-09-18 17:00", "+3d".
        [Parameter(Mandatory = $false)]
        [string]$Until = "",

        # A file of complete nmap command lines, one per line, written by the
        # consultant. Scanyx runs them with its own tracking, retries, state
        # and resume instead of replacing them with a profile.
        [Parameter(Mandatory = $false, ParameterSetName = 'CommandList')]
        [string]$CommandFile = "",

        # The same, inline
        [Parameter(Mandatory = $false, ParameterSetName = 'CommandList')]
        [string[]]$Commands = @(),

        # Parse the list and show each unit with its state, without scanning
        [Parameter(Mandatory = $false, ParameterSetName = 'CommandList')]
        [switch]$ListCommands,

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
    if ($IsLinux -or $IsMacOS) {
        Write-Host "        macOS: brew install nmap    Debian/Kali: sudo apt-get install -y nmap" -ForegroundColor Yellow
    }
    return
}

# Resolve nmap once, up front: background jobs inherit a reduced PATH under sudo
$nmapExePath = Get-NmapPath

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
$resumeParams = @($Resume.IsPresent, $ResumeRetryFailed.IsPresent, $ResumeRetryDead.IsPresent, $RetryFailed.IsPresent, $RetryDead.IsPresent, $ResumeRetryNoOpenPorts.IsPresent, $RetryNoOpenPorts.IsPresent, $Force.IsPresent)
$resumeParamsCount = ($resumeParams | Where-Object { $_ }).Count
if ($resumeParamsCount -gt 1) {
    Write-Host "[ERROR] Parameters -Resume, -ResumeRetryFailed, -ResumeRetryDead, -RetryFailed, -RetryDead, -ResumeRetryNoOpenPorts, -RetryNoOpenPorts, and -Force are mutually exclusive. Use only one." -ForegroundColor DarkRed
    return
}

# ---------------------------------------------------------------------------
# Scheduled stop: resolve it before anything is read, expanded or created, so a
# typo in the one parameter that guards the engagement window fails here rather
# than three hours into the scan.
# ---------------------------------------------------------------------------
$stopTime = $null
if ($StopAt -and $StopAt -ne "") {
    $stopParsed = Resolve-StopTime -Value $StopAt
    if (-not $stopParsed.Ok) {
        Write-Host "[ERROR] $($stopParsed.Error)" -ForegroundColor DarkRed
        Write-Host "" -ForegroundColor Gray
        Write-Host "Accepted formats for -StopAt:" -ForegroundColor Yellow
        Write-Host "  23:30            clock time today (tomorrow if it already passed)" -ForegroundColor Gray
        Write-Host "  23:30:00         the same, to the second" -ForegroundColor Gray
        Write-Host "  2026-09-18 06:00 an explicit date and time" -ForegroundColor Gray
        Write-Host "  +90m / 2h / 1h30m / 1d2h   a span from now" -ForegroundColor Gray
        Write-Host "" -ForegroundColor Gray
        return
    }
    $stopTime = $stopParsed.Time
}

$startTime = $null
if ($StartAt -and $StartAt -ne "") {
    $startParsed = Resolve-StopTime -Value $StartAt
    if (-not $startParsed.Ok) {
        Write-Host "[ERROR] -StartAt: $($startParsed.Error)" -ForegroundColor DarkRed
        Write-Host "" -ForegroundColor Gray
        Write-Host "Accepted formats for -StartAt and -StopAt:" -ForegroundColor Yellow
        Write-Host "  22:00            clock time today (tomorrow if it already passed)" -ForegroundColor Gray
        Write-Host "  22:00:00         the same, to the second" -ForegroundColor Gray
        Write-Host "  2026-09-18 22:00 an explicit date and time" -ForegroundColor Gray
        Write-Host "  +90m / 2h / 1h30m / 1d2h   a span from now" -ForegroundColor Gray
        Write-Host "" -ForegroundColor Gray
        return
    }
    $startTime = $startParsed.Time

    # A window that closes before it opens scans nothing at all. Say so now,
    # rather than after waiting until 22:00 to stop at 22:00.
    if ($stopTime -and $stopTime -le $startTime) {
        Write-Host "[ERROR] The scheduled stop ($($stopTime.ToString('yyyy-MM-dd HH:mm:ss'))) is not after the scheduled start ($($startTime.ToString('yyyy-MM-dd HH:mm:ss')))." -ForegroundColor DarkRed
        Write-Host "        A bare clock time always resolves to the next time it comes round," -ForegroundColor Gray
        Write-Host "        so for a window crossing midnight give the date: -StopAt `"$((Get-Date).AddDays(1).ToString('yyyy-MM-dd')) 06:00`"" -ForegroundColor Gray
        Write-Host "" -ForegroundColor Gray
        return
    }
}

# ---------------------------------------------------------------------------
# Recurring windows: the scan runs inside them, sleeps between them, and ends
# for good at -Until. The pair is what makes a scan that does not fit in one
# sitting survivable without anyone relaunching it every morning.
# ---------------------------------------------------------------------------
$scheduleWindows = $null
if ($Schedule -and $Schedule -ne "") {
    $scheduleParsed = ConvertFrom-ScheduleSpec -Spec $Schedule
    if (-not $scheduleParsed.Ok) {
        Write-Host "[ERROR] -Schedule: $($scheduleParsed.Error)" -ForegroundColor DarkRed
        Write-Host "" -ForegroundColor Gray
        Write-Host "Examples:" -ForegroundColor Yellow
        Write-Host "  -Schedule `"L-V 08:00-17:00`"                 weekdays, office hours" -ForegroundColor Gray
        Write-Host "  -Schedule `"L,J,V 08:00-17:00`"               only Monday, Thursday and Friday" -ForegroundColor Gray
        Write-Host "  -Schedule `"Mon-Fri 08:00-17:00; S 10:00-14:00`"  two windows" -ForegroundColor Gray
        Write-Host "  -Schedule `"V 22:00-06:00`"                   Friday night into Saturday" -ForegroundColor Gray
        Write-Host "  -Schedule `"08:00-17:00`"                     every day" -ForegroundColor Gray
        Write-Host "" -ForegroundColor Gray
        return
    }
    $scheduleWindows = $scheduleParsed.Windows
}

$overallDeadline = $null
if ($Until -and $Until -ne "") {
    $untilParsed = Resolve-DeadlineTime -Value $Until
    if (-not $untilParsed.Ok) {
        Write-Host "[ERROR] -Until: $($untilParsed.Error)" -ForegroundColor DarkRed
        Write-Host "        Accepted: 2026-09-18, 18/09/2026, `"2026-09-18 17:00`", +3d" -ForegroundColor Gray
        Write-Host "" -ForegroundColor Gray
        return
    }
    $overallDeadline = $untilParsed.Time
}

if ($scheduleWindows) {
    # With a schedule, the daily hours come from -Schedule and -StopAt can only
    # mean the end of the whole thing, which is what -Until says.
    if ($stopTime -and $overallDeadline) {
        Write-Host "[ERROR] With -Schedule, use -Until for the end of the engagement, not both -Until and -StopAt." -ForegroundColor DarkRed
        Write-Host "" -ForegroundColor Gray
        return
    }
    if ($stopTime) {
        $overallDeadline = $stopTime
        Write-Host "[INFO] With -Schedule, -StopAt is taken as the end of the engagement ($($overallDeadline.ToString('yyyy-MM-dd HH:mm:ss')))." -ForegroundColor Cyan
    }
    # Per-window stops are computed as each window opens
    $stopTime = $null
    $stopTimeForProgress = [DateTime]::MinValue

    if ($overallDeadline) {
        $probeFrom = if ($startTime) { $startTime } else { Get-Date }
        $opensInside = Get-ScheduleWindowFor -Windows $scheduleWindows -Now $probeFrom
        $opensNext   = Get-NextScheduleOpen  -Windows $scheduleWindows -Now $probeFrom
        if (-not $opensInside -and (-not $opensNext -or $opensNext -ge $overallDeadline)) {
            Write-Host "[ERROR] The schedule never opens before $($overallDeadline.ToString('yyyy-MM-dd HH:mm:ss')), so nothing would be scanned." -ForegroundColor DarkRed
            if ($opensNext) {
                Write-Host "        It next opens $($opensNext.ToString('yyyy-MM-dd HH:mm')), after that deadline." -ForegroundColor Gray
            }
            Write-Host "" -ForegroundColor Gray
            return
        }
    }
} elseif ($overallDeadline) {
    # No schedule: -Until is just another way of saying -StopAt
    if (-not $stopTime) {
        $stopTime = $overallDeadline
        $stopTimeForProgress = $stopTime
    } elseif ($stopTime -ne $overallDeadline) {
        Write-Host "[ERROR] -StopAt and -Until disagree; without -Schedule they mean the same thing, so give only one." -ForegroundColor DarkRed
        Write-Host "" -ForegroundColor Gray
        return
    }
}

if ($StopMode -eq "Drain" -and -not $stopTime -and -not $scheduleWindows) {
    Write-Host "[WARNING] -StopMode only applies together with -StopAt or -Schedule; ignoring it." -ForegroundColor Yellow
}

# Show-ProgressBar takes a [DateTime], which will not bind $null
$stopTimeForProgress = if ($stopTime) { $stopTime } else { [DateTime]::MinValue }

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

# ---------------------------------------------------------------------------
# Command-list mode: the unit of work is a line the consultant already wrote,
# not a target plus a profile. Everything downstream (state, resume, sessions,
# retries, summary) is the same engine.
# ---------------------------------------------------------------------------
$isCommandMode = ($CommandFile -and $CommandFile -ne "") -or ($Commands.Count -gt 0)
$commandUnits = @()

if ($isCommandMode) {
    $conflicting = @()
    if ($ScanType -and $ScanType -ne "")   { $conflicting += "-ScanType" }
    if ($Workflow -and $Workflow -ne "")   { $conflicting += "-Workflow" }
    if ($HostFile -and $HostFile -ne "")   { $conflicting += "-HostFile" }
    if ($Hosts.Count -gt 0)                { $conflicting += "-Hosts" }
    if ($SensitiveFile -and $SensitiveFile -ne "") { $conflicting += "-SensitiveFile" }
    if ($SensitiveHosts.Count -gt 0)       { $conflicting += "-SensitiveHosts" }
    if ($conflicting.Count -gt 0) {
        Write-Host "[ERROR] $($conflicting -join ', ') cannot be combined with -CommandFile/-Commands." -ForegroundColor DarkRed
        Write-Host "        In command-list mode each line already carries its own target and flags." -ForegroundColor Yellow
        return
    }

    $listLines = @()
    if ($CommandFile -and $CommandFile -ne "") {
        if (-not (Test-Path $CommandFile)) {
            Write-Host "[ERROR] Command file not found: $CommandFile" -ForegroundColor DarkRed
            return
        }
        $listLines += Get-Content $CommandFile
    }
    if ($Commands.Count -gt 0) { $listLines += $Commands }

    # Relative -oA paths resolve against the invocation directory, exactly as
    # they would running the list by hand. A background job does not reliably
    # inherit the working directory, so this is pinned here rather than there.
    $invocationDir = (Get-Location).Path
    $commandFallbackDir = [IO.Path]::Combine($OutputDir, "commands")
    $parsed = Read-CommandList -Lines $listLines -BaseDirectory $invocationDir -FallbackOutputDir $commandFallbackDir
    $commandUnits = $parsed.Units

    if ($parsed.Rejected.Count -gt 0) {
        Write-Host "[ERROR] $($parsed.Rejected.Count) line(s) could not be used:" -ForegroundColor DarkRed
        foreach ($bad in $parsed.Rejected) {
            Write-Host "        line $($bad.LineNumber): $($bad.Errors -join '; ')" -ForegroundColor Yellow
            Write-Host "          $($bad.Raw.Trim())" -ForegroundColor DarkGray
        }
        Write-Host ""
        return
    }

    if ($commandUnits.Count -eq 0) {
        Write-Host "[ERROR] The command list is empty." -ForegroundColor DarkRed
        return
    }

    Write-Host "[INFO] Command list: $($commandUnits.Count) command(s)" -ForegroundColor Green
}

# Validate that either ScanType or Workflow is provided (mutually exclusive)
# Skip this validation if resuming a session (will use session's config)
if (-not $resumingSession -and -not $isCommandMode) {
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

# Validate ScanType or Workflow. Command-list mode has no profile to validate:
# every unit brings its own command.
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
} # End of if (-not $resumingSession -and -not $isCommandMode)

# Privilege gate (Linux/macOS only - Windows keeps its previous behaviour).
# nmap needs root for raw sockets, and every stock profile uses -sS or -sU plus -A.
# Every workflow step is checked up front: aborting on step 3 after 40 minutes is useless.
# -ListCommands never runs nmap, so it must not demand root to show a listing.
if (($IsLinux -or $IsMacOS) -and -not $ListCommands) {
    $profilesToCheck = @()
    if ($Workflow -and $Workflow -ne "" -and $scanWorkflows.ContainsKey($Workflow)) {
        $stepNum = 0
        foreach ($step in $scanWorkflows[$Workflow].steps) {
            $stepNum++
            $profilesToCheck += @{ Label = "Step $stepNum ('$($step.profile)')"; Profile = $step.profile }
        }
    } elseif ($ScanType -and $ScanType -ne "" -and $scanProfiles.ContainsKey($ScanType)) {
        $profilesToCheck += @{ Label = "Profile '$ScanType'"; Profile = $ScanType }
    } elseif ($isCommandMode) {
        # Each unit carries its own command, so the gate inspects the lines
        # themselves. Without this the consultant's -sU line would only fail
        # once nmap was already running.
        foreach ($unit in $commandUnits) {
            $profilesToCheck += @{ Label = "Line $($unit.LineNumber) ('$($unit.Label)')"; Profile = $null; Unit = $unit }
        }
    }

    if ($profilesToCheck.Count -gt 0 -and -not (Test-IsElevated)) {
        $blockingHits = @()
        $degradableHits = @()
        foreach ($entry in $profilesToCheck) {
            $entryCommand = if ($entry.Unit) { $entry.Unit.Command } else { $scanProfiles[$entry.Profile].command }
            $flags = Get-RootRequiredFlags -Command $entryCommand
            if ($flags.Blocking.Count -gt 0) {
                $blockingHits += @{ Label = $entry.Label; Flags = ($flags.Blocking -join ', ') }
            } elseif ($flags.Degradable.Count -gt 0) {
                $degradableHits += @{ Label = $entry.Label; Flags = ($flags.Degradable -join ', ') }
            }
        }

        $relaunchTarget = if ($isCommandMode) {
            if ($CommandFile) { "-CommandFile $CommandFile" } else { "-Commands ..." }
        } elseif ($Workflow) { "-Workflow $Workflow" } else { "-ScanType $ScanType" }
        $relaunch = "sudo $(Get-InvocationHint) $relaunchTarget"

        if ($blockingHits.Count -gt 0) {
            Write-Host ""
            foreach ($hit in $blockingHits) {
                Write-Host "[ERROR] $($hit.Label) requires root privileges on macOS/Linux (flag: $($hit.Flags))." -ForegroundColor DarkRed
            }
            Write-Host "        That flag cannot be downgraded: nmap cannot scan UDP or IP protocols without raw sockets." -ForegroundColor Yellow
            Write-Host "        Re-run with:  $relaunch`n" -ForegroundColor Yellow
            return
        }

        if ($degradableHits.Count -gt 0) {
            Write-Host ""
            Write-Host "[WARNING] This scan needs root privileges and you do not have them:" -ForegroundColor Yellow
            foreach ($hit in $degradableHits) {
                Write-Host "          - $($hit.Label): $($hit.Flags)" -ForegroundColor Yellow
            }

            $doDegrade = $false
            if ($Unprivileged -or $AutoUnprivileged) {
                $doDegrade = $true
                Write-Host "[INFO] Unprivileged mode requested: downgrading the profiles." -ForegroundColor Cyan
            } elseif ([Console]::IsInputRedirected) {
                Write-Host ""
                Write-Host "[ERROR] Refusing to downgrade silently without a terminal: it would change the results." -ForegroundColor DarkRed
                Write-Host "        Re-run with:        $relaunch" -ForegroundColor Yellow
                Write-Host "        Or accept the downgrade: -AutoUnprivileged`n" -ForegroundColor Yellow
                return
            } else {
                Write-Host ""
                Write-Host "  [1] Downgrade to an unprivileged scan (-sT, --unprivileged)" -ForegroundColor White
                Write-Host "      Slower and noisier: it leaves full connections in the target log," -ForegroundColor Gray
                Write-Host "      and you lose OS detection (-O) and traceroute." -ForegroundColor Gray
                Write-Host "  [2] Abort and re-run with sudo (recommended)" -ForegroundColor White
                Write-Host ""
                Write-Host "  Option [2]: " -NoNewline -ForegroundColor Cyan
                $privChoice = Read-Host
                if ($privChoice -eq "1") {
                    $doDegrade = $true
                } else {
                    Write-Host "`n[INFO] Aborted. Re-run with:  $relaunch`n" -ForegroundColor Yellow
                    return
                }
            }

            if ($doDegrade) {
                if ($isCommandMode) {
                    # Rewrite the unit in place. Its id is content-addressed, so
                    # recompute it: a downgraded command is genuinely a different
                    # scan and must not inherit the privileged run's results.
                    foreach ($unit in $commandUnits) {
                        $converted = ConvertTo-UnprivilegedCommand -Command $unit.Command
                        if ($converted -and $converted -ne $unit.Command) {
                            $unit.Command = $converted
                            $unit.Id = Get-CommandUnitId -Command $converted -Label $unit.Label
                            Write-Host "[INFO] line $($unit.LineNumber) -> $converted" -ForegroundColor DarkGray
                        }
                    }
                } else {
                    foreach ($profileName in @($profilesToCheck.Profile | Where-Object { $_ } | Select-Object -Unique)) {
                        $converted = ConvertTo-UnprivilegedCommand -Command $scanProfiles[$profileName].command
                        if ($converted) {
                            $scanProfiles[$profileName].command = $converted
                            Write-Host "[INFO] $profileName -> $converted" -ForegroundColor DarkGray
                        }
                    }
                }
                $Unprivileged = $true
                Write-Host ""
            }
        }
    }
}

# Validate that at least one host source is provided.
# Command-list mode brings its own targets inside each line.
if (-not $resumingSession -and -not $isCommandMode) {
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
    $workflowsFolder = [IO.Path]::Combine($OutputDir, $Workflow)
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
    $networksFolder = [IO.Path]::Combine($OutputDir, "networks")
    $hostsFolder = [IO.Path]::Combine($OutputDir, "hosts")
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
$logFile = [IO.Path]::Combine($logsFolder, "scan.log")
$errorLogFile = [IO.Path]::Combine($logsFolder, "scan-errors.log")
$resultsFile = [IO.Path]::Combine($logsFolder, "scan-results.json")
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

# Command-list mode: the units are the work items. They are keyed by their
# content-addressed id so the rest of the engine - state, resume, retries,
# progress - treats them exactly like hosts.
if ($isCommandMode) {
    $commandUnitsById = @{}
    foreach ($unit in $commandUnits) {
        $commandUnitsById[$unit.Id] = $unit
        $targetHostsData[$unit.Id] = @{
            CIDRs    = @()
            Type     = "Command"
            Original = $unit.Command
        }
    }
    $targetHosts = @($commandUnits | ForEach-Object { $_.Id })
    Write-Log -Message "Command units: $($targetHosts.Count)" -Level "INFO" -LogFile $logFile

    $withWarnings = @($commandUnits | Where-Object { $_.Warnings.Count -gt 0 })
    foreach ($unit in $withWarnings) {
        foreach ($w in $unit.Warnings) {
            Write-Log -Message "Line $($unit.LineNumber) ($($unit.Label)): $w" -Level "WARNING" -LogFile $logFile
        }
    }
}


if (-not $isCommandMode) {
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
} # End of if (-not $isCommandMode)
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
                # Exclusions match by exact key, so register every spelling of the
                # host: the name as written and whatever it resolves to.
                $excludedHosts += $entry.Hosts
                $excludedHosts += $entry.ResolvedIPs
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
            # Same as above: name and resolved addresses are both valid keys.
            $excludedHosts += $entry.Hosts
            $excludedHosts += $entry.ResolvedIPs
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

# Process sensitive hosts from file and/or command line.
# NOTE: this accumulator must NOT be called $sensitiveHosts. PowerShell variable
# names are case-insensitive, so that name IS the -SensitiveHosts parameter and
# initialising it here silently discarded whatever the caller passed.
$sensitiveTargets = @()
$sensitiveTargetsData = @{}  # Host -> {CIDRs: [], Type: "", Original: ""}

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
                    $sensitiveTargets += $currentHost

                    # Store metadata
                    if (-not $sensitiveTargetsData.ContainsKey($currentHost)) {
                        $sensitiveTargetsData[$currentHost] = @{
                            CIDRs = @()
                            Type = $entry.Type
                            Original = $entry.Original
                        }
                    }

                    if ($entry.SourceCIDR) {
                        $sensitiveTargetsData[$currentHost].CIDRs += $entry.SourceCIDR
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
                $sensitiveTargets += $currentHost

                # Store metadata
                if (-not $sensitiveTargetsData.ContainsKey($currentHost)) {
                    $sensitiveTargetsData[$currentHost] = @{
                        CIDRs = @()
                        Type = $entry.Type
                        Original = $entry.Original
                    }
                }

                if ($entry.SourceCIDR) {
                    $sensitiveTargetsData[$currentHost].CIDRs += $entry.SourceCIDR
                }
            }
        }
    }
}

# Deduplicate sensitive hosts
if ($sensitiveTargets.Count -gt 0) {
    $beforeSensitiveDedup = $sensitiveTargets.Count
    $sensitiveTargets = $sensitiveTargets | Select-Object -Unique
    $sensitiveDuplicatesRemoved = $beforeSensitiveDedup - $sensitiveTargets.Count

    Write-Log -Message "Total sensitive hosts after expansion: $beforeSensitiveDedup" -Level "INFO" -LogFile $logFile
    if ($sensitiveDuplicatesRemoved -gt 0) {
        Write-Log -Message "Sensitive duplicates removed: $sensitiveDuplicatesRemoved" -Level "INFO" -LogFile $logFile
    }
    Write-Log -Message "Unique sensitive hosts: $($sensitiveTargets.Count)" -Level "INFO" -LogFile $logFile

    # Debug: Show sample of sensitive hosts
    if ($sensitiveTargets.Count -gt 0) {
        $sampleCount = [Math]::Min(5, $sensitiveTargets.Count)
        $sampleHosts = $sensitiveTargets[0..($sampleCount-1)] -join ', '
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
foreach ($h in $sensitiveTargets) { $sensitiveSet[$h] = $true }

# Merge sensitive hosts into target hosts if not already present
$addedSensitiveHosts = 0
foreach ($sh in $sensitiveTargets) {
    if (-not $targetHostsData.ContainsKey($sh)) {
        # Add sensitive host to target hosts
        $targetHostsData[$sh] = @{
            CIDRs = $sensitiveTargetsData[$sh].CIDRs
            Type = $sensitiveTargetsData[$sh].Type
            Original = $sensitiveTargetsData[$sh].Original
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
    # Single scan and command-list mode: one pseudo-step. Command mode stays a
    # single step on purpose, so the state file keeps the name scan-state.json
    # that Get-SessionList and -ResumeSession look for.
    $workflowSteps = @(
        @{
            profile = $(if ($isCommandMode) { "commands" } else { $ScanType })
            description = $(if ($isCommandMode) { "Command list" } else { "Single scan" })
            condition = "always"
        }
    )
}

# ---------------------------------------------------------------------------
# Pre-flight: show exactly what is about to run and let the user back out.
# Scanning the wrong range is expensive, and the moment to notice is now.
# ---------------------------------------------------------------------------
$breakdown = Get-TargetBreakdown -ValidHosts $validHosts -TargetHostsData $targetHostsData

Write-Host ""
Write-Host "╭─────────────────────────────────────────────────╮" -ForegroundColor Cyan
Write-Host "│ SCAN CONFIGURATION                              │" -ForegroundColor Cyan
Write-Host "╰─────────────────────────────────────────────────╯" -ForegroundColor Cyan

if ($isCommandMode) {
    # The list is the configuration: show every line as it will run, with the
    # state it is resuming from, so an edited or half-finished list is obvious.
    # $state does not exist yet (it is built inside the step loop), so read the
    # session's state file straight from disk.
    $preflightStatus = @{}
    $preflightStateFile = [IO.Path]::Combine($OutputDir, ".sessions", $sessionId, "scan-state.json")
    $preflightState = if ($resumingSession -and $resumedSessionData) {
        $resumedSessionData.State
    } elseif (Test-Path $preflightStateFile) {
        Load-StateFile -StateFile $preflightStateFile
    } else { $null }

    if ($preflightState -and $preflightState.hosts) {
        # Load-StateFile only converts the top level, so hosts is a PSCustomObject
        $hostsNode = $preflightState.hosts
        $keys = if ($hostsNode -is [System.Collections.Hashtable]) {
            @($hostsNode.Keys)
        } else {
            @($hostsNode.PSObject.Properties.Name)
        }
        foreach ($k in $keys) {
            $entry = if ($hostsNode -is [System.Collections.Hashtable]) { $hostsNode[$k] } else { $hostsNode.$k }
            if ($entry -and $entry.status) { $preflightStatus[$k] = $entry.status }
        }
    }

    $pendingCount = 0
    $doneCount = 0
    $failedCount0 = 0
    foreach ($unit in $commandUnits) {
        $st = if ($preflightStatus.ContainsKey($unit.Id)) { $preflightStatus[$unit.Id] } else { "pending" }
        switch ($st) {
            "completed" { $doneCount++ }
            "failed"    { $failedCount0++ }
            default     { $pendingCount++ }
        }
    }

    Write-Host "📋 Commands   : " -NoNewline -ForegroundColor Cyan
    Write-Host "$($commandUnits.Count) " -NoNewline -ForegroundColor White
    Write-Host "($pendingCount pending, $doneCount done, $failedCount0 failed)" -ForegroundColor Gray
    if ($CommandFile) {
        Write-Host "   Source     : " -NoNewline -ForegroundColor Cyan
        Write-Host "$CommandFile" -ForegroundColor White
    }

    $shownUnits = if ($commandUnits.Count -le 12) { $commandUnits } else { $commandUnits[0..11] }
    foreach ($unit in $shownUnits) {
        $st = if ($preflightStatus.ContainsKey($unit.Id)) { $preflightStatus[$unit.Id] } else { "pending" }
        $mark, $markColor = switch ($st) {
            "completed" { "[done]", "Green" }
            "failed"    { "[fail]", "Red" }
            "skipped"   { "[skip]", "DarkGray" }
            default     { "[    ]", "DarkGray" }
        }
        Write-Host "   $mark " -NoNewline -ForegroundColor $markColor
        Write-Host "$($unit.Label)" -ForegroundColor White
        # The prefix is added here, so the wrapper must not indent as well.
        foreach ($line in (Format-CommandForDisplay -Command $unit.Command -Width 70 -Indent "")) {
            Write-Host "          $line" -ForegroundColor DarkGray
        }
        foreach ($w in $unit.Warnings) {
            Write-Host "          ! $w" -ForegroundColor Yellow
        }
    }
    if ($commandUnits.Count -gt 12) {
        Write-Host "   ... and $($commandUnits.Count - 12) more" -ForegroundColor DarkGray
    }
} else {

Write-Host "🎯 Targets    : " -NoNewline -ForegroundColor Cyan
Write-Host "$($validHosts.Count) host(s)" -ForegroundColor White

foreach ($cidr in ($breakdown.Networks.Keys | Sort-Object)) {
    Write-Host "   Network    : " -NoNewline -ForegroundColor Cyan
    Write-Host "$cidr " -NoNewline -ForegroundColor White
    Write-Host "-> $($breakdown.Networks[$cidr]) host(s)" -ForegroundColor Gray
}

if ($breakdown.Individual.Count -gt 0) {
    $shown = if ($breakdown.Individual.Count -le 6) {
        $breakdown.Individual -join ", "
    } else {
        ($breakdown.Individual[0..5] -join ", ") + ", ... (+$($breakdown.Individual.Count - 6) more)"
    }
    Write-Host "   Individual : " -NoNewline -ForegroundColor Cyan
    Write-Host "$($breakdown.Individual.Count) host(s) " -NoNewline -ForegroundColor White
    Write-Host "($shown)" -ForegroundColor Gray
}

if ($isWorkflowMode) {
    Write-Host "🔍 Workflow   : " -NoNewline -ForegroundColor Cyan
    Write-Host "$Workflow " -NoNewline -ForegroundColor White
    Write-Host "- $($scanWorkflows[$Workflow].name) ($($workflowSteps.Count) steps)" -ForegroundColor Gray

    $stepNum = 0
    foreach ($step in $workflowSteps) {
        $stepNum++
        $cond = if ($step.condition) { $step.condition } else { $WorkflowCondition }
        Write-Host "   Step $stepNum     : " -NoNewline -ForegroundColor Cyan
        Write-Host "$($step.profile) " -NoNewline -ForegroundColor White
        Write-Host "($cond)" -ForegroundColor Gray
        foreach ($line in (Format-CommandForDisplay -Command $scanProfiles[$step.profile].command)) {
            Write-Host "                $line" -ForegroundColor DarkGray
        }
    }
} else {
    Write-Host "🔍 Profile    : " -NoNewline -ForegroundColor Cyan
    Write-Host "$ScanType " -NoNewline -ForegroundColor White
    Write-Host "- $($scanProfiles[$ScanType].name)" -ForegroundColor Gray
    Write-Host "   Command    : " -NoNewline -ForegroundColor Cyan
    $cmdLines = @(Format-CommandForDisplay -Command $scanProfiles[$ScanType].command)
    Write-Host $cmdLines[0] -ForegroundColor DarkGray
    foreach ($line in ($cmdLines | Select-Object -Skip 1)) {
        Write-Host $line -ForegroundColor DarkGray
    }
}

if ($sensitiveHostsToScan.Count -gt 0) {
    Write-Host "🔒 Sensitive  : " -NoNewline -ForegroundColor Cyan
    Write-Host "$($sensitiveHostsToScan.Count) host(s) " -NoNewline -ForegroundColor White
    Write-Host "| timing $SensitiveTiming | scripts $SensitiveScripts" -ForegroundColor Gray
    $firstProfile = if ($isWorkflowMode) { $workflowSteps[0].profile } else { $ScanType }
    $sensCmd = Get-SensitiveScanCommand -BaseCommand $scanProfiles[$firstProfile].command -Timing $SensitiveTiming -Scripts $SensitiveScripts
    Write-Host "   Command    : " -NoNewline -ForegroundColor Cyan
    $sLines = @(Format-CommandForDisplay -Command $sensCmd)
    Write-Host $sLines[0] -ForegroundColor DarkGray
    foreach ($line in ($sLines | Select-Object -Skip 1)) {
        Write-Host $line -ForegroundColor DarkGray
    }
}

if ($excludedHosts.Count -gt 0) {
    $exShown = if ($excludedHosts.Count -le 6) {
        $excludedHosts -join ", "
    } else {
        ($excludedHosts[0..5] -join ", ") + ", ... (+$($excludedHosts.Count - 6) more)"
    }
    Write-Host "🚫 Excluded   : " -NoNewline -ForegroundColor Cyan
    Write-Host "$($excludedHosts.Count) host(s) " -NoNewline -ForegroundColor White
    Write-Host "($exShown)" -ForegroundColor Gray
}

}

Write-Host "📁 Output     : " -NoNewline -ForegroundColor Cyan
Write-Host "$OutputDir$([IO.Path]::DirectorySeparatorChar)" -ForegroundColor White
Write-Host "   Session    : " -NoNewline -ForegroundColor Cyan
Write-Host "$sessionId" -ForegroundColor White

# The clock the run is measured against, and the line that picks it up again.
# Both are printed before the confirmation so they are on screen from the start,
# not only in the summary of a run that may never reach its summary.
Write-Host "🕒 Clock      : " -NoNewline -ForegroundColor Cyan
Write-Host "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))" -NoNewline -ForegroundColor White
if (-not $startTime -and -not $stopTime -and -not $scheduleWindows) {
    Write-Host " (no schedule; -StartAt, -StopAt and -Schedule set one)" -ForegroundColor DarkGray
} else {
    Write-Host ""
}
if ($startTime) {
    Write-Host "   Starts at  : " -NoNewline -ForegroundColor Cyan
    Write-Host "$($startTime.ToString('yyyy-MM-dd HH:mm:ss')) " -NoNewline -ForegroundColor Yellow
    Write-Host "(in $(Get-TimeRemainingText -Target $startTime)) " -NoNewline -ForegroundColor Gray
    Write-Host "- this process waits; leave it running" -ForegroundColor DarkGray
}
if ($scheduleWindows) {
    Write-Host "   Schedule   : " -NoNewline -ForegroundColor Cyan
    Write-Host "$Schedule" -ForegroundColor White

    # Print the window Scanyx actually computed, so a misread spec is obvious
    # here rather than at 03:00 when nothing has been scanned.
    $previewFrom = if ($startTime) { $startTime } else { Get-Date }
    $previewNow  = Get-ScheduleWindowFor -Windows $scheduleWindows -Now $previewFrom
    if ($previewNow) {
        Write-Host "   Window     : " -NoNewline -ForegroundColor Cyan
        Write-Host "open now " -NoNewline -ForegroundColor Green
        Write-Host "until $($previewNow.Close.ToString('ddd yyyy-MM-dd HH:mm'))" -ForegroundColor Gray
    } else {
        $previewNext = Get-NextScheduleOpen -Windows $scheduleWindows -Now $previewFrom
        if ($previewNext) {
            $previewWindow = Get-ScheduleWindowFor -Windows $scheduleWindows -Now $previewNext
            Write-Host "   Window     : " -NoNewline -ForegroundColor Cyan
            Write-Host "$($previewNext.ToString('ddd yyyy-MM-dd HH:mm'))" -NoNewline -ForegroundColor Yellow
            if ($previewWindow) {
                Write-Host " -> $($previewWindow.Close.ToString('HH:mm')) " -NoNewline -ForegroundColor Yellow
            } else {
                Write-Host " " -NoNewline
            }
            Write-Host "(opens in $(Get-TimeRemainingText -Target $previewNext))" -ForegroundColor Gray
        }
    }

    if ($overallDeadline) {
        Write-Host "   Ends       : " -NoNewline -ForegroundColor Cyan
        Write-Host "$($overallDeadline.ToString('yyyy-MM-dd HH:mm:ss')) " -NoNewline -ForegroundColor Yellow
        Write-Host "(in $(Get-TimeRemainingText -Target $overallDeadline))" -ForegroundColor Gray
    } else {
        Write-Host "   Ends       : " -NoNewline -ForegroundColor Cyan
        Write-Host "when the scan finishes " -NoNewline -ForegroundColor White
        Write-Host "(-Until sets a last day)" -ForegroundColor DarkGray
    }

    Write-Host "   On close   : " -NoNewline -ForegroundColor Cyan
    if ($StopMode -eq "Drain") {
        Write-Host "drain " -NoNewline -ForegroundColor White
        Write-Host "- nothing new is launched, the scans already running finish" -ForegroundColor Gray
    } else {
        Write-Host "hard " -NoNewline -ForegroundColor White
        Write-Host "- the scans still running are stopped too" -ForegroundColor Gray
    }
    Write-Host "                Between windows Scanyx waits here and carries on by itself." -ForegroundColor DarkGray
}
if ($stopTime) {
    Write-Host "   Stops at   : " -NoNewline -ForegroundColor Cyan
    Write-Host "$($stopTime.ToString('yyyy-MM-dd HH:mm:ss')) " -NoNewline -ForegroundColor Yellow
    Write-Host "(in $(Get-TimeRemainingText -Target $stopTime))" -ForegroundColor Gray
    if ($startTime) {
        Write-Host "   Window     : " -NoNewline -ForegroundColor Cyan
        Write-Host "$(Format-Duration -TimeSpan ($stopTime - $startTime))" -ForegroundColor White
    }
    Write-Host "   On stop    : " -NoNewline -ForegroundColor Cyan
    if ($StopMode -eq "Drain") {
        Write-Host "drain " -NoNewline -ForegroundColor White
        Write-Host "- nothing new is launched, the scans already running finish" -ForegroundColor Gray
    } else {
        Write-Host "hard " -NoNewline -ForegroundColor White
        Write-Host "- the scans still running are stopped too" -ForegroundColor Gray
    }
    Write-Host "                Whatever is left stays pending; resume it with the line below." -ForegroundColor DarkGray
}

$resumeCommand = Get-ResumeCommand -SessionId $sessionId -OutputDir $OutputDir -Elevated (Test-IsElevated) -Schedule $Schedule
Write-Host "↩️  Resume     : " -NoNewline -ForegroundColor Cyan
Write-Host "$resumeCommand" -ForegroundColor Yellow

Write-Host "⚙️  Execution  : " -NoNewline -ForegroundColor Cyan
Write-Host "$MaxConcurrent concurrent | $MaxRetries retry | ${RetryDelay}s delay | $OverwriteMode" -ForegroundColor White
if ($Unprivileged) {
    Write-Host "   Privileges : " -NoNewline -ForegroundColor Cyan
    Write-Host "unprivileged (downgraded, no raw sockets)" -ForegroundColor Yellow
}
Write-Host ""

# -ListCommands stops here: the block above is the listing, and the point is
# to review a list without committing scan time to it.
if ($isCommandMode -and $ListCommands) {
    $stale = @()
    $currentIds = @{}
    foreach ($unit in $commandUnits) { $currentIds[$unit.Id] = $true }
    foreach ($key in @($preflightStatus.Keys)) {
        if (-not $currentIds.ContainsKey($key)) { $stale += $key }
    }
    if ($stale.Count -gt 0) {
        Write-Host "🕗 Stale      : " -NoNewline -ForegroundColor Cyan
        Write-Host "$($stale.Count) state entry(ies) from lines that were edited or removed" -ForegroundColor Yellow
        Write-Host "                They are ignored; -Force clears them." -ForegroundColor DarkGray
    }
    Write-Host ""
    return
}

# The wizard already asked; -Yes is an explicit opt-out; and with no terminal
# there is nobody to ask, so run unattended rather than hang.
if ($Yes) {
    Write-Log -Message "Pre-flight confirmation skipped (-Yes)" -Level "INFO" -LogFile $logFile
} elseif ($Wizard) {
    Write-Log -Message "Pre-flight confirmation already given in the wizard" -Level "INFO" -LogFile $logFile
} elseif ([Console]::IsInputRedirected) {
    Write-Log -Message "No interactive terminal: starting unattended" -Level "INFO" -LogFile $logFile
} else {
    Write-Host "  Proceed with this scan? [Y/n]: " -NoNewline -ForegroundColor Cyan
    $proceed = Read-Host
    if ($proceed -ne "" -and $proceed -notmatch '^[YySs]') {
        Write-Log -Message "Aborted by user at the pre-flight confirmation" -Level "WARNING" -LogFile $logFile
        Write-Host ""
        Write-Host "[INFO] Aborted by user. No hosts were scanned." -ForegroundColor Yellow
        Write-Host "       The output directory and scan.log were already created: " -NoNewline -ForegroundColor Gray
        Write-Host "$OutputDir" -ForegroundColor Gray
        Write-Host ""
        return
    }
    Write-Host ""
}

# Workflow execution loop
$workflowStepNumber = 1

# Initialize timing tracking for entire scan session
$scanStartTime = Get-Date

# Set once the scheduled stop time arrives, and never cleared: it ends the
# current step and keeps any later workflow step from starting.
$stopReached = $false

foreach ($workflowStep in $workflowSteps) {
    $currentProfile = $workflowStep.profile
    $stepCondition = if ($workflowStep.condition) { $workflowStep.condition } else { $WorkflowCondition }
    # Nothing consumes $stepCondition yet, so a step declaring anything but
    # 'always' still runs against every host. Better a visible no-op than a
    # silent one; implementing it needs a decision on whether the condition is
    # per-host or global, which is a separate change.
    if ($stepCondition -and $stepCondition -ne 'always') {
        Write-Log -Message "Workflow step $workflowStepNumber declares condition '$stepCondition', which is not yet enforced; the step will run unconditionally." -Level "WARNING" -LogFile $logFile
    }

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

    # Initialize liveness tallies and network progress (per workflow step).
    # Counting here, as each job finishes, is what lets the progress bar stop
    # re-reading every host's output file on every repaint.
    $script:livenessCounts = @{ open = 0; alive = 0; filtered = 0; unreachable = 0; unknown = 0 }
    $script:networkProgress = @{}

    # Initialize network progress tracking for each CIDR
    foreach ($cidr in $allCIDRs) {
        $script:networkProgress[$cidr] = @{
            Total = 0
            Scanned = 0
            Alive = 0
            Open = 0
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

    if ($isCommandMode) {
        # The author's own -oA decides where nmap writes; Scanyx only adds a
        # place for stdout/stderr when the line has no output flag of its own.
        $unit = $commandUnitsById[$currentHost]
        $outputFolder = if ($unit.OutputBase) {
            [IO.Path]::GetDirectoryName($unit.OutputBase)
        } else {
            [IO.Path]::Combine($currentBaseDir, "commands", $unit.Id)
        }

        $state.hosts[$currentHost] = @{
            status = "pending"
            attempts = 0
            last_update = ""
            error = ""
            scan_type = "command"
            command = $unit.Command
            exec_command = $unit.ExecCommand
            label = $unit.Label
            target = $unit.Target
            line_number = $unit.LineNumber
            result_file = $unit.ResultFile
            output_flag = $unit.OutputFlag
            output_folder = $outputFolder
        }
    } else {
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
    } elseif ($ResumeRetryNoOpenPorts) {
        $action = "Resume and retry hosts without open ports"
    } elseif ($RetryNoOpenPorts) {
        $action = "Retry hosts without open ports only"
    } else {
        # Interactive choice
        $options = @(
            "Resume (pending only)",
            "Resume and retry failed",
            "Resume and retry dead",
            "Retry failed only",
            "Retry dead only",
            "Resume and retry hosts without open ports",
            "Retry hosts without open ports only",
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

    # The two "no open ports" actions run exactly the selection their "dead"
    # counterparts do; only the rescan predicate differs, so map them onto the
    # same cases and carry the difference in $retryDeadMode.
    $retryDeadMode = 'NoResponse'
    switch ($action) {
        "Resume and retry hosts without open ports" {
            $retryDeadMode = 'NoOpenPorts'
            $action = "Resume and retry dead"
        }
        "Retry hosts without open ports only" {
            $retryDeadMode = 'NoOpenPorts'
            $action = "Retry dead only"
        }
    }

    # -RetryDead used to mean "no open ports", which rescanned hosts that had
    # answered RST on every port -- a retry guaranteed to reproduce itself. Say
    # so once, with the number of hosts it no longer touches.
    if ($retryDeadMode -eq 'NoResponse' -and $action -in @("Resume and retry dead", "Retry dead only")) {
        $answeredNoPorts = 0
        foreach ($currentHost in $validHosts) {
            $hostState = $existingState.hosts.$currentHost
            if (-not $hostState -or $hostState.status -ne "completed") { continue }
            if ((Get-PersistedLiveness -HostState $hostState -TargetHost $currentHost) -eq 'alive') { $answeredNoPorts++ }
        }
        if ($answeredNoPorts -gt 0) {
            Write-Host "[INFO] -RetryDead now retries only hosts with no response (filtered/unreachable/unknown)." -ForegroundColor Cyan
            Write-Host "       $answeredNoPorts host(s) that answered with all ports closed are no longer retried." -ForegroundColor Cyan
            Write-Host "       Use -RetryNoOpenPorts for the previous behaviour." -ForegroundColor Cyan
            Write-Log -Message "-RetryDead narrowed to no-response hosts; $answeredNoPorts host(s) that answered are no longer retried" -Level "INFO" -LogFile $logFile
        }
    }

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
                    # A host that answered RST on every port is alive, and
                    # rescanning it is guaranteed to reproduce the same answer.
                    # Only hosts with no evidence of a response are worth a retry.
                    if (Test-HostNeedsRescan -HostState $hostState -Mode $retryDeadMode) {
                        $hostsToScan += $currentHost
                        $state.hosts[$currentHost] = $hostState
                        $state.hosts[$currentHost].status = "pending"
                    } else {
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
                    # A host that answered RST on every port is alive, and
                    # rescanning it is guaranteed to reproduce the same answer.
                    # Only hosts with no evidence of a response are worth a retry.
                    if (Test-HostNeedsRescan -HostState $hostState -Mode $retryDeadMode) {
                        $hostsToScan += $currentHost
                        $state.hosts[$currentHost] = $hostState
                        $state.hosts[$currentHost].status = "pending"
                    } else {
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
                Move-Item $stateFile ([IO.Path]::Combine((Split-Path $stateFile -Parent), "scan-state_$archiveTimestamp.json")) -Force
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
            Move-Item $stateFile ([IO.Path]::Combine((Split-Path $stateFile -Parent), "scan-state_$archiveTimestamp.json")) -Force
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
            # In command-list mode the result file is the one the line's own
            # output flag names, not <folder>/<profile>.nmap.
            $probe = if ($hostMeta.result_file) {
                $hostMeta.result_file
            } elseif ($hostFolder) {
                "$([IO.Path]::Combine($hostFolder, $(if ($isCommandMode) { $targetHost } else { "$currentScanType" }))).nmap"
            } else { $null }
            $probeIsCurrent = if ($isCommandMode) {
                Test-NmapOutputMatchesCommand -ResultFile $probe -Command $(if ($hostMeta.exec_command) { $hostMeta.exec_command } else { $hostMeta.command })
            } else {
                $probe -and (Test-Path $probe)
            }
            if ($probeIsCurrent) {
                $hostsWithExistingResults++
            }
        }
    }

    if ($hostsWithExistingResults -gt 0 -and ($Yes -or [Console]::IsInputRedirected)) {
        # Unattended: keep what is already on disk rather than silently
        # redoing work the consultant may have paid for in scan time.
        $OverwriteMode = "Skip"
        Write-Log -Message "$hostsWithExistingResults item(s) already have results; skipping them (unattended)" -Level "INFO" -LogFile $logFile
    } elseif ($hostsWithExistingResults -gt 0) {
        Write-Host "`n$hostsWithExistingResults item(s) have existing scan results." -ForegroundColor Yellow
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

# The resume line on disk, written before the first scan so it is already there
# if the run dies in a way that prints nothing at all.
$resumeCommand = Get-ResumeCommand -SessionId $sessionId -OutputDir $OutputDir -Elevated (Test-IsElevated) -Schedule $Schedule
$resumeFile = Write-ResumeFile -SessionDir $sessionDir -ResumeCommand $resumeCommand -SessionId $sessionId -Status "in_progress"

# Remembered for the interrupt handler, which runs in its own scope and may
# fire on any workflow step.
$script:currentResultsFile = $resultsFile
$script:currentSessionId = $sessionId
$script:currentOutputDir = $OutputDir
$script:currentElevated = Test-IsElevated
$script:currentResumeFile = $resumeFile

# Initialize results file
if (-not (Test-Path $resultsFile)) {
    @{
        scan_session = $sessionId
        scans = @()
    } | ConvertTo-Json -Depth 10 | Set-Content -Path $resultsFile
}

# Ctrl+C handler
$global:cleanupJobs = @()
$script:scanCompleted = $false
$exitSubscriber = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    # This fires on ANY exit, not just Ctrl+C, so only claim an interruption
    # when the scan loop did not reach its end.
    if ($script:scanCompleted) { return }

    Write-Host "`n`n[INFO] Scan interrupted by user (Ctrl+C)" -ForegroundColor Yellow

    # Show network summary if available
    if ($script:networkProgress -and $script:networkProgress.Count -gt 0) {
        Show-NetworkSummary -NetworkProgress $script:networkProgress -Title "Network Scan Summary (Interrupted)"
    }

    Write-Host "`n[INFO] Cleaning up background jobs..." -ForegroundColor Yellow
    try {
        # Only the scan jobs. Removing every job would also remove this handler's
        # own PSEventJob, and the engine then aborts the process (FailFast) when it
        # tries to unsubscribe a disposed job while closing the runspace.
        Get-Job | Where-Object { $_.PSJobTypeName -eq "BackgroundJob" } |
            Stop-Job -ErrorAction SilentlyContinue
    } catch { }

    # The results of everything that did complete are already on disk in the
    # append-only log; render them so an interrupted run still leaves the
    # artifact behind.
    if ($script:currentResultsFile) {
        Export-ScanResults -ResultsFile $script:currentResultsFile -SessionId $script:currentSessionId
    }

    # Ctrl+C is precisely when the resume line matters, and the summary that
    # normally prints it is never reached.
    if ($script:currentSessionId) {
        Write-Host "[INFO] Resume this session with:" -ForegroundColor Cyan
        Write-Host "  $(Get-ResumeCommand -SessionId $script:currentSessionId -OutputDir $script:currentOutputDir -Elevated $script:currentElevated)" -ForegroundColor Yellow
        if ($script:currentResumeFile) {
            Write-Host "       Also saved in: $script:currentResumeFile" -ForegroundColor DarkGray
        }
    }

    Write-Host "[INFO] Cleanup completed. Exiting...`n" -ForegroundColor Yellow
}

# Main scanning loop with parallel execution
$completedCount = $state.completed
$failedCount = $state.failed
$jobQueue = @{}
# Failed scans waiting out RetryDelay before their next attempt. They wait here,
# not in a sleep, so the loop keeps collecting the other jobs meanwhile.
$retryQueue = @{}

# Collect every finished job: record its verdict, queue its retry or mark it
# failed, and refresh the bar. Dot-sourced by the dispatch loop and by the
# final drain, so it runs in their scope and updates the counters in place.
# It used to be two copies of the same 130 lines, and they had drifted: the
# drain never fed the ETA, and both carried the same lost-retry bug.
$collectFinishedJobs = {
    $completedJobs = $jobQueue.GetEnumerator() | Where-Object { $_.Value.Job.State -ne "Running" }
    foreach ($job in $completedJobs) {
        $jobHost = $job.Key
        $jobData = $job.Value
        $jobResult = Receive-Job -Job $jobData.Job
        Remove-Job -Job $jobData.Job -Force
        # Out of the queue now, not after processing: a retry put back under
        # the same key below must survive, or its job runs untracked.
        $jobQueue.Remove($jobHost)

        # Process result
        $scanSuccess = $jobResult.Success
        $attempts = $jobData.Attempts

        if ($scanSuccess) {
            # Check if host has open ports and update counters
            $nmapFile = if ($jobData.ResultFile) { $jobData.ResultFile } else { "$([IO.Path]::Combine($jobData.HostFolder, $jobData.FileName)).nmap" }

            $verdict = Get-HostLivenessVerdict -ResultFile $nmapFile -TargetHost $jobHost -OutputFlag $state.hosts[$jobHost].output_flag
            Update-HostState -State $state -TargetHost $jobHost -Status "completed" -Attempts $attempts -ScanFile $nmapFile `
                             -Liveness $verdict.Verdict -LivenessReason $verdict.Evidence -OpenPortCount $verdict.OpenCount
            $script:livenessCounts[$verdict.Verdict]++
            $completedCount++
            Write-Log -Message "Scan completed: $jobHost | $currentScanType | Attempt: $attempts | Duration: $(Format-Duration -TimeSpan ([TimeSpan]::FromSeconds($jobResult.DurationSeconds)))" -Level "SUCCESS" -LogFile $logFile

            # Track scan duration for ETA calculation
            if ($jobStartTimes.ContainsKey($jobHost)) {
                $duration = (Get-Date) - $jobStartTimes[$jobHost]
                $scanDurations += $duration.TotalSeconds
                $jobStartTimes.Remove($jobHost)
            }
            # Alive counts every host that answered, open counts the ones with
            # attack surface. A host that RSTs every port is alive, not dead.
            $hostCIDR = $state.hosts[$jobHost].source_cidr
            if ($hostCIDR -and $script:networkProgress.ContainsKey($hostCIDR)) {
                if ($verdict.Verdict -eq 'open') { $script:networkProgress[$hostCIDR].Open++ }
                if ($verdict.Verdict -in @('open', 'alive')) { $script:networkProgress[$hostCIDR].Alive++ }
            }

            # Update network scanned counter
            $hostCIDR = $state.hosts[$jobHost].source_cidr
            if ($hostCIDR -and $script:networkProgress.ContainsKey($hostCIDR)) {
                $script:networkProgress[$hostCIDR].Scanned++
            }

            # Verbose: Show nmap output after completion
            if ($VerboseMode) {
                $stdoutFile = "$([IO.Path]::Combine($jobData.HostFolder, $jobData.FileName)).stdout"
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
                output_files = @($nmapFile)
                liveness = $verdict.Verdict
                liveness_reason = $verdict.Evidence
                liveness_source = $verdict.Source
                srtt_ms = $verdict.SrttMs
                port_counts = @{
                    open = $verdict.OpenCount
                    closed = $verdict.ClosedCount
                    filtered = $verdict.FilteredCount
                }
            }
        } else {
            # Check if retry needed
            if ($attempts -lt ($MaxRetries + 1)) {
                Write-Log -Message "Scan failed: $jobHost | $currentScanType | Attempt: $attempts/$($MaxRetries + 1) | Error: $($jobResult.Error)" -Level "WARNING" -LogFile $logFile -ErrorLogFile $errorLogFile
                $retryAt = (Get-Date).AddSeconds([math]::Max(0, $RetryDelay))
                Write-Log -Message "Retrying in $RetryDelay seconds (at $($retryAt.ToString('HH:mm:ss')))" -Level "INFO" -LogFile $logFile

                $newAttempts = $attempts + 1
                Update-HostState -State $state -TargetHost $jobHost -Status "in_progress" -Attempts $newAttempts -Error $jobResult.Error
                Save-StateFile -StateFile $stateFile -State $state

                # Verbose: Show retry command
                if ($VerboseMode) {
                    $fullNmapCommand = "$($jobData.ScanCommand) -oA `"$([IO.Path]::Combine($jobData.HostFolder, $jobData.FileName))`" $jobHost"
                    Write-Log -Message "Retry command: $fullNmapCommand" -Level "VERBOSE" -LogFile $logFile
                }

                # Queued, not slept on: Start-DueRetries launches it once the
                # delay is over, and the other scans keep being collected meanwhile.
                $retryQueue[$jobHost] = @{
                    NotBefore = $retryAt
                    Attempts = $newAttempts
                    HostFolder = $jobData.HostFolder
                    FileName = $jobData.FileName
                    ScanCommand = $jobData.ScanCommand
                    ResultFile = $jobData.ResultFile
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
                    liveness = 'unknown'
                }
            }
        }

        # Save state and update progress
        Save-StateFile -StateFile $stateFile -State $state
        if ($isWorkflowMode) {
            Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $totalWork -Failed $failedCount -CurrentHost $jobHost -WorkflowStep $workflowStepNumber -WorkflowTotalSteps $workflowSteps.Count -StepProfile $currentProfile -NetworkProgress $script:networkProgress -LivenessCounts $script:livenessCounts -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations -Concurrency $MaxConcurrent -StopTime $stopTimeForProgress -PendingRetries $retryQueue.Count
        } else {
            Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $totalWork -Failed $failedCount -CurrentHost $jobHost -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations -Concurrency $MaxConcurrent -LivenessCounts $script:livenessCounts -StopTime $stopTimeForProgress -PendingRetries $retryQueue.Count
        }
    }
}

# Timing tracking for individual scans
$scanDurations = @()  # Array to store completed scan durations in seconds
$jobStartTimes = @{}  # Hashtable to track when each job started

# Scheduled start: hold here, not earlier. Everything the run needs to ask -
# the pre-flight, the previous-session choice, the overwrite question - has been
# asked by now, so an unattended window does not open onto a prompt.
if ($startTime -and -not $startWaitDone) {
    $null = Wait-ForScheduledStart -StartTime $startTime -StopTime $stopTime -LogFile $logFile
    $startWaitDone = $true
    # The clock the summary and the ETA run on is the scan's, not the wait's.
    $scanStartTime = Get-Date
    $scriptStartTime = $scanStartTime
}

# Warning thresholds already announced, so each one is said once per window
$stopWarningsFired = @{}

Write-Host ""

# ---------------------------------------------------------------------------
# One pass per open window. Without -Schedule there is exactly one pass and
# this behaves as it always did; with it, the run spans as many passes as the
# schedule has openings, keeping its place in $hostIndex across the pauses.
# ---------------------------------------------------------------------------
# $hostsToScan may arrive as a key collection or a single scalar; foreach never
# cared, but indexing by position does.
$hostsToScan = @($hostsToScan)

# What is left to dispatch, and where we are in it. A window that closes on a
# running scan puts that host back here, so the next window starts by redoing
# what it interrupted. The progress denominator stays the original count: a
# host scanned twice is still one host.
$workList = @($hostsToScan)
$totalWork = $hostsToScan.Count
$carryOver = @()

$hostIndex = 0
$runStopped = $false      # the schedule itself is over: deadline, or no window left
$stoppedInFlight = 0      # scans killed at a window close, across every window
$windowNumber = 0
$totalPausedSeconds = 0

while ($true) {

if ($scheduleWindows) {
    $windowNumber++
    $nowInSchedule = Get-Date

    if ($overallDeadline -and $nowInSchedule -ge $overallDeadline) { $runStopped = $true; break }

    $window = Get-ScheduleWindowFor -Windows $scheduleWindows -Now $nowInSchedule
    if (-not $window) {
        $nextOpen = Get-NextScheduleOpen -Windows $scheduleWindows -Now $nowInSchedule
        if (-not $nextOpen -or ($overallDeadline -and $nextOpen -ge $overallDeadline)) {
            $runStopped = $true
            break
        }

        $nextWindow = Get-ScheduleWindowFor -Windows $scheduleWindows -Now $nextOpen
        $waitedFrom = Get-Date
        $null = Wait-ForScheduledStart -StartTime $nextOpen -StopTime $(if ($nextWindow) { $nextWindow.Close } else { $null }) -LogFile $logFile
        $paused = (Get-Date) - $waitedFrom
        $totalPausedSeconds += $paused.TotalSeconds
        # The elapsed counter and the ETA measure scanning, not the nights in
        # between: move their origin forward by however long we slept.
        $scanStartTime = $scanStartTime.AddSeconds($paused.TotalSeconds)
        $scriptStartTime = $scriptStartTime.AddSeconds($paused.TotalSeconds)

        $window = Get-ScheduleWindowFor -Windows $scheduleWindows -Now (Get-Date)
        if (-not $window) { $runStopped = $true; break }
    }

    # The window closes at its own hour, or at the end of the engagement,
    # whichever comes first. Everything downstream already understands $stopTime.
    $stopTime = if ($overallDeadline -and $overallDeadline -lt $window.Close) { $overallDeadline } else { $window.Close }
    $stopTimeForProgress = $stopTime
    $stopWarningsFired = @{}
    $stopReached = $false

    if ($carryOver.Count -gt 0) {
        $notYetStarted = if ($hostIndex -lt $workList.Count) { @($workList[$hostIndex..($workList.Count - 1)]) } else { @() }
        $workList = @($carryOver) + $notYetStarted
        $hostIndex = 0
        $carryOver = @()
    }

    $remainingNow = $workList.Count - $hostIndex
    Write-Host ""
    Write-Host "▶️  Window $windowNumber open " -NoNewline -ForegroundColor Cyan
    Write-Host "$($window.Open.ToString('ddd yyyy-MM-dd HH:mm')) -> $($stopTime.ToString('HH:mm')) " -NoNewline -ForegroundColor White
    Write-Host "($(Format-Duration -TimeSpan ($stopTime - (Get-Date))) left, $remainingNow item(s) to go)" -ForegroundColor Gray
    Write-Log -Message "Scan window $windowNumber open until $($stopTime.ToString('yyyy-MM-dd HH:mm:ss')): $remainingNow item(s) left" -Level "INFO" -LogFile $logFile
}

while ($hostIndex -lt $workList.Count) {
    # Scheduled stop: nothing new leaves the machine after the deadline.
    Show-StopWarning -StopTime $stopTime -Fired $stopWarningsFired -StopMode $StopMode -LogFile $logFile
    if ($stopTime -and (Get-Date) -ge $stopTime) { $stopReached = $true; break }

    # A retry whose delay is over takes a free slot before the next new host
    $null = Start-DueRetries -RetryQueue $retryQueue -JobQueue $jobQueue -JobStartTimes $jobStartTimes -MaxConcurrent $MaxConcurrent -StopTime $stopTime -Unprivileged $Unprivileged -NmapPath $nmapExePath -Verbatim $isCommandMode

    $currentHost = $workList[$hostIndex]

    # Wait if max concurrent jobs reached
    $progressUpdateCounter = 0
    while ($jobQueue.Count -ge $MaxConcurrent) {
        Show-StopWarning -StopTime $stopTime -Fired $stopWarningsFired -StopMode $StopMode -LogFile $logFile
        if ($stopTime -and (Get-Date) -ge $stopTime) { $stopReached = $true; break }
        Start-Sleep -Milliseconds 500
        $progressUpdateCounter++

        # Refresh the bar every ~5 seconds (10 iterations * 500ms) even when no
        # job finishes: a clock that stands still for a minute reads as a hang
        if ($progressUpdateCounter % 10 -eq 0) {
            if ($isWorkflowMode) {
                Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $totalWork -Failed $failedCount -CurrentHost "" -WorkflowStep $workflowStepNumber -WorkflowTotalSteps $workflowSteps.Count -StepProfile $currentProfile -NetworkProgress $script:networkProgress -LivenessCounts $script:livenessCounts -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations -Concurrency $MaxConcurrent -StopTime $stopTimeForProgress -PendingRetries $retryQueue.Count
            } else {
                Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $totalWork -Failed $failedCount -CurrentHost "" -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations -Concurrency $MaxConcurrent -LivenessCounts $script:livenessCounts -StopTime $stopTimeForProgress -PendingRetries $retryQueue.Count
            }
        }

        . $collectFinishedJobs

        # Slots freed above go to due retries first
        $null = Start-DueRetries -RetryQueue $retryQueue -JobQueue $jobQueue -JobStartTimes $jobStartTimes -MaxConcurrent $MaxConcurrent -StopTime $stopTime -Unprivileged $Unprivileged -NmapPath $nmapExePath -Verbatim $isCommandMode
    }

    # The wait above exits on the deadline as well as on a free slot
    if ($stopReached) { break }

    # This host is ours now: the index moves on even if the body skips it, which
    # is what keeps a `continue` below from re-reading the same entry forever.
    $hostIndex++

    # Get host metadata from state
    $hostMeta = $state.hosts[$currentHost]
    $hostFolder = $hostMeta.output_folder
    $isSensitive = $hostMeta.sensitive

    if ($isCommandMode) {
        # The unit already carries its command, its target and its own output
        # flag: it runs verbatim, and nmap writes where the author said.
        $currentScanCommand = if ($hostMeta.exec_command) { $hostMeta.exec_command } else { $hostMeta.command }
        $fileName = $currentHost
        $unitResultFile = $hostMeta.result_file
        $existingResultFile = if ($unitResultFile) { $unitResultFile } else { "$([IO.Path]::Combine($hostFolder, $fileName)).nmap" }
    } else {
        $fileName = "$currentScanType"
        # Determine scan command (normal or sensitive)
        $baseScanCommand = $scanProfiles[$currentScanType].command
        if ($isSensitive) {
            $currentScanCommand = Get-SensitiveScanCommand -BaseCommand $baseScanCommand -Timing $SensitiveTiming -Scripts $SensitiveScripts
        } else {
            $currentScanCommand = $baseScanCommand
        }
        $unitResultFile = ""
        $existingResultFile = "$([IO.Path]::Combine($hostFolder, $fileName)).nmap"
    }

    # Check if results already exist. In command-list mode a file at the
    # author's -oA path may well be from a previous version of that line, so
    # the check is whether THIS command produced it.
    $skipHost = $false
    $resultsAreCurrent = if ($isCommandMode) {
        Test-NmapOutputMatchesCommand -ResultFile $existingResultFile -Command $currentScanCommand
    } else {
        Test-Path $existingResultFile
    }
    if ($resultsAreCurrent) {
        # If host was in_progress, always overwrite incomplete results
        if ($hostMeta.status -eq "in_progress") {
            Write-Log -Message "Overwriting incomplete scan for $currentHost (was in_progress)" -Level "INFO" -LogFile $logFile
        } else {
            $existingNmapFile = $existingResultFile
            switch ($OverwriteMode) {
                "Skip" {
                    Write-Log -Message "Skipping $currentHost (results already exist)" -Level "INFO" -LogFile $logFile
                    # Classify here as well: a skipped host that reached the
                    # summary without a verdict would just be re-parsed there.
                    $skipVerdict = Get-HostLivenessVerdict -ResultFile $existingNmapFile -TargetHost $currentHost -OutputFlag $state.hosts[$currentHost].output_flag
                    Update-HostState -State $state -TargetHost $currentHost -Status "completed" -Attempts 0 -ScanFile $existingNmapFile `
                                     -Liveness $skipVerdict.Verdict -LivenessReason $skipVerdict.Evidence -OpenPortCount $skipVerdict.OpenCount
                    $script:livenessCounts[$skipVerdict.Verdict]++
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
        $fullNmapCommand = "$currentScanCommand -oA `"$([IO.Path]::Combine($hostFolder, $fileName))`" $currentHost"
        Write-Log -Message "Command: $fullNmapCommand" -Level "VERBOSE" -LogFile $logFile
    }

    $job = Start-NmapScanJob -TargetHost $currentHost -ScanCommand $currentScanCommand -OutputPath $hostFolder -FileName $fileName -Attempts 1 -Unprivileged $Unprivileged -NmapPath $nmapExePath -Verbatim $isCommandMode -ResultFile $unitResultFile

    $jobQueue[$currentHost] = @{
        Job = $job
        Attempts = 1
        HostFolder = $hostFolder
        FileName = $fileName
        ScanCommand = $currentScanCommand
        ResultFile = $unitResultFile
    }
    $jobStartTimes[$currentHost] = Get-Date

    if ($isWorkflowMode) {
        Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $totalWork -Failed $failedCount -CurrentHost $currentHost -WorkflowStep $workflowStepNumber -WorkflowTotalSteps $workflowSteps.Count -StepProfile $currentProfile -NetworkProgress $script:networkProgress -LivenessCounts $script:livenessCounts -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations -Concurrency $MaxConcurrent -StopTime $stopTimeForProgress -PendingRetries $retryQueue.Count
    } else {
        Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $totalWork -Failed $failedCount -CurrentHost $currentHost -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations -Concurrency $MaxConcurrent -LivenessCounts $script:livenessCounts -StopTime $stopTimeForProgress -PendingRetries $retryQueue.Count
    }
}

# Wait for remaining jobs to complete
$progressUpdateCounter = 0
# Retries still waiting keep this loop alive, but only until the deadline: past
# it nothing new is launched, and they are carried over below instead.
while ($jobQueue.Count -gt 0 -or ($retryQueue.Count -gt 0 -and -not ($stopTime -and (Get-Date) -ge $stopTime))) {
    Show-StopWarning -StopTime $stopTime -Fired $stopWarningsFired -StopMode $StopMode -LogFile $logFile
    if ($stopTime -and $StopMode -ne "Drain" -and (Get-Date) -ge $stopTime) { $stopReached = $true; break }
    Start-Sleep -Milliseconds 500
    $progressUpdateCounter++

    # Refresh the bar every ~5 seconds (10 iterations * 500ms) even when no
    # job finishes: a clock that stands still for a minute reads as a hang
    if ($progressUpdateCounter % 10 -eq 0) {
        if ($isWorkflowMode) {
            Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $totalWork -Failed $failedCount -CurrentHost "" -WorkflowStep $workflowStepNumber -WorkflowTotalSteps $workflowSteps.Count -StepProfile $currentProfile -NetworkProgress $script:networkProgress -LivenessCounts $script:livenessCounts -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations -Concurrency $MaxConcurrent -StopTime $stopTimeForProgress -PendingRetries $retryQueue.Count
        } else {
            Show-ProgressBar -Completed ($completedCount + $failedCount) -Total $totalWork -Failed $failedCount -CurrentHost "" -ActiveJobs $jobQueue -ScanStartTime $scanStartTime -CompletedDurations $scanDurations -Concurrency $MaxConcurrent -LivenessCounts $script:livenessCounts -StopTime $stopTimeForProgress -PendingRetries $retryQueue.Count
        }
    }

    . $collectFinishedJobs

    $null = Start-DueRetries -RetryQueue $retryQueue -JobQueue $jobQueue -JobStartTimes $jobStartTimes -MaxConcurrent $MaxConcurrent -StopTime $stopTime -Unprivileged $Unprivileged -NmapPath $nmapExePath -Verbatim $isCommandMode
}

# Scheduled stop: cut this window here. Scans still in flight are stopped and
# left unfinished rather than recorded as failures - they were never given the
# chance to complete, and the next window has to run them again from the start.
# They stay "in_progress" on purpose: a killed nmap still leaves a partial .nmap
# on disk, and that is the one status the resume treats as incomplete results to
# overwrite instead of a finished scan to skip.
# A retry still waiting when the deadline came was never launched: it ends
# this window the same way as a scan stopped in flight.
if ($retryQueue.Count -gt 0) { $stopReached = $true }

$killedHere = 0
if ($stopReached) {
    foreach ($entry in @($jobQueue.GetEnumerator())) {
        $stoppedHost = $entry.Key
        try {
            Stop-Job -Job $entry.Value.Job -ErrorAction SilentlyContinue
            Remove-Job -Job $entry.Value.Job -Force -ErrorAction SilentlyContinue
        } catch { }
        Update-HostState -State $state -TargetHost $stoppedHost -Status "in_progress" -Attempts $entry.Value.Attempts -Error "Stopped at the scheduled stop time (incomplete, will be scanned again)"
        $killedHere++
        $stoppedInFlight++
        $carryOver += $stoppedHost
        $jobQueue.Remove($stoppedHost)
    }
    $retriesLeft = $retryQueue.Count
    foreach ($entry in @($retryQueue.GetEnumerator())) {
        Update-HostState -State $state -TargetHost $entry.Key -Status "in_progress" -Attempts $entry.Value.Attempts -Error "Retry pending at the scheduled stop time (will be scanned again)"
        $carryOver += $entry.Key
    }
    $retryQueue.Clear()
    Save-StateFile -StateFile $stateFile -State $state
    $stopDetail = if ($StopMode -eq "Drain") {
        "the scans already running were allowed to finish"
    } else {
        "$killedHere scan(s) stopped in flight and left unfinished"
    }
    if ($retriesLeft -gt 0) { $stopDetail += "; $retriesLeft retry(ies) not launched" }
    Write-Log -Message "Scheduled stop reached ($($stopTime.ToString('yyyy-MM-dd HH:mm:ss')), mode $StopMode): $stopDetail" -Level "WARNING" -LogFile $logFile
}

# --- end of this window -----------------------------------------------------
if (-not $scheduleWindows) { break }

$itemsLeft = ($workList.Count - $hostIndex) + $carryOver.Count
$unfinishedNow = @($state.hosts.GetEnumerator() | Where-Object {
    $_.Value.status -eq "pending" -or $_.Value.status -eq "in_progress"
}).Count

# Nothing left to hand out and nothing still running: the work is done, whatever
# the clock says. Without this a schedule would keep opening empty windows.
if ($itemsLeft -le 0 -and $jobQueue.Count -eq 0) { break }

if ($overallDeadline -and (Get-Date) -ge $overallDeadline) {
    $runStopped = $true
    break
}

# There is work left and the engagement has not ended: sleep until the schedule
# opens again and carry on where we stopped.
Write-Host ""
Write-Host "⏸️  Window $windowNumber closed " -NoNewline -ForegroundColor Yellow
Write-Host "at $((Get-Date).ToString('HH:mm:ss')) " -NoNewline -ForegroundColor White
Write-Host "- $unfinishedNow item(s) still to scan" -ForegroundColor Gray
Write-Log -Message "Window $windowNumber closed: $unfinishedNow item(s) still to scan" -Level "INFO" -LogFile $logFile

} # End of window loop

# Clear progress bars
if ($isWorkflowMode) {
    Write-Progress -Id 2 -Activity "Current step" -Completed
} else {
    Write-Progress -Activity "Scanning hosts" -Completed
}

# Final summary
$scriptEndTime = Get-Date
$totalDuration = $scriptEndTime - $scriptStartTime
# "Stopped" means the schedule ended the run with work still to do. A run that
# finished everything inside its windows completed, whatever the clock did.
$unfinishedAtEnd = @($state.hosts.GetEnumerator() | Where-Object {
    $_.Value.status -eq "pending" -or $_.Value.status -eq "in_progress"
}).Count
$stopReached = ($stopReached -or $runStopped) -and $unfinishedAtEnd -gt 0

$state.status = if ($stopReached) { "stopped" } else { "completed" }
$state.end_time = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
if ($stopTime) { $state.stop_at = $stopTime.ToString("yyyy-MM-ddTHH:mm:ss") }
if ($Schedule -and $Schedule -ne "") { $state.schedule = $Schedule }
if ($overallDeadline) { $state.until = $overallDeadline.ToString("yyyy-MM-ddTHH:mm:ss") }
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
# A host that was never scanned - left pending by a scheduled stop, or skipped
# by a retry-only mode - is not a failure. Counting it as one turns a run that
# was cut short on purpose into a report full of red.
$normalNetworkPending = 0
$sensitiveNetworkPending = 0
$normalIndividualPending = 0
$sensitiveIndividualPending = 0
$normalPending = 0
$sensitivePending = 0

# Count unique networks
$uniqueNetworks = @{}

foreach ($currentHost in $validHosts) {
    $hostMeta = $state.hosts[$currentHost]
    $isSensitive = $hostMeta.sensitive
    $isFromCIDR = $null -ne $hostMeta.source_cidr -and $hostMeta.source_cidr -ne ""
    $isSuccess = $hostMeta.status -eq "completed"
    $isFailure = $hostMeta.status -eq "failed"

    # Track unique networks
    if ($isFromCIDR) {
        $uniqueNetworks[$hostMeta.source_cidr] = $true
    }

    if ($isFromCIDR) {
        $networkHostsCount++
        if ($isSensitive) {
            if ($isSuccess) { $sensitiveNetworkSuccess++ } elseif ($isFailure) { $sensitiveNetworkFailed++ } else { $sensitiveNetworkPending++ }
        } else {
            if ($isSuccess) { $normalNetworkSuccess++ } elseif ($isFailure) { $normalNetworkFailed++ } else { $normalNetworkPending++ }
        }
    } else {
        $individualHostsCount++
        if ($isSensitive) {
            if ($isSuccess) { $sensitiveIndividualSuccess++ } elseif ($isFailure) { $sensitiveIndividualFailed++ } else { $sensitiveIndividualPending++ }
        } else {
            if ($isSuccess) { $normalIndividualSuccess++ } elseif ($isFailure) { $normalIndividualFailed++ } else { $normalIndividualPending++ }
        }
    }

    if ($isSensitive) {
        if ($isSuccess) { $sensitiveSuccess++ } elseif ($isFailure) { $sensitiveFailed++ } else { $sensitivePending++ }
    } else {
        if ($isSuccess) { $normalSuccess++ } elseif ($isFailure) { $normalFailed++ } else { $normalPending++ }
    }
}

$networkCount = $uniqueNetworks.Count
$conflictCount = if ($conflicts) { $conflicts.Count } else { 0 }

# Tally the liveness verdicts. State files written before liveness existed carry
# no verdict, so those hosts are classified once, here, and nowhere else.
$verdictCounts = @{ open = 0; alive = 0; filtered = 0; unreachable = 0; unknown = 0 }

foreach ($currentHost in $validHosts) {
    $hostMeta = $state.hosts[$currentHost]
    if ($hostMeta.status -ne "completed") { continue }

    $verdict = if ($hostMeta.liveness) {
        [string]$hostMeta.liveness
    } else {
        Get-PersistedLiveness -HostState $hostMeta -TargetHost $currentHost
    }
    if (-not $verdict -or -not $verdictCounts.ContainsKey($verdict)) { $verdict = 'unknown' }
    $verdictCounts[$verdict]++
}

$openHostsCount   = $verdictCounts.open
$aliveHostsCount  = $verdictCounts.alive
$noRespHostsCount = $verdictCounts.filtered + $verdictCounts.unreachable + $verdictCounts.unknown

# Calculate metrics
$totalCompleted = $normalSuccess + $sensitiveSuccess
$totalFailed = $normalFailed + $sensitiveFailed
$totalPending = $normalPending + $sensitivePending

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

$pendingPercent = if ($validHosts.Count -gt 0) {
    [math]::Round($totalPending / $validHosts.Count * 100, 1)
} else {
    0
}

$openPercent = if ($totalCompleted -gt 0) {
    [math]::Round($openHostsCount / $totalCompleted * 100, 1)
} else {
    0
}

$alivePercent = if ($totalCompleted -gt 0) {
    [math]::Round($aliveHostsCount / $totalCompleted * 100, 1)
} else {
    0
}

$noRespPercent = if ($totalCompleted -gt 0) {
    [math]::Round($noRespHostsCount / $totalCompleted * 100, 1)
} else {
    0
}

# Format duration (remove leading zeros)
$durationFormatted = Format-Duration -TimeSpan $totalDuration

Write-Host ""
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

if ($totalPausedSeconds -gt 0) {
    Write-Host "   Paused   : " -NoNewline -ForegroundColor Cyan
    Write-Host "$(Format-Duration -TimeSpan ([TimeSpan]::FromSeconds($totalPausedSeconds))) " -NoNewline -ForegroundColor White
    Write-Host "between windows (not counted above)" -ForegroundColor DarkGray
}

# Output directory info
Write-Host "📁 Output   : " -NoNewline -ForegroundColor Cyan
if ($isWorkflowMode) {
    Write-Host "$([IO.Path]::Combine($OutputDir, $Workflow))$([IO.Path]::DirectorySeparatorChar)" -ForegroundColor White
} else {
    Write-Host "$OutputDir$([IO.Path]::DirectorySeparatorChar)" -ForegroundColor White
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
if ($totalPending -gt 0) {
    Write-Host "($failPercent%)" -NoNewline -ForegroundColor Red
    Write-Host " | " -NoNewline -ForegroundColor DarkGray
    Write-Host "$totalPending " -NoNewline -ForegroundColor White
    Write-Host "⏸ " -NoNewline -ForegroundColor Yellow
    Write-Host "pending ($pendingPercent%)" -ForegroundColor Yellow
} else {
    Write-Host "($failPercent%)" -ForegroundColor Red
}

# Host status. "Open" is attack surface, "Responded" is a host that answered but
# offers nothing, "No response" is the only bucket where we genuinely do not know.
Write-Host "🎯 Status   : " -NoNewline -ForegroundColor Cyan
Write-Host "$openHostsCount " -NoNewline -ForegroundColor White
Write-Host "🟢 " -NoNewline -ForegroundColor Green
Write-Host "Open ($openPercent%)" -NoNewline -ForegroundColor Green
Write-Host " | " -NoNewline -ForegroundColor DarkGray
Write-Host "$aliveHostsCount " -NoNewline -ForegroundColor White
Write-Host "🟡 " -NoNewline -ForegroundColor Yellow
Write-Host "Responded, no ports ($alivePercent%)" -NoNewline -ForegroundColor Yellow
Write-Host " | " -NoNewline -ForegroundColor DarkGray
Write-Host "$noRespHostsCount " -NoNewline -ForegroundColor White
Write-Host "⚫ " -NoNewline -ForegroundColor DarkGray
Write-Host "No response ($noRespPercent%)" -ForegroundColor DarkGray

if ($noRespHostsCount -gt 0) {
    Write-Host "              └─ of those $noRespHostsCount" -NoNewline -ForegroundColor DarkGray
    Write-Host ": $($verdictCounts.filtered) filtered · $($verdictCounts.unreachable) unreachable · $($verdictCounts.unknown) unknown" -ForegroundColor DarkGray
}

Write-Host ""

# Source breakdown
Write-Host "📁 Source Breakdown" -ForegroundColor Cyan

# Networks section - only show if there are networks
if ($networkCount -gt 0) {
    Write-Host "   Networks : " -NoNewline -ForegroundColor White
    Write-Host "$networkCount CIDR(s) - $networkHostsCount hosts" -ForegroundColor White

    Write-Host "   ├─ Normal    : " -NoNewline -ForegroundColor White
    Write-Host "$($normalNetworkSuccess + $normalNetworkFailed + $normalNetworkPending) " -NoNewline -ForegroundColor White
    Write-Host "(✅ " -NoNewline -ForegroundColor Green
    Write-Host "$normalNetworkSuccess" -NoNewline -ForegroundColor Green
    Write-Host " | ❌ " -NoNewline -ForegroundColor Red
    Write-Host "$normalNetworkFailed" -NoNewline -ForegroundColor Red
    if ($normalNetworkPending -gt 0) {
        Write-Host " | ⏸ " -NoNewline -ForegroundColor Yellow
        Write-Host "$normalNetworkPending" -NoNewline -ForegroundColor Yellow
    }
    Write-Host ")" -ForegroundColor White

    Write-Host "   └─ Sensitive : " -NoNewline -ForegroundColor White
    Write-Host "$($sensitiveNetworkSuccess + $sensitiveNetworkFailed + $sensitiveNetworkPending) " -NoNewline -ForegroundColor Yellow
    Write-Host "(✅ " -NoNewline -ForegroundColor Green
    Write-Host "$sensitiveNetworkSuccess" -NoNewline -ForegroundColor Green
    Write-Host " | ❌ " -NoNewline -ForegroundColor Red
    Write-Host "$sensitiveNetworkFailed" -NoNewline -ForegroundColor Red
    if ($sensitiveNetworkPending -gt 0) {
        Write-Host " | ⏸ " -NoNewline -ForegroundColor Yellow
        Write-Host "$sensitiveNetworkPending" -NoNewline -ForegroundColor Yellow
    }
    Write-Host ")" -ForegroundColor Yellow

    Write-Host ""
}

# Individual hosts section - only show if there are individual hosts
if ($individualHostsCount -gt 0) {
    Write-Host "   Individual: " -NoNewline -ForegroundColor White
    Write-Host "$individualHostsCount hosts" -ForegroundColor White

    Write-Host "   ├─ Normal    : " -NoNewline -ForegroundColor White
    Write-Host "$($normalIndividualSuccess + $normalIndividualFailed + $normalIndividualPending) " -NoNewline -ForegroundColor White
    Write-Host "(✅ " -NoNewline -ForegroundColor Green
    Write-Host "$normalIndividualSuccess" -NoNewline -ForegroundColor Green
    Write-Host " | ❌ " -NoNewline -ForegroundColor Red
    Write-Host "$normalIndividualFailed" -NoNewline -ForegroundColor Red
    if ($normalIndividualPending -gt 0) {
        Write-Host " | ⏸ " -NoNewline -ForegroundColor Yellow
        Write-Host "$normalIndividualPending" -NoNewline -ForegroundColor Yellow
    }
    Write-Host ")" -ForegroundColor White

    Write-Host "   └─ Sensitive : " -NoNewline -ForegroundColor White
    Write-Host "$($sensitiveIndividualSuccess + $sensitiveIndividualFailed + $sensitiveIndividualPending) " -NoNewline -ForegroundColor Yellow
    Write-Host "(✅ " -NoNewline -ForegroundColor Green
    Write-Host "$sensitiveIndividualSuccess" -NoNewline -ForegroundColor Green
    Write-Host " | ❌ " -NoNewline -ForegroundColor Red
    Write-Host "$sensitiveIndividualFailed" -NoNewline -ForegroundColor Red
    if ($sensitiveIndividualPending -gt 0) {
        Write-Host " | ⏸ " -NoNewline -ForegroundColor Yellow
        Write-Host "$sensitiveIndividualPending" -NoNewline -ForegroundColor Yellow
    }
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

$sessionOutcome = if ($stopReached) { "Scan session stopped at the scheduled time" } else { "Scan session completed" }
Write-Log -Message "$sessionOutcome | Total: $($validHosts.Count) | Normal: $($normalSuccess + $normalFailed) (success: $normalSuccess, failed: $normalFailed) | Sensitive: $($sensitiveSuccess + $sensitiveFailed) (success: $sensitiveSuccess, failed: $sensitiveFailed) | Pending: $totalPending | Excluded: $($excludedHosts.Count) | Duration: $durationFormatted" -Level $(if ($stopReached) { "WARNING" } else { "SUCCESS" }) -LogFile $logFile

if ($failedCount -gt 0) {
    Write-Host "[INFO] To retry failed hosts, run:" -ForegroundColor Yellow
    if ($isWorkflowMode) {
        Write-Host "  $(Get-InvocationHint) -HostFile $HostFile -Workflow $Workflow -RetryFailed`n" -ForegroundColor Yellow
    } else {
        Write-Host "  $(Get-InvocationHint) -HostFile $HostFile -ScanType $ScanType -RetryFailed`n" -ForegroundColor Yellow
    }
}

# Hosts that never answered are the only ones a second pass can change.
if (($verdictCounts.filtered + $verdictCounts.unreachable) -gt 0) {
    Write-Host "[INFO] To re-probe the hosts that never responded, run:" -ForegroundColor Yellow
    if ($isWorkflowMode) {
        Write-Host "  $(Get-InvocationHint) -HostFile $HostFile -Workflow $Workflow -RetryDead`n" -ForegroundColor Yellow
    } else {
        Write-Host "  $(Get-InvocationHint) -HostFile $HostFile -ScanType $ScanType -RetryDead`n" -ForegroundColor Yellow
    }
}

# What was left behind and how to pick it up. Printed on every run, because the
# session that most needs its resume line is the one that did not finish.
Write-Host ""
if ($stopReached) {
    Write-Host "⏹️  Stopped by the schedule" -ForegroundColor Yellow
    if ($scheduleWindows) {
        Write-Host "   Schedule  : " -NoNewline -ForegroundColor Cyan
        Write-Host "$Schedule " -NoNewline -ForegroundColor White
        Write-Host "| $windowNumber window(s) used" -ForegroundColor Gray
        if ($overallDeadline) {
            Write-Host "   Ended at  : " -NoNewline -ForegroundColor Cyan
            Write-Host "$($overallDeadline.ToString('yyyy-MM-dd HH:mm:ss')) " -NoNewline -ForegroundColor White
            Write-Host "(-Until)" -ForegroundColor Gray
        }
    } elseif ($stopTime) {
        Write-Host "   Stop time : " -NoNewline -ForegroundColor Cyan
        Write-Host "$($stopTime.ToString('yyyy-MM-dd HH:mm:ss')) " -NoNewline -ForegroundColor White
        Write-Host "| now: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
    }
    Write-Host "   Left over : " -NoNewline -ForegroundColor Cyan
    Write-Host "$unfinishedAtEnd still to scan " -NoNewline -ForegroundColor White
    if ($StopMode -eq "Drain") {
        Write-Host "(drain: the scans already running were allowed to finish)" -ForegroundColor Gray
    } else {
        Write-Host "($stoppedInFlight stopped in flight, they will be scanned again)" -ForegroundColor Gray
    }
    Write-Host ""
}

Write-Host "↩️  Resume this session" -ForegroundColor Cyan
Write-Host "   $resumeCommand" -ForegroundColor Yellow
# Same line on disk, with the outcome of this run, for whoever comes back to it
$resumeFile = Write-ResumeFile -SessionDir $sessionDir -ResumeCommand $resumeCommand -SessionId $sessionId -Status $state.status
if ($resumeFile) {
    Write-Host "   Saved in  : " -NoNewline -ForegroundColor Cyan
    Write-Host "$resumeFile" -ForegroundColor Gray
}

# Next steps suggestion with XNP
Write-Host ""
Write-Host "🚀 Next Steps" -ForegroundColor Cyan
Write-Host "   To analyze and merge scan results, you can use XtremeNmapParser (XNP):" -ForegroundColor White
Write-Host ""
if ($isWorkflowMode) {
    Write-Host "   xnp -d `"$([IO.Path]::Combine($OutputDir, $Workflow))`" --show" -ForegroundColor Yellow
} else {
    Write-Host "   xnp -d `"$OutputDir`" --show" -ForegroundColor Yellow
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
    Export-ScanResults -ResultsFile $resultsFile -SessionId $sessionId

    if ($stopReached) {
        $stepsLeft = $workflowSteps.Count - ($workflowStepNumber - 1)
        if ($isWorkflowMode -and $stepsLeft -gt 0) {
            Write-Host "[INFO] $stepsLeft workflow step(s) were not started because of the scheduled stop." -ForegroundColor Yellow
            Write-Log -Message "Workflow halted by the scheduled stop: $stepsLeft step(s) not started" -Level "WARNING" -LogFile $logFile
        }
        break
    }
} # End of workflow loop

# Clear all progress bars after workflow completes
if ($isWorkflowMode) {
    Write-Progress -Id 1 -Activity "Workflow Progress" -Completed
    Write-Progress -Id 2 -Activity "Current step" -Completed
}

if ($isWorkflowMode -and -not $stopReached) {
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "  Workflow Complete: $($workflowDef.name)" -ForegroundColor Green
    Write-Host "  All $($workflowSteps.Count) steps finished" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green
    Write-Log -Message "Workflow completed: $Workflow" -Level "SUCCESS" -LogFile $logFile
}

# Normal completion: stop the exiting handler from firing and reporting an
# interruption that never happened.
$script:scanCompleted = $true
if ($exitSubscriber) {
    Unregister-Event -SubscriptionId $exitSubscriber.Id -ErrorAction SilentlyContinue
    Remove-Job -Job $exitSubscriber -Force -ErrorAction SilentlyContinue
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
