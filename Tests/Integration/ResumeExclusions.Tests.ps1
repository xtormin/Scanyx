# ResumeExclusions.Tests.ps1
# End-to-end tests for adding -ExcludeHosts to a session that is being resumed.
# On a resume the target list IS the session state, so an exclusion decides what
# stays in that file: these tests pin down that an excluded host keeps its entry
# instead of being dropped, and comes back as it was once the exclusion is gone.
# A stand-in nmap records each argv it is given, so the tests see exactly what
# would have been scanned, without touching the network or needing nmap.

BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1'))

    $script:fakeBin = Join-Path $TestDrive "exbin"
    New-Item -ItemType Directory -Path $script:fakeBin -Force | Out-Null
    $script:argvLog = Join-Path $TestDrive "exnmap-argv.log"

    $fakeNmap = Join-Path $script:fakeBin "nmap"
    Set-Content -Path $fakeNmap -Value @'
#!/bin/sh
echo "$*" >> "$FAKE_NMAP_LOG"
case " $* " in *" -V "*|*" --version "*) echo "Nmap version 7.99"; exit 0;; esac
out=""; prev=""
for a in "$@"; do [ "$prev" = "-oA" ] && out="$a"; prev="$a"; done
if [ -n "$out" ]; then
    mkdir -p "$(dirname "$out")"
    printf '# Nmap 7.99 scan initiated Wed Oct  7 12:00:00 2026 as: nmap %s\n22/tcp open ssh\n# Nmap done -- 1 IP address (1 host up) scanned in 0.01 seconds\n' "$*" > "$out.nmap"
    : > "$out.xml"; : > "$out.gnmap"
fi
exit 0
'@
    chmod +x $fakeNmap

    $script:savedPath = $env:PATH
    $env:PATH = "$($script:fakeBin)$([IO.Path]::PathSeparator)$env:PATH"
    $env:FAKE_NMAP_LOG = $script:argvLog

    function Get-ScannedLines {
        if (-not (Test-Path $script:argvLog)) { return @() }
        # The capability probe (--noninteractive -V) is not a scan
        @(Get-Content $script:argvLog | Where-Object { $_ -notmatch '(^| )-V( |$)' })
    }

    function Get-SessionStateFile {
        param([string]$OutputDir, [string]$Session)
        [IO.Path]::Combine($OutputDir, ".sessions", $Session, "scan-state.json")
    }

    function Read-SessionState {
        param([string]$StateFile)
        Get-Content $StateFile -Raw | ConvertFrom-Json
    }

    function Set-HostStatus {
        # Puts a host back the way a scheduled stop leaves it: unfinished. A
        # resume needs something left to do, or it returns before it saves.
        param([string]$StateFile, [string]$TargetHost, [string]$Status)
        $s = Get-Content $StateFile -Raw | ConvertFrom-Json
        $s.hosts.$TargetHost.status = $Status
        $s | ConvertTo-Json -Depth 10 | Set-Content $StateFile
    }
}

AfterAll {
    $env:PATH = $script:savedPath
    Remove-Item Env:FAKE_NMAP_LOG -ErrorAction SilentlyContinue
}

Describe "-ExcludeHosts on a resumed session" -Tag "Integration", "Exclusions" -Skip:$IsWindows {
    BeforeEach {
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $out = Join-Path $root "out"
        $cfg = Join-Path $root "profiles.json"
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        @{
            profiles = @{ "tcp-test" = @{
                name = "TCP Test"; description = "Fast test profile"
                command = "nmap -sT -Pn -p 22 -T4"
            } }
            workflows = @{}
        } | ConvertTo-Json -Depth 10 | Set-Content $cfg

        Remove-Item $script:argvLog -ErrorAction SilentlyContinue

        # A finished session with three hosts, then one of them put back to
        # pending: that is the state every test here resumes from.
        Invoke-Scanyx -Hosts "127.0.0.1", "127.0.0.2", "127.0.0.3" -ScanType "tcp-test" `
                      -SessionName "excl" -OutputDir $out -ConfigFile $cfg -Unprivileged `
                      -OverwriteMode Overwrite -RetryDelay 1 -Yes *> $null

        $stateFile = Get-SessionStateFile -OutputDir $out -Session "excl"
        $before = Read-SessionState -StateFile $stateFile
        $before.hosts.'127.0.0.2'.status | Should -Be "completed"
        $script:scannedAt = $before.hosts.'127.0.0.2'.last_update

        Set-HostStatus -StateFile $stateFile -TargetHost "127.0.0.3" -Status "pending"
        Remove-Item $script:argvLog -ErrorAction SilentlyContinue

        function Invoke-Resume {
            param([string[]]$Exclude = @())
            Invoke-Scanyx -ResumeSession "excl" -OutputDir $out -Resume -ConfigFile $cfg `
                          -Unprivileged -OverwriteMode Overwrite -RetryDelay 1 -Yes `
                          -ExcludeHosts $Exclude *> $null
        }
    }

    It "Keeps an excluded host in the state instead of dropping it" {
        Invoke-Resume -Exclude @("127.0.0.2")

        $s = Read-SessionState -StateFile $stateFile
        $s.hosts.PSObject.Properties.Name | Should -Contain "127.0.0.2"
        $s.hosts.'127.0.0.2'.status | Should -Be "excluded"
        $s.hosts.'127.0.0.2'.previous_status | Should -Be "completed"
        $s.hosts.'127.0.0.2'.excluded_at | Should -Not -BeNullOrEmpty
    }

    It "Keeps what the excluded host's finished scan recorded" {
        Invoke-Resume -Exclude @("127.0.0.2")

        $kept = (Read-SessionState -StateFile $stateFile).hosts.'127.0.0.2'
        $kept.scan_file | Should -Not -BeNullOrEmpty
        $kept.output_folder | Should -Not -BeNullOrEmpty
        $kept.liveness | Should -Not -BeNullOrEmpty
        $kept.last_update | Should -Be $script:scannedAt
    }

    It "Does not scan the excluded host" {
        Invoke-Resume -Exclude @("127.0.0.2")

        $scanned = @(Get-ScannedLines)
        $scanned.Count | Should -Be 1
        $scanned[0] | Should -Match '127\.0\.0\.3'
        @($scanned | Where-Object { $_ -match '127\.0\.0\.2' }).Count | Should -Be 0
    }

    It "Leaves the excluded host out of the work in hand, so the session still completes" {
        Invoke-Resume -Exclude @("127.0.0.2")

        $s = Read-SessionState -StateFile $stateFile
        $s.total_hosts | Should -Be 2
        $s.excluded | Should -Be 1
        $s.pending | Should -Be 0
        $s.status | Should -Be "completed"
    }

    It "Puts the host back as it was when the exclusion is lifted, without rescanning it" {
        Invoke-Resume -Exclude @("127.0.0.2")
        Set-HostStatus -StateFile $stateFile -TargetHost "127.0.0.3" -Status "pending"
        Remove-Item $script:argvLog -ErrorAction SilentlyContinue

        Invoke-Resume

        $s = Read-SessionState -StateFile $stateFile
        $s.hosts.'127.0.0.2'.status | Should -Be "completed"
        $s.hosts.'127.0.0.2'.last_update | Should -Be $script:scannedAt
        $s.hosts.'127.0.0.2'.PSObject.Properties.Name | Should -Not -Contain "previous_status"
        $s.total_hosts | Should -Be 3
        @(Get-ScannedLines | Where-Object { $_ -match '127\.0\.0\.2' }).Count | Should -Be 0
    }

    It "Scans a host again when the exclusion is lifted and it never finished" {
        # Something else has to be left to scan, or the resume below returns
        # before it writes anything (see the last test in this block).
        Set-HostStatus -StateFile $stateFile -TargetHost "127.0.0.1" -Status "pending"
        Invoke-Resume -Exclude @("127.0.0.3")

        (Read-SessionState -StateFile $stateFile).hosts.'127.0.0.3'.previous_status | Should -Be "pending"
        @(Get-ScannedLines | Where-Object { $_ -match '127\.0\.0\.3' }).Count | Should -Be 0

        Invoke-Resume

        $s = Read-SessionState -StateFile $stateFile
        $s.hosts.'127.0.0.3'.status | Should -Be "completed"
        @(Get-ScannedLines | Where-Object { $_ -match '127\.0\.0\.3' }).Count | Should -Be 1
    }

    It "Leaves the state alone when the exclusion leaves nothing to scan" {
        # Every host either finished or is excluded, so the run stops before it
        # saves. Nothing is marked, and nothing is lost either, which is the
        # part that matters.
        Set-HostStatus -StateFile $stateFile -TargetHost "127.0.0.3" -Status "completed"
        $untouched = Get-Content $stateFile -Raw

        Invoke-Resume -Exclude @("127.0.0.2")

        Get-Content $stateFile -Raw | Should -Be $untouched
        @(Get-ScannedLines).Count | Should -Be 0
    }

    It "Keeps the status from before the first exclusion when the host is excluded twice" {
        Invoke-Resume -Exclude @("127.0.0.2")
        Set-HostStatus -StateFile $stateFile -TargetHost "127.0.0.3" -Status "pending"

        Invoke-Resume -Exclude @("127.0.0.2")

        $kept = (Read-SessionState -StateFile $stateFile).hosts.'127.0.0.2'
        $kept.status | Should -Be "excluded"
        $kept.previous_status | Should -Be "completed"
    }
}

Describe "Exclusions the session remembers" -Tag "Integration", "Exclusions" -Skip:$IsWindows {
    BeforeEach {
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $out = Join-Path $root "out"
        $cfg = Join-Path $root "profiles.json"
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        @{
            profiles = @{ "tcp-test" = @{
                name = "TCP Test"; description = "Fast test profile"
                command = "nmap -sT -Pn -p 22 -T4"
            } }
            workflows = @{}
        } | ConvertTo-Json -Depth 10 | Set-Content $cfg

        Remove-Item $script:argvLog -ErrorAction SilentlyContinue

        Invoke-Scanyx -Hosts "127.0.0.1", "127.0.0.2", "127.0.0.3" -ScanType "tcp-test" `
                      -SessionName "rem" -OutputDir $out -ConfigFile $cfg -Unprivileged `
                      -OverwriteMode Overwrite -RetryDelay 1 -Yes *> $null

        $stateFile = Get-SessionStateFile -OutputDir $out -Session "rem"
        $resumeTxt = [IO.Path]::Combine($out, ".sessions", "rem", "resume.txt")

        # The run that arms the exclusion: its list is the one the session keeps.
        Set-HostStatus -StateFile $stateFile -TargetHost "127.0.0.3" -Status "pending"
        $armedOutput = Invoke-Scanyx -ResumeSession "rem" -OutputDir $out -Resume -ConfigFile $cfg `
                                     -Unprivileged -OverwriteMode Overwrite -RetryDelay 1 -Yes `
                                     -ExcludeHosts "127.0.0.2" *>&1 | Out-String
        Remove-Item $script:argvLog -ErrorAction SilentlyContinue

        function Invoke-ResumeSayingNothing {
            # Neither -ExcludeFile nor -ExcludeHosts bound, which is what makes
            # the session's own list apply.
            Invoke-Scanyx -ResumeSession "rem" -OutputDir $out -Resume -ConfigFile $cfg `
                          -Unprivileged -OverwriteMode Overwrite -RetryDelay 1 -Yes *> $null
        }
    }

    It "Saves the exclusions it was given in the session state" {
        $s = Read-SessionState -StateFile $stateFile
        @($s.exclude_hosts) | Should -Contain "127.0.0.2"
        $s.resolve_hostnames | Should -BeFalse
    }

    It "Puts them in the resume line it prints and in resume.txt" {
        $armedOutput | Should -Match '-ExcludeHosts "127\.0\.0\.2"'
        Get-Content $resumeTxt -Raw | Should -Match '-ExcludeHosts "127\.0\.0\.2"'
    }

    It "Keeps the host excluded on a resume that says nothing about exclusions" {
        Set-HostStatus -StateFile $stateFile -TargetHost "127.0.0.3" -Status "pending"

        Invoke-ResumeSayingNothing

        $s = Read-SessionState -StateFile $stateFile
        $s.hosts.'127.0.0.2'.status | Should -Be "excluded"
        @($s.exclude_hosts) | Should -Contain "127.0.0.2"
        @(Get-ScannedLines | Where-Object { $_ -match '127\.0\.0\.2' }).Count | Should -Be 0
    }

    It "Clears them when an empty -ExcludeHosts is passed" {
        Set-HostStatus -StateFile $stateFile -TargetHost "127.0.0.3" -Status "pending"

        Invoke-Scanyx -ResumeSession "rem" -OutputDir $out -Resume -ConfigFile $cfg -Unprivileged `
                      -OverwriteMode Overwrite -RetryDelay 1 -Yes -ExcludeHosts @() *> $null

        $s = Read-SessionState -StateFile $stateFile
        $s.hosts.'127.0.0.2'.status | Should -Be "completed"
        $s.exclude_hosts | Should -BeNullOrEmpty
    }

    It "Replaces them when a new list is passed" {
        Set-HostStatus -StateFile $stateFile -TargetHost "127.0.0.3" -Status "pending"

        Invoke-Scanyx -ResumeSession "rem" -OutputDir $out -Resume -ConfigFile $cfg -Unprivileged `
                      -OverwriteMode Overwrite -RetryDelay 1 -Yes -ExcludeHosts "127.0.0.1" *> $null

        $s = Read-SessionState -StateFile $stateFile
        $s.hosts.'127.0.0.1'.status | Should -Be "excluded"
        $s.hosts.'127.0.0.2'.status | Should -Be "completed"
        @($s.exclude_hosts) | Should -Contain "127.0.0.1"
        @($s.exclude_hosts) | Should -Not -Contain "127.0.0.2"
    }

    It "Remembers an exclusion file by its resolved path, and that file alone" {
        $exFile = Join-Path $root "gateways.txt"
        Set-Content -Path $exFile -Value "127.0.0.1"
        Set-HostStatus -StateFile $stateFile -TargetHost "127.0.0.3" -Status "pending"

        $said = Invoke-Scanyx -ResumeSession "rem" -OutputDir $out -Resume -ConfigFile $cfg `
                              -Unprivileged -OverwriteMode Overwrite -RetryDelay 1 -Yes `
                              -ExcludeFile $exFile *>&1 | Out-String

        $s = Read-SessionState -StateFile $stateFile
        $s.exclude_file | Should -Be (Resolve-Path -LiteralPath $exFile).Path
        $s.exclude_hosts | Should -BeNullOrEmpty
        $s.hosts.'127.0.0.1'.status | Should -Be "excluded"
        $s.hosts.'127.0.0.2'.status | Should -Be "completed"
        $said | Should -Match '-ExcludeFile "'
    }
}
