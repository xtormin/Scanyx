# ResumeCommandList.Tests.ps1
# End-to-end tests for resuming a command-list session with -ResumeSession, the
# line Scanyx itself prints. A stand-in nmap records each argv it is given, so
# the tests see exactly what would have been scanned, without touching the
# network or needing nmap installed.

BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1'))

    $script:fakeBin = Join-Path $TestDrive "bin"
    New-Item -ItemType Directory -Path $script:fakeBin -Force | Out-Null
    $script:argvLog = Join-Path $TestDrive "nmap-argv.log"

    # Writes the same first line as real nmap ("... as: <argv>"), which is what
    # Test-NmapOutputMatchesCommand reads; fails like nmap on an unknown option.
    $fakeNmap = Join-Path $script:fakeBin "nmap"
    Set-Content -Path $fakeNmap -Value @'
#!/bin/sh
echo "$*" >> "$FAKE_NMAP_LOG"
case " $* " in *" -V "*|*" --version "*) echo "Nmap version 7.99"; exit 0;; esac
case " $* " in *" --bogus "*) echo "nmap: unrecognized option '--bogus'" >&2; exit 255;; esac
out=""; prev=""
for a in "$@"; do [ "$prev" = "-oA" ] && out="$a"; prev="$a"; done
if [ -n "$out" ]; then
    mkdir -p "$(dirname "$out")"
    printf '# Nmap 7.99 scan initiated Wed Oct  7 12:00:00 2026 as: nmap %s\n# Nmap done -- 1 IP address (1 host up) scanned in 0.01 seconds\n' "$*" > "$out.nmap"
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

    function Set-UnitStatus {
        # Puts a unit back the way a scheduled stop leaves it: unfinished.
        param([string]$StateFile, [string]$Label, [string]$Status)
        $s = Get-Content $StateFile -Raw | ConvertFrom-Json
        foreach ($p in $s.hosts.PSObject.Properties) {
            if ($p.Value.label -eq $Label) { $p.Value.status = $Status }
        }
        $s | ConvertTo-Json -Depth 10 | Set-Content $StateFile
    }
}

AfterAll {
    $env:PATH = $script:savedPath
    Remove-Item Env:FAKE_NMAP_LOG -ErrorAction SilentlyContinue
}

Describe "-ResumeSession on a command-list session" -Tag "Integration", "CommandList" -Skip:$IsWindows {
    BeforeEach {
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $out = Join-Path $root "out"
        $res = Join-Path $root "r"
        New-Item -ItemType Directory -Path $res -Force | Out-Null
        $listFile = Join-Path $root "cmds.txt"
        Set-Content -Path $listFile -Value @(
            "nmap -sT -Pn -p 22 127.0.0.1 -oA $res/one"
            "nmap -sT -Pn -p 80 127.0.0.1 -oA $res/two"
        )
        Remove-Item $script:argvLog -ErrorAction SilentlyContinue

        Invoke-Scanyx -CommandFile $listFile -SessionName "rlist" -OutputDir $out -RetryDelay 1 -Yes *> $null
        $stateFile = Get-SessionStateFile -OutputDir $out -Session "rlist"
        Remove-Item $script:argvLog -ErrorAction SilentlyContinue
    }

    It "Saves the list in the session state" {
        $s = Get-Content $stateFile -Raw | ConvertFrom-Json
        @($s.command_lines).Count | Should -Be 2
        $s.command_lines[0] | Should -BeLike "nmap -sT -Pn -p 22 *"
        $s.command_base_dir | Should -Not -BeNullOrEmpty
    }

    It "Runs the unfinished line with its own command, not the unit id as a host" {
        Set-UnitStatus -StateFile $stateFile -Label "line2" -Status "in_progress"

        Invoke-Scanyx -ResumeSession "rlist" -OutputDir $out -Resume -RetryDelay 1 -Yes *> $null

        $scanned = @(Get-ScannedLines)
        $scanned.Count | Should -Be 1
        $scanned[0] | Should -BeLike "-sT -Pn -p 80 127.0.0.1 -oA *two*"
        $scanned[0] | Should -Not -Match 'line2-'
        $s = Get-Content $stateFile -Raw | ConvertFrom-Json
        @($s.hosts.PSObject.Properties.Value | Where-Object { $_.status -eq "completed" }).Count | Should -Be 2
    }

    It "Works from another directory than the one the list ran from" {
        Set-UnitStatus -StateFile $stateFile -Label "line1" -Status "in_progress"
        $elsewhere = Join-Path $root "elsewhere"
        New-Item -ItemType Directory -Path $elsewhere -Force | Out-Null

        Push-Location $elsewhere
        try {
            Invoke-Scanyx -ResumeSession "rlist" -OutputDir $out -Resume -RetryDelay 1 -Yes *> $null
        } finally {
            Pop-Location
        }

        $scanned = @(Get-ScannedLines)
        $scanned.Count | Should -Be 1
        $scanned[0] | Should -BeLike "-sT -Pn -p 22 127.0.0.1 -oA *one*"
        @(Get-ChildItem $elsewhere).Count | Should -Be 0
    }

    It "Refuses an older session that has no saved list, and scans nothing" {
        $s = Get-Content $stateFile -Raw | ConvertFrom-Json
        $s.PSObject.Properties.Remove("command_lines")
        $s.PSObject.Properties.Remove("command_base_dir")
        $s | ConvertTo-Json -Depth 10 | Set-Content $stateFile
        Set-UnitStatus -StateFile $stateFile -Label "line1" -Status "pending"

        $said = Invoke-Scanyx -ResumeSession "rlist" -OutputDir $out -Resume -Yes 6>&1 | Out-String

        $said | Should -Match "predates saving that list"
        $said | Should -Match "-CommandFile"
        @(Get-ScannedLines).Count | Should -Be 0
    }
}
