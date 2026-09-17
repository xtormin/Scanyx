# Presentation.Tests.ps1
# Unit tests for duration formatting and the pre-flight helpers

BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1'))
}

Describe "Format-Duration" -Tag "Unit", "Presentation" {
    It "Shows seconds below a minute (<sec>s)" -ForEach @(
        @{ sec = 1;  expected = "1s"  }
        @{ sec = 24; expected = "24s" }
        @{ sec = 59; expected = "59s" }
    ) {
        Format-Duration -TimeSpan ([TimeSpan]::FromSeconds($sec)) | Should -Be $expected
    }

    It "Never renders a sub-minute scan as 00:00" {
        # Regression: the HH:MM formatter made every scan under a minute read 00:00
        $result = Format-Duration -TimeSpan ([TimeSpan]::FromSeconds(24))
        $result | Should -Not -Be "00:00"
        $result | Should -Match '^\d+s$'
    }

    It "Shows minutes and seconds below an hour" {
        Format-Duration -TimeSpan ([TimeSpan]::FromSeconds(61))  | Should -Be "1m 01s"
        Format-Duration -TimeSpan ([TimeSpan]::FromSeconds(125)) | Should -Be "2m 05s"
    }

    It "Shows hours and minutes below a day" {
        Format-Duration -TimeSpan ([TimeSpan]::FromSeconds(3660)) | Should -Be "1h 01m"
    }

    It "Accumulates days instead of wrapping at 24h" {
        Format-Duration -TimeSpan ([TimeSpan]::FromSeconds(90000))  | Should -Be "1d 01h"
        Format-Duration -TimeSpan ([TimeSpan]::FromSeconds(172800)) | Should -Be "2d 00h"
    }

    It "Handles zero and negative spans without throwing" {
        Format-Duration -TimeSpan ([TimeSpan]::Zero) | Should -Be "0s"
        Format-Duration -TimeSpan ([TimeSpan]::FromSeconds(-5)) | Should -Be "0s"
    }
}

Describe "Get-SensitiveScanCommand" -Tag "Unit", "Presentation" {
    BeforeAll {
        $script:Base = 'nmap -v -T4 -Pn -open -sS --script=default,vuln -A --host-timeout 10m --top-ports 100'
    }

    It "Replaces the timing template" {
        $r = Get-SensitiveScanCommand -BaseCommand $script:Base -Timing "T2" -Scripts "default"
        $r | Should -Match '(^|\s)-T2(\s|$)'
        $r | Should -Not -Match '(^|\s)-T4(\s|$)'
    }

    It "Keeps the scripts unless asked to drop them" {
        $r = Get-SensitiveScanCommand -BaseCommand $script:Base -Timing "T2" -Scripts "default"
        $r | Should -Match '--script=default,vuln'
    }

    It "Drops the scripts with -SensitiveScripts none" {
        $r = Get-SensitiveScanCommand -BaseCommand $script:Base -Timing "T1" -Scripts "none"
        $r | Should -Not -Match '--script'
        $r | Should -Match '(^|\s)-T1(\s|$)'
        $r | Should -Not -Match '\s{2,}'
    }

    It "Leaves the rest of the command untouched" {
        $r = Get-SensitiveScanCommand -BaseCommand $script:Base -Timing "T2" -Scripts "default"
        $r | Should -Match '--top-ports 100'
        $r | Should -Match '--host-timeout 10m'
    }
}

Describe "Get-TargetBreakdown" -Tag "Unit", "Presentation" {
    It "Counts hosts per source network" {
        $data = @{
            '10.0.0.1' = @{ CIDRs = @('10.0.0.0/24'); Type = 'CIDR' }
            '10.0.0.2' = @{ CIDRs = @('10.0.0.0/24'); Type = 'CIDR' }
            '192.168.1.5' = @{ CIDRs = @(); Type = 'IP' }
        }
        $r = Get-TargetBreakdown -ValidHosts @('10.0.0.1','10.0.0.2','192.168.1.5') -TargetHostsData $data

        $r.Networks['10.0.0.0/24'] | Should -Be 2
        $r.Individual.Count | Should -Be 1
        $r.Individual | Should -Contain '192.168.1.5'
    }

    It "Reflects exclusions, because it counts the surviving hosts" {
        $data = @{
            '10.0.0.1' = @{ CIDRs = @('10.0.0.0/24') }
            '10.0.0.2' = @{ CIDRs = @('10.0.0.0/24') }
        }
        # 10.0.0.1 was excluded and is not in ValidHosts
        $r = Get-TargetBreakdown -ValidHosts @('10.0.0.2') -TargetHostsData $data
        $r.Networks['10.0.0.0/24'] | Should -Be 1
    }

    It "Handles an empty target list" {
        $r = Get-TargetBreakdown -ValidHosts @() -TargetHostsData @{}
        $r.Networks.Count | Should -Be 0
        $r.Individual.Count | Should -Be 0
    }

    It "Treats a host with unknown metadata as individual" {
        $r = Get-TargetBreakdown -ValidHosts @('1.2.3.4') -TargetHostsData @{}
        $r.Individual | Should -Contain '1.2.3.4'
    }
}

Describe "Format-CommandForDisplay" -Tag "Unit", "Presentation" {
    It "Leaves a short command on one line" {
        $r = @(Format-CommandForDisplay -Command 'nmap -sT -p 80')
        $r.Count | Should -Be 1
        $r[0] | Should -Be 'nmap -sT -p 80'
    }

    It "Wraps a long command and indents the continuation" {
        $long = 'nmap -v -T4 -Pn -open -sS --script=default,vuln -A --host-timeout 10m --top-ports 100 --unprivileged'
        $r = @(Format-CommandForDisplay -Command $long -Width 40 -Indent '    ')
        $r.Count | Should -BeGreaterThan 1
        $r[0] | Should -Not -Match '^\s'
        $r[1] | Should -Match '^    '
    }

    It "Loses no token when wrapping" {
        $long = 'nmap -v -T4 -Pn -open -sS --script=default,vuln -A --top-ports 100'
        $r = Format-CommandForDisplay -Command $long -Width 30 -Indent ''
        ($r -join ' ') | Should -Be $long
    }
}

Describe "Resolve-StopTime" -Tag "Unit", "Presentation" {
    BeforeAll {
        $script:Now = [datetime]"2026-09-17 21:15:00"
    }

    It "Returns no stop time when nothing was asked for" -ForEach @(
        @{ value = "" }
        @{ value = "   " }
    ) {
        $r = Resolve-StopTime -Value $value -Now $script:Now
        $r.Ok | Should -BeTrue
        $r.Time | Should -BeNullOrEmpty
    }

    It "Reads a clock time later today" {
        $r = Resolve-StopTime -Value "23:30" -Now $script:Now
        $r.Ok | Should -BeTrue
        $r.Time | Should -Be ([datetime]"2026-09-17 23:30:00")
    }

    It "Reads a clock time to the second" {
        (Resolve-StopTime -Value "23:30:45" -Now $script:Now).Time |
            Should -Be ([datetime]"2026-09-17 23:30:45")
    }

    It "Rolls an hour that already passed today over to tomorrow" -ForEach @(
        @{ value = "06:00" }
        @{ value = "6:00"  }
    ) {
        (Resolve-StopTime -Value $value -Now $script:Now).Time |
            Should -Be ([datetime]"2026-09-18 06:00:00")
    }

    It "Reads an explicit date and time" -ForEach @(
        @{ value = "2026-09-18 06:00"    }
        @{ value = "2026-09-18T06:00"    }
        @{ value = "2026-09-18 06:00:00" }
        @{ value = "18/09/2026 06:00"    }
    ) {
        (Resolve-StopTime -Value $value -Now $script:Now).Time |
            Should -Be ([datetime]"2026-09-18 06:00:00")
    }

    It "Reads a relative span" -ForEach @(
        @{ value = "+90m";  expected = "2026-09-17 22:45:00" }
        @{ value = "90m";   expected = "2026-09-17 22:45:00" }
        @{ value = "2h";    expected = "2026-09-17 23:15:00" }
        @{ value = "1h30m"; expected = "2026-09-17 22:45:00" }
        @{ value = "45s";   expected = "2026-09-17 21:15:45" }
        @{ value = "1d2h";  expected = "2026-09-18 23:15:00" }
    ) {
        (Resolve-StopTime -Value $value -Now $script:Now).Time | Should -Be ([datetime]$expected)
    }

    It "Reads the clock the same way under a non-English culture" {
        # Regression guard: a culture-dependent parse reads 2026-09-18 as day 09
        # of month 18 and either throws or lands on the wrong day.
        $previous = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::new("es-ES")
            (Resolve-StopTime -Value "2026-09-18 06:00" -Now $script:Now).Time |
                Should -Be ([datetime]"2026-09-18 06:00:00")
            (Resolve-StopTime -Value "23:30" -Now $script:Now).Time |
                Should -Be ([datetime]"2026-09-17 23:30:00")
        } finally {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $previous
        }
    }

    It "Rejects a date that has already gone by" {
        $r = Resolve-StopTime -Value "2020-01-01 10:00" -Now $script:Now
        $r.Ok | Should -BeFalse
        $r.Time | Should -BeNullOrEmpty
        $r.Error | Should -Match 'past'
    }

    It "Rejects a span of zero" {
        (Resolve-StopTime -Value "+0m" -Now $script:Now).Ok | Should -BeFalse
    }

    It "Rejects what it cannot read instead of guessing" -ForEach @(
        @{ value = "30"       }
        @{ value = "tomorrow" }
        @{ value = "25:00"    }
        @{ value = "later"    }
    ) {
        $r = Resolve-StopTime -Value $value -Now $script:Now
        $r.Ok | Should -BeFalse
        $r.Error | Should -Not -BeNullOrEmpty
    }
}

Describe "Get-TimeRemainingText" -Tag "Unit", "Presentation" {
    BeforeAll {
        $script:Now = [datetime]"2026-09-17 21:15:00"
    }

    It "Counts down in the same units as every other duration" {
        Get-TimeRemainingText -Target ([datetime]"2026-09-17 23:30:00") -Now $script:Now | Should -Be "2h 15m"
        Get-TimeRemainingText -Target ([datetime]"2026-09-17 21:16:30") -Now $script:Now | Should -Be "1m 30s"
        Get-TimeRemainingText -Target ([datetime]"2026-09-17 21:15:40") -Now $script:Now | Should -Be "40s"
    }

    It "Says the deadline is here rather than showing a negative span" {
        Get-TimeRemainingText -Target ([datetime]"2026-09-17 21:15:00") -Now $script:Now | Should -Be "due now"
        Get-TimeRemainingText -Target ([datetime]"2026-09-17 20:00:00") -Now $script:Now | Should -Be "due now"
    }
}

Describe "Get-DueStopWarnings" -Tag "Unit", "Presentation" {
    BeforeAll {
        $script:Stop = [datetime]"2026-09-18 06:00:00"
    }

    It "Says nothing while the stop is far away" {
        $r = @(Get-DueStopWarnings -StopTime $script:Stop -Fired @{} -Now ([datetime]"2026-09-18 05:00:00"))
        $r.Count | Should -Be 0
    }

    It "Announces a threshold as it comes due" {
        # 35 minutes left: not yet
        $r = @(Get-DueStopWarnings -StopTime $script:Stop -Fired @{} -Now ([datetime]"2026-09-18 05:25:00"))
        $r.Count | Should -Be 0
        # 29 minutes left: now
        $r = @(Get-DueStopWarnings -StopTime $script:Stop -Fired @{} -Now ([datetime]"2026-09-18 05:31:00"))
        $r | Should -Be @(30)
    }

    It "Says each threshold once" {
        $fired = @{ 30 = $true }
        $r = @(Get-DueStopWarnings -StopTime $script:Stop -Fired $fired -Now ([datetime]"2026-09-18 05:35:00"))
        $r.Count | Should -Be 0
        $r = @(Get-DueStopWarnings -StopTime $script:Stop -Fired $fired -Now ([datetime]"2026-09-18 05:55:00"))
        $r | Should -Be @(10)
    }

    It "Returns every threshold already behind it, so a late start warns once" {
        # Started with eight minutes of window left: 30 and 10 are both past.
        $r = @(Get-DueStopWarnings -StopTime $script:Stop -Fired @{} -Now ([datetime]"2026-09-18 05:52:00"))
        $r | Should -Be @(30, 10)
    }

    It "Stops warning once the deadline is here" {
        @(Get-DueStopWarnings -StopTime $script:Stop -Fired @{} -Now $script:Stop).Count | Should -Be 0
        @(Get-DueStopWarnings -StopTime $script:Stop -Fired @{} -Now ([datetime]"2026-09-18 06:30:00")).Count | Should -Be 0
    }

    It "Takes the thresholds it is given" {
        # 4 minutes left: 5 is due, 2 is not
        $r = @(Get-DueStopWarnings -StopTime $script:Stop -Fired @{} -Now ([datetime]"2026-09-18 05:56:00") -Thresholds @(5, 2))
        $r | Should -Be @(5)
    }
}

Describe "Write-ResumeFile" -Tag "Unit", "Presentation" {
    BeforeAll {
        $script:Dir = [IO.Path]::Combine([IO.Path]::GetTempPath(), "scanyx-resume-$([guid]::NewGuid().ToString('N'))")
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }

    AfterAll {
        if (Test-Path $script:Dir) { Remove-Item $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It "Writes the command where the session lives" {
        $path = Write-ResumeFile -SessionDir $script:Dir -ResumeCommand './scanyx.sh -ResumeSession "s1" -Resume' -SessionId "s1"
        $path | Should -Be ([IO.Path]::Combine($script:Dir, "resume.txt"))
        $content = Get-Content $path -Raw
        $expected = [regex]::Escape('./scanyx.sh -ResumeSession "s1" -Resume')
        $content | Should -Match $expected
        $content | Should -Match 'Session : s1'
        $content | Should -Match 'Status  : in_progress'
    }

    It "Records the outcome of the run that wrote it" {
        $path = Write-ResumeFile -SessionDir $script:Dir -ResumeCommand './scanyx.sh -Resume' -SessionId "s1" -Status "stopped"
        Get-Content $path -Raw | Should -Match 'Status  : stopped'
    }

    It "Rewrites rather than appends, so the file is never a pile of old lines" {
        Write-ResumeFile -SessionDir $script:Dir -ResumeCommand './scanyx.sh -A' -SessionId "s1" | Out-Null
        $path = Write-ResumeFile -SessionDir $script:Dir -ResumeCommand './scanyx.sh -B' -SessionId "s1"
        $content = Get-Content $path -Raw
        $content | Should -Match '\-B'
        $content | Should -Not -Match '\-A'
    }

    It "Does nothing without somewhere to write or something to write" {
        Write-ResumeFile -SessionDir "" -ResumeCommand "x" -SessionId "s1" | Should -Be ""
        Write-ResumeFile -SessionDir $script:Dir -ResumeCommand "" -SessionId "s1" | Should -Be ""
    }
}

Describe "Get-ResumeCommand" -Tag "Unit", "Presentation" {
    It "Names the session and the directory it lives in" {
        $r = Get-ResumeCommand -SessionId "engagement-01" -OutputDir "/tmp/scans"
        $r | Should -Match '-ResumeSession "engagement-01"'
        $r | Should -Match '-OutputDir "/tmp/scans"'
        $r | Should -Match '-Resume$'
    }

    It "Leaves the directory out when there is none to name" {
        Get-ResumeCommand -SessionId "engagement-01" | Should -Not -Match '-OutputDir'
    }

    It "Quotes a directory with spaces so the line can be pasted as is" {
        Get-ResumeCommand -SessionId "s1" -OutputDir "/tmp/my scans" | Should -Match '-OutputDir "/tmp/my scans"'
    }

    It "Keeps sudo on a run that needed root, and only there" {
        $elevated = Get-ResumeCommand -SessionId "s1" -OutputDir "/tmp/scans" -Elevated $true
        $plain    = Get-ResumeCommand -SessionId "s1" -OutputDir "/tmp/scans" -Elevated $false
        $plain | Should -Not -Match '^sudo '
        if ($IsLinux -or $IsMacOS) {
            $elevated | Should -Match '^sudo \./scanyx\.sh'
        } else {
            $elevated | Should -Not -Match '^sudo '
        }
    }
}

Describe "Parameter name collisions" -Tag "Unit", "Presentation" {
    # PowerShell variable names are case-insensitive, so a local accumulator
    # sharing a parameter's name silently destroys what the caller passed.
    # -SensitiveHosts was dead for exactly this reason.
    It "Does not re-initialise any Invoke-Scanyx parameter in the function body" {
        $scriptPath = [IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1')
        $paramNames = (Get-Command Invoke-Scanyx).Parameters.Keys

        # Names the body legitimately reassigns (wizard hand-off, resume, path
        # normalisation, privilege downgrade, overwrite decisions).
        $allowed = @('ScanType','Workflow','HostFile','Hosts','SessionName','ExcludeFile',
                     'ExcludeHosts','ResolveHostnames','SensitiveFile','SensitiveTiming',
                     'SensitiveScripts','OutputDir','MaxConcurrent','MaxRetries','RetryDelay',
                     'OverwriteMode','VerboseMode','Unprivileged','ConfigFile')

        $offenders = @()
        foreach ($name in $paramNames) {
            if ($allowed -contains $name) { continue }
            $hits = Select-String -Path $scriptPath -Pattern ("^\s*\`$" + $name + "\s*=\s*@\(\)") -AllMatches
            foreach ($hit in $hits) { $offenders += "$name at line $($hit.LineNumber)" }
        }

        $offenders | Should -BeNullOrEmpty
    }
}
