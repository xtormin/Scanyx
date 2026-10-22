# Noninteractive.Tests.ps1
# Unit tests for keeping nmap off the terminal: --noninteractive

BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1'))
}

Describe "Test-NmapSupportsNoninteractive" -Tag "Unit", "Noninteractive" {
    It "Says no for an nmap that is not there" {
        Test-NmapSupportsNoninteractive -NmapPath "/nonexistent/nmap-$([guid]::NewGuid())" | Should -BeFalse
    }

    It "Agrees with the installed nmap on whether it knows the option" -Skip:(-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
        & nmap --noninteractive -V *> $null
        $expected = ($LASTEXITCODE -eq 0)
        Test-NmapSupportsNoninteractive -NmapPath (Get-Command nmap).Source | Should -Be $expected
    }
}

Describe "Start-NmapScanJob" -Tag "Unit", "Noninteractive" {
    BeforeEach {
        Mock Start-Job { [pscustomobject]@{ ArgumentList = $ArgumentList } }
    }

    It "Hands the job --noninteractive when asked" {
        $job = Start-NmapScanJob -TargetHost "10.0.0.1" -ScanCommand "nmap -sT" -OutputPath "/tmp" -FileName "tcp" -Attempts 1 -Unprivileged $false -Noninteractive $true
        $job.ArgumentList[9] | Should -BeTrue
    }

    It "Leaves it off unless asked" {
        $job = Start-NmapScanJob -TargetHost "10.0.0.1" -ScanCommand "nmap -sT" -OutputPath "/tmp" -FileName "tcp" -Attempts 1 -Unprivileged $false
        $job.ArgumentList[9] | Should -BeFalse
    }
}

Describe "Start-DueRetries" -Tag "Unit", "Noninteractive" {
    It "Passes --noninteractive on to the retry" {
        Mock Start-NmapScanJob { [pscustomobject]@{ State = "Running" } }
        $now = [datetime]"2026-10-07 12:00:00"
        $retryQueue = @{
            "10.0.0.1" = @{ NotBefore = $now.AddSeconds(-1); Attempts = 2; HostFolder = "/tmp"; FileName = "tcp"; ScanCommand = "nmap -sT"; ResultFile = "" }
        }

        $null = Start-DueRetries -RetryQueue $retryQueue -JobQueue @{} -JobStartTimes @{} -MaxConcurrent 5 -Noninteractive $true -Now $now

        Should -Invoke Start-NmapScanJob -Times 1 -Exactly -ParameterFilter { $Noninteractive }
    }
}

Describe "nmap keeps its hands off the terminal in every mode" -Tag "Unit", "Noninteractive" {
    # Scanyx reads Ctrl+C, s and p off the same terminal nmap opens for its own
    # runtime keys. If nmap is listening it eats them, and a -CommandFile run is
    # back to a Ctrl+C that does nothing - so --noninteractive goes on the line
    # in command-list mode too, verbatim or not.
    BeforeAll {
        $script:stubDir = [IO.Path]::Combine([IO.Path]::GetTempPath(), "scanyx-stub-$([guid]::NewGuid())")
        New-Item -ItemType Directory -Path $script:stubDir -Force | Out-Null
        $script:argvFile = [IO.Path]::Combine($script:stubDir, "argv.txt")
        $script:stub = [IO.Path]::Combine($script:stubDir, "fake-nmap")

        # A stand-in for nmap: records its argv, then writes whatever -oA asked
        # for so the scriptblock sees the output it checks for.
        Set-Content -LiteralPath $script:stub -Value @'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$SCANYX_TEST_ARGV"
prev=""
for a in "$@"; do
    if [ "$prev" = "-oA" ]; then printf 'stub\n' > "$a.nmap"; fi
    prev="$a"
done
exit 0
'@
        chmod +x $script:stub 2>$null
        if ($IsLinux -or $IsMacOS) { & /bin/chmod +x $script:stub }
        $env:SCANYX_TEST_ARGV = $script:argvFile
    }

    AfterAll {
        Remove-Item -LiteralPath $script:stubDir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item Env:SCANYX_TEST_ARGV -ErrorAction SilentlyContinue
    }

    BeforeEach {
        Remove-Item -LiteralPath $script:argvFile -Force -ErrorAction SilentlyContinue
    }

    It "Puts --noninteractive on a profile scan" -Skip:(-not ($IsLinux -or $IsMacOS)) {
        $out = [IO.Path]::Combine($script:stubDir, "profile")
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        $null = & $Global:NmapScanScriptBlock "10.0.0.1" "nmap -sT -p 80" $out "tcp" 1 $false $script:stub $false "" $true
        (Get-Content $script:argvFile) | Should -Contain "--noninteractive"
    }

    It "Puts --noninteractive on a verbatim command-list line too" -Skip:(-not ($IsLinux -or $IsMacOS)) {
        $out = [IO.Path]::Combine($script:stubDir, "verbatim")
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        $result = [IO.Path]::Combine($out, "line1.nmap")
        $null = & $Global:NmapScanScriptBlock "line1" "nmap -Pn -p 80 10.0.0.1 -oA $([IO.Path]::Combine($out, 'line1'))" $out "line1" 1 $false $script:stub $true $result $true
        (Get-Content $script:argvFile) | Should -Contain "--noninteractive"
    }

    It "Leaves the author's own flags and target alone while doing it" -Skip:(-not ($IsLinux -or $IsMacOS)) {
        $out = [IO.Path]::Combine($script:stubDir, "verbatim2")
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        $oa = [IO.Path]::Combine($out, "line2")
        $null = & $Global:NmapScanScriptBlock "line2" "nmap -Pn -p 443 --scan-delay 10ms 10.0.0.2 -oA $oa" $out "line2" 1 $false $script:stub $true "$oa.nmap" $true
        $argv = @(Get-Content $script:argvFile)
        $argv | Should -Contain "-Pn"
        $argv | Should -Contain "443"
        $argv | Should -Contain "--scan-delay"
        $argv | Should -Contain "10.0.0.2"
        # Verbatim means Scanyx adds no second -oA and no target of its own.
        @($argv | Where-Object { $_ -eq "-oA" }).Count | Should -Be 1
    }

    It "Adds it only once when the author already asked for it" -Skip:(-not ($IsLinux -or $IsMacOS)) {
        $out = [IO.Path]::Combine($script:stubDir, "dup")
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        $oa = [IO.Path]::Combine($out, "line3")
        $null = & $Global:NmapScanScriptBlock "line3" "nmap -Pn --noninteractive 10.0.0.3 -oA $oa" $out "line3" 1 $false $script:stub $true "$oa.nmap" $true
        @(Get-Content $script:argvFile | Where-Object { $_ -eq "--noninteractive" }).Count | Should -Be 1
    }

    It "Stays off the line when the installed nmap does not know it" -Skip:(-not ($IsLinux -or $IsMacOS)) {
        $out = [IO.Path]::Combine($script:stubDir, "old")
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        $null = & $Global:NmapScanScriptBlock "10.0.0.4" "nmap -sT -p 80" $out "tcp" 1 $false $script:stub $false "" $false
        (Get-Content $script:argvFile) | Should -Not -Contain "--noninteractive"
    }
}

Describe "Test-NmapOutputMatchesCommand and --noninteractive" -Tag "Unit", "Noninteractive" {
    # The resume compares the argv nmap recorded against the author's line.
    # --noninteractive is Scanyx's, not the author's, so it must not make a
    # finished unit look like a different one and get scanned all over again.
    BeforeAll {
        $script:nmapFile = [IO.Path]::Combine([IO.Path]::GetTempPath(), "scanyx-match-$([guid]::NewGuid()).nmap")
    }
    AfterEach {
        Remove-Item -LiteralPath $script:nmapFile -Force -ErrorAction SilentlyContinue
    }

    It "Matches a line that never asked for it against output that ran with it" {
        Set-Content -LiteralPath $script:nmapFile -Value '# Nmap 7.991 scan initiated as: /usr/bin/nmap -Pn -p 80 --noninteractive -oA /tmp/x 10.0.0.1'
        Test-NmapOutputMatchesCommand -ResultFile $script:nmapFile -Command "nmap -Pn -p 80 -oA /tmp/x 10.0.0.1" | Should -BeTrue
    }

    It "Still refuses a line that really is different" {
        Set-Content -LiteralPath $script:nmapFile -Value '# Nmap 7.991 scan initiated as: /usr/bin/nmap -Pn -p 80 --noninteractive -oA /tmp/x 10.0.0.1'
        Test-NmapOutputMatchesCommand -ResultFile $script:nmapFile -Command "nmap -Pn -p 443 -oA /tmp/x 10.0.0.1" | Should -BeFalse
    }

    It "Matches when the author asked for it themselves" {
        Set-Content -LiteralPath $script:nmapFile -Value '# Nmap 7.991 scan initiated as: /usr/bin/nmap --noninteractive -Pn -oA /tmp/x 10.0.0.1'
        Test-NmapOutputMatchesCommand -ResultFile $script:nmapFile -Command "nmap --noninteractive -Pn -oA /tmp/x 10.0.0.1" | Should -BeTrue
    }
}
