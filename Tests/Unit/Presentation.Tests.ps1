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
