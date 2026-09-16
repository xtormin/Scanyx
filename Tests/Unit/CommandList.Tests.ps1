# CommandList.Tests.ps1
# Unit tests for command-list mode: parsing, identity, validation, paths

BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1'))
    $script:Base = '/tmp/engagement'
}

Describe "Split-NmapCommandLine" -Tag "Unit", "CommandList" {
    It "Keeps a comma-separated port list as one token" {
        $t = Split-NmapCommandLine -Command 'nmap -p 22,80,443 10.0.0.1'
        $t | Should -Contain '22,80,443'
    }

    It "Handles mixed TCP/UDP port syntax" {
        $t = @(Split-NmapCommandLine -Command 'nmap -sS -sU -p T:22,23,U:161 10.0.0.1')
        $t | Should -Contain 'T:22,23,U:161'
        $t.Count | Should -Be 6
    }

    It "Returns nothing for an empty command" {
        @(Split-NmapCommandLine -Command '').Count | Should -Be 0
    }
}

Describe "Get-CommandUnitId" -Tag "Unit", "CommandList" {
    It "Is stable for the same command" {
        $a = Get-CommandUnitId -Command 'nmap -sV 10.0.0.1' -Label 'DC01'
        $b = Get-CommandUnitId -Command 'nmap -sV 10.0.0.1' -Label 'DC01'
        $a | Should -Be $b
    }

    It "Ignores differences in whitespace only" {
        $a = Get-CommandUnitId -Command 'nmap -sV 10.0.0.1' -Label 'x'
        $b = Get-CommandUnitId -Command '  nmap   -sV    10.0.0.1  ' -Label 'x'
        $a | Should -Be $b
    }

    It "Changes when the command changes" {
        $a = Get-CommandUnitId -Command 'nmap -p 80 10.0.0.1' -Label 'x'
        $b = Get-CommandUnitId -Command 'nmap -p 80,443 10.0.0.1' -Label 'x'
        $a | Should -Not -Be $b
    }

    It "Produces an id usable as a folder name and a JSON property" {
        $id = Get-CommandUnitId -Command 'nmap -sV 10.0.0.1' -Label 'DC 01 / primary'
        $id | Should -Match '^[A-Za-z0-9._-]+$'
        $id | Should -Not -Match '[/\\ ]'
    }

    It "Falls back to the bare hash when there is no usable label" {
        $id = Get-CommandUnitId -Command 'nmap -sV 10.0.0.1' -Label '///'
        $id | Should -Match '^[0-9a-f]{8}$'
    }
}

Describe "ConvertFrom-NmapCommandLine" -Tag "Unit", "CommandList" {
    It "Parses a typical consultant line" {
        $u = ConvertFrom-NmapCommandLine -Line 'nmap -sV -T3 -oA nmap/10.30.0.10 -p 53,88,445 10.30.0.10' -LineNumber 1 -BaseDirectory $script:Base
        $u.Errors.Count | Should -Be 0
        $u.Target | Should -Be '10.30.0.10'
        $u.OutputFlag | Should -Be '-oA'
        $u.Label | Should -Be '10.30.0.10'
    }

    It "Uses a trailing comment as the label" {
        $u = ConvertFrom-NmapCommandLine -Line 'nmap -sV -oA nmap/a 10.0.0.1   # DC01' -BaseDirectory $script:Base
        $u.Label | Should -Be 'DC01'
        $u.Command | Should -Not -Match '#'
    }

    It "Resolves a relative output path against the base directory" {
        $u = ConvertFrom-NmapCommandLine -Line 'nmap -sV -oA nmap/a 10.0.0.1' -BaseDirectory $script:Base
        $u.OutputBase | Should -Be ([IO.Path]::GetFullPath([IO.Path]::Combine($script:Base, 'nmap/a')))
        $u.ResultFile | Should -Be "$($u.OutputBase).nmap"
    }

    It "Leaves an absolute output path alone" {
        $abs = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'out')
        $u = ConvertFrom-NmapCommandLine -Line "nmap -sV -oA $abs 10.0.0.1" -BaseDirectory $script:Base
        $u.OutputBase | Should -Be ([IO.Path]::GetFullPath($abs))
    }

    It "Pins the output path in the executed command but not in the displayed one" {
        $u = ConvertFrom-NmapCommandLine -Line 'nmap -sV -oA nmap/a 10.0.0.1' -BaseDirectory $script:Base
        $u.Command | Should -Match 'nmap/a'
        $u.ExecCommand | Should -Match ([regex]::Escape($u.OutputBase))
        $u.ExecCommand | Should -Not -Be $u.Command
    }

    It "Executes verbatim when the line has no output flag" {
        $u = ConvertFrom-NmapCommandLine -Line 'nmap -sV 10.0.0.1' -BaseDirectory $script:Base
        $u.ExecCommand | Should -Be $u.Command
        $u.OutputBase | Should -BeNullOrEmpty
    }

    It "Rejects a line that does not start with nmap" {
        $u = ConvertFrom-NmapCommandLine -Line 'masscan -p80 10.0.0.1' -BaseDirectory $script:Base
        $u.Errors.Count | Should -BeGreaterThan 0
        $u.Errors[0] | Should -Match 'must start with nmap'
    }

    It "Accepts nmap given by path" {
        $u = ConvertFrom-NmapCommandLine -Line '/usr/bin/nmap -sV 10.0.0.1' -BaseDirectory $script:Base
        $u.Errors.Count | Should -Be 0
    }

    It "Rejects shell metacharacters (<meta>)" -ForEach @(
        @{ meta = 'nmap -sV 10.0.0.1; rm -rf /' }
        @{ meta = 'nmap -sV 10.0.0.1 && whoami' }
        @{ meta = 'nmap -sV 10.0.0.1 | tee out' }
        @{ meta = 'nmap -sV $(whoami)' }
        @{ meta = 'nmap -sV 10.0.0.1 > out.txt' }
    ) {
        $u = ConvertFrom-NmapCommandLine -Line $meta -BaseDirectory $script:Base
        $u.Errors.Count | Should -BeGreaterThan 0
        $u.Errors[0] | Should -Match 'Shell metacharacters'
    }

    It "Rejects -oA combined with another output flag, as nmap itself does" {
        $u = ConvertFrom-NmapCommandLine -Line 'nmap -oA nmap/a -oN nmap/a.txt 10.0.0.1' -BaseDirectory $script:Base
        $u.Errors.Count | Should -BeGreaterThan 0
        $u.Errors[0] | Should -Match 'rejects -oA'
    }

    It "Warns that grepable-only output weakens open-port detection" {
        $u = ConvertFrom-NmapCommandLine -Line 'nmap -sV -oG nmap/a 10.0.0.1' -BaseDirectory $script:Base
        ($u.Warnings -join ' ') | Should -Match 'Grepable'
    }

    It "Warns when the last token is a flag value rather than a target" {
        $u = ConvertFrom-NmapCommandLine -Line 'nmap -sV -oA nmap/a -p 80' -BaseDirectory $script:Base
        $u.Target | Should -Be ''
        ($u.Warnings -join ' ') | Should -Match 'Could not identify the target'
    }

    It "Warns that -iL covers more than one host" {
        $u = ConvertFrom-NmapCommandLine -Line 'nmap -sV -oA nmap/a -iL targets.txt' -BaseDirectory $script:Base
        ($u.Warnings -join ' ') | Should -Match '-iL'
    }
}

Describe "Read-CommandList" -Tag "Unit", "CommandList" {
    It "Skips blank lines and whole-line comments" {
        $r = Read-CommandList -Lines @('', '# nota', 'nmap -sV -oA a 10.0.0.1', '   ') -BaseDirectory $script:Base
        $r.Units.Count | Should -Be 1
        $r.Rejected.Count | Should -Be 0
    }

    It "Separates rejected lines from usable ones" {
        $r = Read-CommandList -Lines @('nmap -sV -oA a 10.0.0.1', 'masscan -p80 10.0.0.2') -BaseDirectory $script:Base
        $r.Units.Count | Should -Be 1
        $r.Rejected.Count | Should -Be 1
    }

    It "Flags two lines writing to the same output path" {
        $r = Read-CommandList -Lines @(
            'nmap -sV -oA nmap/same 10.0.0.1',
            'nmap -sV -oA nmap/same 10.0.0.2'
        ) -BaseDirectory $script:Base
        ($r.Units[1].Warnings -join ' ') | Should -Match 'same output path'
    }

    It "Flags a duplicated line" {
        $r = Read-CommandList -Lines @(
            'nmap -sV -oA nmap/a 10.0.0.1',
            'nmap -sV -oA nmap/a 10.0.0.1'
        ) -BaseDirectory $script:Base
        ($r.Units[1].Warnings -join ' ') | Should -Match 'Duplicate'
    }

    It "Keeps ids stable when the list is reordered" {
        $one = Read-CommandList -Lines @('nmap -sV -oA a 10.0.0.1', 'nmap -sV -oA b 10.0.0.2') -BaseDirectory $script:Base
        $two = Read-CommandList -Lines @('nmap -sV -oA b 10.0.0.2', 'nmap -sV -oA a 10.0.0.1') -BaseDirectory $script:Base
        $idsOne = ($one.Units | ForEach-Object { $_.Id } | Sort-Object) -join ','
        $idsTwo = ($two.Units | ForEach-Object { $_.Id } | Sort-Object) -join ','
        $idsOne | Should -Be $idsTwo
    }

    It "Records the line number of each unit" {
        $r = Read-CommandList -Lines @('# nota', 'nmap -sV -oA a 10.0.0.1') -BaseDirectory $script:Base
        $r.Units[0].LineNumber | Should -Be 2
    }
}

Describe "Test-NmapOutputMatchesCommand" -Tag "Unit", "CommandList" {
    BeforeAll {
        $script:TmpDir = [IO.Path]::Combine([IO.Path]::GetTempPath(), "scanyx-cmd-$(Get-Random)")
        New-Item -Path $script:TmpDir -ItemType Directory -Force | Out-Null
        $script:Out = [IO.Path]::Combine($script:TmpDir, 'r.nmap')
        # First line of real nmap output records the argv it ran with
        Set-Content -Path $script:Out -Value @(
            '# Nmap 7.991 scan initiated Wed Sep 16 2026 as: /opt/homebrew/bin/nmap -sT -T4 -oA /tmp/out -p 53 127.0.0.1',
            'Nmap scan report for localhost (127.0.0.1)',
            '53/tcp open domain'
        )
    }
    AfterAll {
        if (Test-Path $script:TmpDir) { Remove-Item $script:TmpDir -Recurse -Force }
    }

    It "Matches the same command regardless of how nmap itself was resolved" {
        Test-NmapOutputMatchesCommand -ResultFile $script:Out -Command 'nmap -sT -T4 -oA /tmp/out -p 53 127.0.0.1' | Should -BeTrue
    }

    It "Does not match an edited command that writes to the same path" {
        # This is what makes an edited line re-run instead of being skipped
        Test-NmapOutputMatchesCommand -ResultFile $script:Out -Command 'nmap -sT -T4 -oA /tmp/out -p 53,80 127.0.0.1' | Should -BeFalse
    }

    It "Returns false for a missing or empty path" {
        Test-NmapOutputMatchesCommand -ResultFile '' -Command 'nmap -sV 10.0.0.1' | Should -BeFalse
        Test-NmapOutputMatchesCommand -ResultFile '/no/such/file.nmap' -Command 'nmap -sV 10.0.0.1' | Should -BeFalse
    }
}

Describe "Privilege gate over command lines" -Tag "Unit", "CommandList" {
    It "Sees the root-only flags in a consultant's line" {
        $u = ConvertFrom-NmapCommandLine -Line 'nmap -sV -T3 -oA nmap/a -sS -sU -p T:22,U:161 10.10.10.5' -BaseDirectory $script:Base
        $flags = Get-RootRequiredFlags -Command $u.Command
        $flags.Blocking | Should -Contain '-sU'
        $flags.Degradable | Should -Contain '-sS'
    }

    It "Refuses to downgrade a UDP line, because nmap cannot" {
        $u = ConvertFrom-NmapCommandLine -Line 'nmap -sU -oA nmap/a 10.0.0.1' -BaseDirectory $script:Base
        ConvertTo-UnprivilegedCommand -Command $u.Command | Should -BeNullOrEmpty
    }

    It "Downgrades a TCP SYN line and changes its identity" {
        $u = ConvertFrom-NmapCommandLine -Line 'nmap -sS -oA nmap/a 10.0.0.1' -BaseDirectory $script:Base
        $converted = ConvertTo-UnprivilegedCommand -Command $u.Command
        $converted | Should -Match '-sT'
        # A downgraded scan is a different scan and must not inherit results
        (Get-CommandUnitId -Command $converted -Label $u.Label) | Should -Not -Be $u.Id
    }
}

Describe "Open-port detection across output formats" -Tag "Unit", "CommandList" {
    BeforeAll {
        $script:FmtDir = [IO.Path]::Combine([IO.Path]::GetTempPath(), "scanyx-fmt-$(Get-Random)")
        New-Item -Path $script:FmtDir -ItemType Directory -Force | Out-Null
        $script:Gnmap = [IO.Path]::Combine($script:FmtDir, 'g.gnmap')
        Set-Content -Path $script:Gnmap -Value @(
            '# Nmap 7.991 scan initiated Wed Sep 16 2026 as: nmap -oG g.gnmap 127.0.0.1',
            "Host: 127.0.0.1 (localhost)`tPorts: 53/open/tcp//domain///, 8080/open/tcp//http-proxy///",
            '# Nmap done'
        )
        $script:GnmapClosed = [IO.Path]::Combine($script:FmtDir, 'c.gnmap')
        Set-Content -Path $script:GnmapClosed -Value @(
            '# Nmap 7.991 scan initiated Wed Sep 16 2026 as: nmap -oG c.gnmap 127.0.0.1',
            "Host: 127.0.0.1 (localhost)`tPorts: 53/closed/tcp//domain///",
            '# Nmap done'
        )
    }
    AfterAll {
        if (Test-Path $script:FmtDir) { Remove-Item $script:FmtDir -Recurse -Force }
    }

    It "Finds open ports in grepable output" {
        # Regression: the plain-text pattern never matched "53/open/tcp",
        # so a -oG-only line counted every host as dead
        Test-HostHasOpenPorts -XmlFile $script:Gnmap | Should -BeTrue
    }

    It "Reports no open ports when grepable output has none" {
        Test-HostHasOpenPorts -XmlFile $script:GnmapClosed | Should -BeFalse
    }
}
