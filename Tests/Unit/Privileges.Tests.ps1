# Privileges.Tests.ps1
# Unit tests for the Linux/macOS privilege gate (root-only nmap flags)

BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1'))

    # The six stock profiles, taken verbatim from nmap-profiles-workflows.json
    $script:StockProfiles = @{
        'tcp-100'    = 'nmap -v -T4 -Pn -open -sS --script=default,vuln -A --host-timeout 10m --top-ports 100'
        'tcp-1000'   = 'nmap -v -T4 -Pn -open -sS --script=default,vuln -A --host-timeout 60m --top-ports 1000'
        'tcp-full'   = 'nmap -v -T4 -Pn -open -sS --script=default,vuln -A --host-timeout 60m -p-'
        'udp-common' = "nmap -v -T4 -Pn -sU -sV -A --host-timeout 60m -p '53,67,69,11,123,137,161,500,514,520,563'"
        'udp-1000'   = 'nmap -v -T4 -Pn -sU -sV -A --host-timeout 60m'
        'udp-full'   = 'nmap -v -T4 -Pn -sU -sV -A --host-timeout 60m -p-'
    }
}

Describe "Get-RootRequiredFlags" -Tag "Unit", "Privileges" {
    Context "Stock TCP profiles" {
        It "Flags -sS and -A as degradable in <name>" -ForEach @(
            @{ name = 'tcp-100' }, @{ name = 'tcp-1000' }, @{ name = 'tcp-full' }
        ) {
            $flags = Get-RootRequiredFlags -Command $script:StockProfiles[$name]
            $flags.Degradable | Should -Contain '-sS'
            $flags.Degradable | Should -Contain '-A'
            $flags.Blocking | Should -BeNullOrEmpty
        }
    }

    Context "Stock UDP profiles" {
        It "Flags -sU as blocking in <name>" -ForEach @(
            @{ name = 'udp-common' }, @{ name = 'udp-1000' }, @{ name = 'udp-full' }
        ) {
            $flags = Get-RootRequiredFlags -Command $script:StockProfiles[$name]
            $flags.Blocking | Should -Contain '-sU'
        }
    }

    Context "Commands that need no privileges" {
        It "Returns nothing for a plain connect scan" {
            $flags = Get-RootRequiredFlags -Command 'nmap -v -T4 -Pn -sT -sV --top-ports 100'
            $flags.Degradable | Should -BeNullOrEmpty
            $flags.Blocking | Should -BeNullOrEmpty
        }

        It "Handles an empty command" {
            $flags = Get-RootRequiredFlags -Command ''
            $flags.Degradable | Should -BeNullOrEmpty
            $flags.Blocking | Should -BeNullOrEmpty
        }
    }

    Context "Token boundaries" {
        It "Does not match -sU inside an unrelated value" {
            $flags = Get-RootRequiredFlags -Command 'nmap -sT --script=http-sUspicious -oA out'
            $flags.Blocking | Should -BeNullOrEmpty
        }

        It "Matches a flag written with =" {
            $flags = Get-RootRequiredFlags -Command 'nmap -sT --spoof-mac=0 -p 80'
            $flags.Degradable | Should -Contain '--spoof-mac'
        }
    }
}

Describe "ConvertTo-UnprivilegedCommand" -Tag "Unit", "Privileges" {
    Context "Degrading TCP profiles" {
        It "Converts <name> to a runnable unprivileged command" -ForEach @(
            @{ name = 'tcp-100' }, @{ name = 'tcp-1000' }, @{ name = 'tcp-full' }
        ) {
            $result = ConvertTo-UnprivilegedCommand -Command $script:StockProfiles[$name]

            $result | Should -Not -BeNullOrEmpty
            $result | Should -Match '(^|\s)-sT(\s|$)'
            $result | Should -Match '--unprivileged'
            # -sS, -A and the root-only detections it implies must all be gone
            $result | Should -Not -Match '(^|\s)-sS(\s|$)'
            $result | Should -Not -Match '(^|\s)-A(\s|$)'
            $result | Should -Not -Match '(^|\s)-O(\s|$)'
            $result | Should -Not -Match '--traceroute'
            # -A is replaced by its unprivileged parts, not simply dropped
            $result | Should -Match '(^|\s)-sV(\s|$)'
            $result | Should -Match '(^|\s)-sC(\s|$)'
        }

        It "Leaves the rest of the command untouched" {
            $result = ConvertTo-UnprivilegedCommand -Command $script:StockProfiles['tcp-1000']
            $result | Should -Match '--top-ports 1000'
            $result | Should -Match '--host-timeout 60m'
            $result | Should -Match '--script=default,vuln'
        }

        It "Produces a command the gate will accept as privilege-free" {
            $result = ConvertTo-UnprivilegedCommand -Command $script:StockProfiles['tcp-full']
            $flags = Get-RootRequiredFlags -Command $result
            $flags.Degradable | Should -BeNullOrEmpty
            $flags.Blocking | Should -BeNullOrEmpty
        }

        It "Is idempotent" {
            $once  = ConvertTo-UnprivilegedCommand -Command $script:StockProfiles['tcp-100']
            $twice = ConvertTo-UnprivilegedCommand -Command $once
            $twice | Should -Be $once
        }
    }

    Context "UDP profiles cannot be degraded" {
        It "Returns null for <name>" -ForEach @(
            @{ name = 'udp-common' }, @{ name = 'udp-1000' }, @{ name = 'udp-full' }
        ) {
            ConvertTo-UnprivilegedCommand -Command $script:StockProfiles[$name] | Should -BeNullOrEmpty
        }
    }
}

Describe "Test-IsElevated" -Tag "Unit", "Privileges" {
    It "Returns a boolean without throwing" {
        $result = Test-IsElevated
        $result | Should -BeOfType [bool]
    }

    It "Agrees with id -u on Unix" -Skip:(-not ($IsLinux -or $IsMacOS)) {
        Test-IsElevated | Should -Be ((& id -u) -eq '0')
    }
}
