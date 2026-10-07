# Memory.Tests.ps1
# Unit tests for the pre-flight memory check: how much a concurrent scan costs
# and whether -MaxConcurrent fits in what the machine has free

BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1'))
}

Describe "ConvertFrom-Meminfo" -Tag "Unit", "Memory" {
    It "Reads MemAvailable, not MemFree" {
        $lines = @(
            "MemTotal:        2014864 kB"
            "MemFree:          102400 kB"
            "MemAvailable:     819200 kB"
            "Buffers:           20480 kB"
        )
        ConvertFrom-Meminfo -Lines $lines | Should -Be 800
    }

    It "Gives 0 for a kernel without MemAvailable" {
        ConvertFrom-Meminfo -Lines @("MemTotal: 2014864 kB", "MemFree: 102400 kB") | Should -Be 0
    }
}

Describe "ConvertFrom-VmStat" -Tag "Unit", "Memory" {
    It "Adds free, inactive and speculative pages at the reported page size" {
        $lines = @(
            "Mach Virtual Memory Statistics: (page size of 16384 bytes)"
            "Pages free:                                     4096."
            "Pages active:                                 291272."
            "Pages inactive:                                 8192."
            "Pages speculative:                              4096."
            "Pages wired down:                             237710."
        )
        # (4096 + 8192 + 4096) pages * 16 KB = 256 MB
        ConvertFrom-VmStat -Lines $lines | Should -Be 256
    }

    It "Gives 0 when the output is not vm_stat's" {
        ConvertFrom-VmStat -Lines @("something else") | Should -Be 0
    }
}

Describe "Get-ScanSlotMemoryMB" -Tag "Unit", "Memory" {
    It "Costs more when nmap runs NSE scripts" {
        $plain = Get-ScanSlotMemoryMB -Command "nmap -sT -Pn -p 22"
        $plain | Should -Be 190
        Get-ScanSlotMemoryMB -Command "nmap -v -T4 -Pn -sS --script=default,vuln -sV --top-ports 100" | Should -Be 340
        Get-ScanSlotMemoryMB -Command "nmap -sC -p 80" | Should -Be 340
        Get-ScanSlotMemoryMB -Command "nmap -A -p 80" | Should -Be 340
    }

    It "Sees -sC inside combined scan types" {
        Get-ScanSlotMemoryMB -Command "nmap -sCV -p 80" | Should -Be 340
        Get-ScanSlotMemoryMB -Command "nmap -sVC -p 80" | Should -Be 340
    }

    It "Does not mistake an option that merely starts like one for scripts" {
        Get-ScanSlotMemoryMB -Command "nmap --script-trace -p 80" | Should -Be 190
        Get-ScanSlotMemoryMB -Command "nmap -sV -sS -p 80" | Should -Be 190
    }
}

Describe "Test-ConcurrencyFitsMemory" -Tag "Unit", "Memory" {
    It "Fits when the scans take less than 80% of what is available" {
        $r = Test-ConcurrencyFitsMemory -Concurrency 5 -Commands @("nmap -sT -p 22") -AvailableMB 4000
        $r.Fits | Should -BeTrue
        $r.NeededMB | Should -Be 950
    }

    It "Warns, and says how many would fit, when they do not" {
        # 10 x 340 MB = 3400 MB against a 1600 MB budget (80% of 2000)
        $r = Test-ConcurrencyFitsMemory -Concurrency 10 -Commands @("nmap --script=vuln -p 80") -AvailableMB 2000
        $r.Fits | Should -BeFalse
        $r.NeededMB | Should -Be 3400
        $r.SuggestedMax | Should -Be 4
    }

    It "Sizes the slot by the heaviest command in the run" {
        $r = Test-ConcurrencyFitsMemory -Concurrency 2 -Commands @("nmap -sT -p 22", "nmap -A -p 80") -AvailableMB 4000
        $r.PerSlotMB | Should -Be 340
    }

    It "Never suggests fewer than one scan" {
        (Test-ConcurrencyFitsMemory -Concurrency 5 -Commands @("nmap -A") -AvailableMB 100).SuggestedMax | Should -Be 1
    }

    It "Stays quiet when the free memory could not be read" {
        (Test-ConcurrencyFitsMemory -Concurrency 500 -Commands @("nmap -A") -AvailableMB 0).Fits | Should -BeTrue
    }
}
