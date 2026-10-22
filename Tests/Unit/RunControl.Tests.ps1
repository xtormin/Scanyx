# RunControl.Tests.ps1
# Unit tests for stopping a run: Ctrl+C and the s/p keys read as keystrokes,
# SIGTERM and SIGHUP arriving as a stop file, and the exit code each leaves.
#
# Pester runs with its output redirected, so there is no console to read keys
# from and Enable-RunControl declines the capture on purpose. That is the case
# worth pinning down here: the polling must stay a cheap no-op and must never
# throw, because it is called on every turn of the scan loop. The stop file is
# the one channel that needs no terminal, so that part is exercised for real.

BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1'))

    function New-StopFilePath {
        [IO.Path]::Combine([IO.Path]::GetTempPath(), "scanyx-stop-test-$([guid]::NewGuid()).request")
    }
}

Describe "Enable-RunControl" -Tag "Unit", "RunControl" {
    AfterEach {
        Restore-RunControl
    }

    It "Declines the capture when there is no console to read a keystroke from" -Skip:(-not [Console]::IsInputRedirected) {
        Enable-RunControl | Should -BeFalse
    }

    It "Leaves the terminal untouched when it declines" -Skip:(-not [Console]::IsInputRedirected) {
        $null = Enable-RunControl
        $script:interruptCapture | Should -BeNullOrEmpty
    }

    It "Starts each run with a clean slate" {
        $script:interruptRequested = $true
        $script:interruptCount = 7
        $script:drainRequested = $true
        $script:pauseRequested = $true
        $global:ScanyxExitCode = 143

        $null = Enable-RunControl

        $script:interruptRequested | Should -BeFalse
        $script:interruptCount | Should -Be 0
        $script:drainRequested | Should -BeFalse
        $script:pauseRequested | Should -BeFalse
        $global:ScanyxExitCode | Should -Be 0
    }

    It "Clears a stop file left behind by the run that was stopped" {
        # Otherwise a resume would stop before it scanned anything.
        $stale = New-StopFilePath
        Set-Content -LiteralPath $stale -Value "SIGTERM"
        try {
            $null = Enable-RunControl -StopFile $stale
            Test-Path -LiteralPath $stale | Should -BeFalse
            Test-InterruptRequested | Should -BeFalse
        } finally {
            Remove-Item -LiteralPath $stale -Force -ErrorAction SilentlyContinue
        }
    }

    It "Ignores an empty stop file path" {
        { $null = Enable-RunControl -StopFile @($null, "") } | Should -Not -Throw
        $script:stopFiles | Should -BeNullOrEmpty
    }
}

Describe "Test-InterruptRequested" -Tag "Unit", "RunControl" {
    AfterEach {
        Restore-RunControl
        $null = Enable-RunControl
    }

    It "Says no, and does not throw, when nothing was asked for" {
        $null = Enable-RunControl
        { Test-InterruptRequested } | Should -Not -Throw
        Test-InterruptRequested | Should -BeFalse
    }

    It "Keeps saying yes once the stop has been asked for" {
        $null = Enable-RunControl
        Request-ScanStop -Reason "Ctrl+C" -ExitCode 130 6> $null
        # The loops poll this many times over; the answer cannot wear off.
        Test-InterruptRequested | Should -BeTrue
        Test-InterruptRequested | Should -BeTrue
    }

    It "Stops when a stop file appears, with no console involved" {
        $path = New-StopFilePath
        try {
            $null = Enable-RunControl -StopFile $path
            Test-InterruptRequested | Should -BeFalse

            Set-Content -LiteralPath $path -Value "SIGTERM"
            Test-InterruptRequested 6> $null | Should -BeTrue
            $script:interruptReason | Should -Be "SIGTERM"
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    It "Reads the reason off the file, and falls back when it is empty" {
        $path = New-StopFilePath
        try {
            $null = Enable-RunControl -StopFile $path
            New-Item -ItemType File -Path $path -Force | Out-Null
            Test-InterruptRequested 6> $null | Should -BeTrue
            $script:interruptReason | Should -Be "a stop request"
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe "Exit codes" -Tag "Unit", "RunControl" {
    AfterEach {
        Restore-RunControl
        $null = Enable-RunControl
    }

    It "Gives Ctrl+C 130" {
        $null = Enable-RunControl
        Request-ScanStop -Reason "Ctrl+C" -ExitCode 130 6> $null
        $script:exitCode | Should -Be 130
    }

    It "Gives SIGTERM 143 and SIGHUP 129, the way a shell reports them" {
        foreach ($case in @(@{ Signal = "SIGTERM"; Code = 143 }, @{ Signal = "SIGHUP"; Code = 129 })) {
            $path = New-StopFilePath
            try {
                $null = Enable-RunControl -StopFile $path
                Set-Content -LiteralPath $path -Value $case.Signal
                $null = Test-InterruptRequested 6> $null
                $script:exitCode | Should -Be $case.Code -Because "$($case.Signal) is 128 + its signal number"
            } finally {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
    }

    It "Gives a stop file touched by hand 130, not a signal's code" {
        $path = New-StopFilePath
        try {
            $null = Enable-RunControl -StopFile $path
            Set-Content -LiteralPath $path -Value "someone asked nicely"
            $null = Test-InterruptRequested 6> $null
            $script:exitCode | Should -Be 130
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    It "Only the first stop counts: a later one cannot rewrite the verdict" {
        $null = Enable-RunControl
        Request-ScanStop -Reason "Ctrl+C" -ExitCode 130 6> $null
        Request-ScanStop -Reason "SIGTERM" -ExitCode 143 6> $null
        $script:interruptReason | Should -Be "Ctrl+C"
        $script:exitCode | Should -Be 130
    }
}

Describe "Request-ScanDrain and Switch-ScanPause" -Tag "Unit", "RunControl" {
    AfterEach {
        Restore-RunControl
        $null = Enable-RunControl
    }

    It "Draining is not a stop: the scans in flight still get their time" {
        $null = Enable-RunControl
        Request-ScanDrain 6> $null
        $script:drainRequested | Should -BeTrue
        $script:interruptRequested | Should -BeFalse
    }

    It "Draining ends a pause" {
        $null = Enable-RunControl
        Switch-ScanPause 6> $null
        $script:pauseRequested | Should -BeTrue
        Request-ScanDrain 6> $null
        $script:pauseRequested | Should -BeFalse
    }

    It "Pause is a toggle" {
        $null = Enable-RunControl
        Switch-ScanPause 6> $null
        $script:pauseRequested | Should -BeTrue
        Switch-ScanPause 6> $null
        $script:pauseRequested | Should -BeFalse
    }

    It "Neither one can start once a stop is under way" {
        $null = Enable-RunControl
        Request-ScanStop -Reason "Ctrl+C" -ExitCode 130 6> $null
        Request-ScanDrain 6> $null
        Switch-ScanPause 6> $null
        $script:drainRequested | Should -BeFalse
        $script:pauseRequested | Should -BeFalse
    }

    It "A stop cancels a pause, so the loops do not hold on their way out" {
        $null = Enable-RunControl
        Switch-ScanPause 6> $null
        Request-ScanStop -Reason "Ctrl+C" -ExitCode 130 6> $null
        $script:pauseRequested | Should -BeFalse
    }
}

Describe "Get-StopCause" -Tag "Unit", "RunControl" {
    AfterEach {
        Restore-RunControl
        $null = Enable-RunControl
    }

    It "Says nothing when nothing was asked for: the clock did it" {
        $null = Enable-RunControl
        Get-StopCause | Should -BeNullOrEmpty
    }

    It "Names whatever asked for the stop" {
        $null = Enable-RunControl
        Request-ScanStop -Reason "SIGTERM" -ExitCode 143 6> $null
        Get-StopCause | Should -Be "SIGTERM"
    }

    It "Names a drain, and a stop outranks it" {
        $null = Enable-RunControl
        Request-ScanDrain 6> $null
        Get-StopCause | Should -Match "drain"
        Request-ScanStop -Reason "Ctrl+C" -ExitCode 130 6> $null
        Get-StopCause | Should -Be "Ctrl+C"
    }
}

Describe "Get-RunControlBadge and Show-RunControlKeys" -Tag "Unit", "RunControl" {
    AfterEach {
        Restore-RunControl
        $null = Enable-RunControl
    }

    It "Promises no key when there is no console listening for one" -Skip:(-not [Console]::IsInputRedirected) {
        $null = Enable-RunControl
        Get-RunControlBadge | Should -BeNullOrEmpty
        # And says nothing at all, rather than naming keys nothing will read.
        (Show-RunControlKeys 6>&1 | Out-String).Trim() | Should -BeNullOrEmpty
    }

    It "Stays out of the bar while a run is just running" {
        $script:interruptCapture = $false   # pretend a console was captured
        try {
            Get-RunControlBadge | Should -BeNullOrEmpty
        } finally {
            $script:interruptCapture = $null
        }
    }

    It "Says PAUSED while paused, and how to get out of it" {
        $script:interruptCapture = $false
        try {
            $script:pauseRequested = $true
            Get-RunControlBadge | Should -Match "PAUSED"
            Get-RunControlBadge | Should -Match "p resumes"
        } finally {
            $script:interruptCapture = $null
            $script:pauseRequested = $false
        }
    }

    It "Says DRAINING while draining" {
        $script:interruptCapture = $false
        try {
            $script:pauseRequested = $false
            $script:drainRequested = $true
            Get-RunControlBadge | Should -Match "DRAINING"
        } finally {
            $script:interruptCapture = $null
            $script:drainRequested = $false
        }
    }

    It "Names all three keys once, where the bar has no room for them" {
        $script:interruptCapture = $false
        try {
            $said = Show-RunControlKeys 6>&1 | Out-String
            $said | Should -Match "Ctrl\+C"
            $said | Should -Match "drain"
            $said | Should -Match "pause"
        } finally {
            $script:interruptCapture = $null
        }
    }
}

Describe "Restore-RunControl" -Tag "Unit", "RunControl" {
    It "Is safe to call when nothing was captured, and twice over" {
        $script:interruptCapture = $null
        { Restore-RunControl } | Should -Not -Throw
        { Restore-RunControl } | Should -Not -Throw
    }

    It "Takes the stop file with it, so the next run does not stop on it" {
        $path = New-StopFilePath
        try {
            $null = Enable-RunControl -StopFile $path
            Set-Content -LiteralPath $path -Value "SIGTERM"
            Restore-RunControl
            Test-Path -LiteralPath $path | Should -BeFalse
        } finally {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe "Clear-ProgressPanes" -Tag "Unit", "RunControl" {
    It "Clears the single-scan bar and the workflow pair" {
        Mock Write-Progress { }
        Clear-ProgressPanes
        Should -Invoke Write-Progress -Times 3 -Exactly
    }

    It "Does not throw when no bar was ever shown" {
        { Clear-ProgressPanes } | Should -Not -Throw
    }
}

Describe "Wait-ForScheduledStart" -Tag "Unit", "RunControl" {
    AfterEach {
        Restore-RunControl
        $null = Enable-RunControl
    }

    It "Gives up the countdown when the stop has been asked for" {
        $null = Enable-RunControl
        Request-ScanStop -Reason "Ctrl+C" -ExitCode 130 6> $null
        # 10 minutes out: without the interrupt check this would hold the test
        # run hostage instead of returning.
        $target = (Get-Date).AddMinutes(10)
        $returned = Wait-ForScheduledStart -StartTime $target -RefreshSeconds 1 6> $null
        $returned | Should -BeOfType [datetime]
        $returned | Should -BeLessThan $target
    }
}
