# Retry.Tests.ps1
# Unit tests for the deferred retry queue: Start-DueRetries

BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1'))

    function New-RetryEntry {
        param([datetime]$NotBefore, [int]$Attempts = 2)
        @{
            NotBefore = $NotBefore
            Attempts = $Attempts
            HostFolder = "/tmp/out/host"
            FileName = "tcp-100"
            ScanCommand = "nmap -sT --top-ports 100"
            ResultFile = ""
        }
    }
}

Describe "Start-DueRetries" -Tag "Unit", "Retry" {
    BeforeEach {
        Mock Start-NmapScanJob { [pscustomobject]@{ Name = "job-$TargetHost"; State = "Running" } }
        $now = [datetime]"2026-10-07 12:00:00"
        $retryQueue = @{}
        $jobQueue = @{}
        $jobStartTimes = @{}
    }

    It "Leaves a retry alone until its delay is over" {
        $retryQueue["10.0.0.1"] = New-RetryEntry -NotBefore $now.AddSeconds(30)

        $n = Start-DueRetries -RetryQueue $retryQueue -JobQueue $jobQueue -JobStartTimes $jobStartTimes -MaxConcurrent 5 -Now $now

        $n | Should -Be 0
        $retryQueue.Count | Should -Be 1
        $jobQueue.Count | Should -Be 0
        Should -Invoke Start-NmapScanJob -Times 0 -Exactly
    }

    It "Moves a due retry into the job queue with everything it needs" {
        $entry = New-RetryEntry -NotBefore $now.AddSeconds(-1) -Attempts 2
        $entry.ResultFile = "/tmp/out/x.nmap"
        $retryQueue["10.0.0.1"] = $entry

        $n = Start-DueRetries -RetryQueue $retryQueue -JobQueue $jobQueue -JobStartTimes $jobStartTimes -MaxConcurrent 5 -Now $now -Verbatim $true

        $n | Should -Be 1
        $retryQueue.Count | Should -Be 0
        $jobQueue["10.0.0.1"].Attempts | Should -Be 2
        $jobQueue["10.0.0.1"].ResultFile | Should -Be "/tmp/out/x.nmap"
        $jobQueue["10.0.0.1"].Job.Name | Should -Be "job-10.0.0.1"
        $jobStartTimes["10.0.0.1"] | Should -Be $now
        Should -Invoke Start-NmapScanJob -Times 1 -Exactly -ParameterFilter {
            $TargetHost -eq "10.0.0.1" -and $Attempts -eq 2 -and $Verbatim -and $ResultFile -eq "/tmp/out/x.nmap"
        }
    }

    It "Never goes past MaxConcurrent, and launches the oldest first" {
        $jobQueue["busy"] = @{ Job = $null }
        $retryQueue["late"]  = New-RetryEntry -NotBefore $now.AddSeconds(-5)
        $retryQueue["early"] = New-RetryEntry -NotBefore $now.AddSeconds(-50)

        $n = Start-DueRetries -RetryQueue $retryQueue -JobQueue $jobQueue -JobStartTimes $jobStartTimes -MaxConcurrent 2 -Now $now

        $n | Should -Be 1
        $jobQueue.Count | Should -Be 2
        $jobQueue.ContainsKey("early") | Should -BeTrue
        $retryQueue.ContainsKey("late") | Should -BeTrue
    }

    It "Launches nothing once the deadline has passed" {
        $retryQueue["10.0.0.1"] = New-RetryEntry -NotBefore $now.AddSeconds(-60)

        $n = Start-DueRetries -RetryQueue $retryQueue -JobQueue $jobQueue -JobStartTimes $jobStartTimes -MaxConcurrent 5 -StopTime $now.AddSeconds(-1) -Now $now

        $n | Should -Be 0
        $retryQueue.Count | Should -Be 1
        Should -Invoke Start-NmapScanJob -Times 0 -Exactly
    }
}

Describe "Show-ProgressBar pending retries" -Tag "Unit", "Retry" {
    BeforeEach {
        Mock Write-Progress { }
    }

    It "Shows how many retries are waiting" {
        Show-ProgressBar -Completed 3 -Total 10 -Failed 0 -PendingRetries 2
        Should -Invoke Write-Progress -Times 1 -Exactly -ParameterFilter { $Status -like "*| Retry: 2*" }
    }

    It "Says nothing about retries when none are waiting" {
        Show-ProgressBar -Completed 3 -Total 10 -Failed 0
        Should -Invoke Write-Progress -Times 1 -Exactly -ParameterFilter { $Status -notlike "*Retry:*" }
    }
}
