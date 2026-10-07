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
