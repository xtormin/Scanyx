# RunTests.ps1
# Main test runner for SCANYX
# Executes all tests and generates reports

[CmdletBinding()]
param(
    # Run only specific test category (Unit, Integration, Functional)
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Unit", "Integration", "Functional")]
    [string]$Category = "All",

    # Generate code coverage report
    [Parameter(Mandatory = $false)]
    [switch]$CodeCoverage,

    # Output format (Normal, Detailed, Diagnostic)
    [Parameter(Mandatory = $false)]
    [ValidateSet("Normal", "Detailed", "Diagnostic")]
    [string]$Output = "Detailed",

    # Generate CI/CD compatible output
    [Parameter(Mandatory = $false)]
    [switch]$CI,

    # Path to output test results (for CI)
    [Parameter(Mandatory = $false)]
    [string]$OutputFile = "",

    # Run only tests with specific tag
    [Parameter(Mandatory = $false)]
    [string]$Tag = ""
)

# Check if Pester is installed
$pesterModule = Get-Module -Name Pester -ListAvailable | Where-Object { $_.Version -ge [Version]"5.0.0" }
if (-not $pesterModule) {
    Write-Host "❌ Pester 5.x is not installed. Installing..." -ForegroundColor Red
    Install-Module -Name Pester -Force -SkipPublisherCheck -MinimumVersion 5.0.0
    Write-Host "✅ Pester installed successfully" -ForegroundColor Green
}

# Import Pester
Import-Module Pester -MinimumVersion 5.0.0

# Get script root
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$testRoot = $scriptRoot
$projectRoot = Split-Path -Parent $scriptRoot
$mainScript = Join-Path $projectRoot "scanyx.ps1"

# Validate main script exists
if (-not (Test-Path $mainScript)) {
    Write-Host "❌ Main script not found: $mainScript" -ForegroundColor Red
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  SCANYX Test Suite" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Build test path based on category
$testPaths = @()
switch ($Category) {
    "Unit" {
        $testPaths += Join-Path $testRoot "Unit\*.Tests.ps1"
        Write-Host "Running Unit Tests..." -ForegroundColor Yellow
    }
    "Integration" {
        $testPaths += Join-Path $testRoot "Integration\*.Tests.ps1"
        Write-Host "Running Integration Tests..." -ForegroundColor Yellow
    }
    "Functional" {
        $testPaths += Join-Path $testRoot "Functional\*.Tests.ps1"
        Write-Host "Running Functional Tests..." -ForegroundColor Yellow
    }
    "All" {
        $testPaths += Join-Path $testRoot "Unit\*.Tests.ps1"
        $testPaths += Join-Path $testRoot "Integration\*.Tests.ps1"
        $testPaths += Join-Path $testRoot "Functional\*.Tests.ps1"
        Write-Host "Running All Tests..." -ForegroundColor Yellow
    }
}

# Check if any test files exist
$foundTests = $false
foreach ($path in $testPaths) {
    if (Test-Path $path) {
        $foundTests = $true
        break
    }
}

if (-not $foundTests) {
    Write-Host "⚠️  No test files found in: $testPaths" -ForegroundColor Yellow
    exit 0
}

# Build Pester configuration
$pesterConfig = New-PesterConfiguration

# Set paths
$pesterConfig.Run.Path = $testPaths
$pesterConfig.Run.PassThru = $true

# Set output
$pesterConfig.Output.Verbosity = $Output

# Set tag filter if specified
if ($Tag) {
    $pesterConfig.Filter.Tag = $Tag
    Write-Host "Filtering by tag: $Tag" -ForegroundColor Cyan
}

# Code coverage configuration
if ($CodeCoverage) {
    Write-Host "Code coverage enabled" -ForegroundColor Cyan
    $pesterConfig.CodeCoverage.Enabled = $true
    $pesterConfig.CodeCoverage.Path = $mainScript
    $pesterConfig.CodeCoverage.OutputFormat = "JaCoCo"
    $pesterConfig.CodeCoverage.OutputPath = Join-Path $projectRoot "coverage.xml"
}

# CI/CD output configuration
if ($CI) {
    Write-Host "CI mode enabled" -ForegroundColor Cyan
    $pesterConfig.TestResult.Enabled = $true
    $pesterConfig.TestResult.OutputFormat = "NUnitXml"

    if ($OutputFile) {
        $pesterConfig.TestResult.OutputPath = $OutputFile
    } else {
        $pesterConfig.TestResult.OutputPath = Join-Path $projectRoot "TestResults.xml"
    }
}

# Run tests
Write-Host ""
$result = Invoke-Pester -Configuration $pesterConfig

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "Total Tests  : " -NoNewline
Write-Host $result.TotalCount -ForegroundColor White

Write-Host "Passed       : " -NoNewline
Write-Host $result.PassedCount -ForegroundColor Green

if ($result.FailedCount -gt 0) {
    Write-Host "Failed       : " -NoNewline
    Write-Host $result.FailedCount -ForegroundColor Red
}

if ($result.SkippedCount -gt 0) {
    Write-Host "Skipped      : " -NoNewline
    Write-Host $result.SkippedCount -ForegroundColor Yellow
}

if ($result.NotRunCount -gt 0) {
    Write-Host "Not Run      : " -NoNewline
    Write-Host $result.NotRunCount -ForegroundColor Gray
}

$duration = $result.Duration.TotalSeconds
Write-Host "Duration     : " -NoNewline
Write-Host "$($duration.ToString('0.00'))s" -ForegroundColor White

# Code coverage summary
if ($CodeCoverage -and $result.CodeCoverage) {
    Write-Host "`nCode Coverage:" -ForegroundColor Cyan
    $coverage = $result.CodeCoverage

    $coveredCommands = $coverage.CommandsExecutedCount
    $totalCommands = $coverage.CommandsAnalyzedCount

    if ($totalCommands -gt 0) {
        $coveragePercent = ($coveredCommands / $totalCommands) * 100

        Write-Host "Commands     : $coveredCommands / $totalCommands" -ForegroundColor White
        Write-Host "Coverage     : " -NoNewline

        $color = if ($coveragePercent -ge 80) { "Green" }
                 elseif ($coveragePercent -ge 60) { "Yellow" }
                 else { "Red" }

        Write-Host "$($coveragePercent.ToString('0.00'))%" -ForegroundColor $color
    }
}

Write-Host "`n========================================`n" -ForegroundColor Cyan

# Exit with appropriate code
if ($result.FailedCount -gt 0) {
    Write-Host "❌ Tests failed" -ForegroundColor Red
    exit 1
} else {
    Write-Host "✅ All tests passed!" -ForegroundColor Green
    exit 0
}
