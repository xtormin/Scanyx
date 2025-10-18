# SCANYX Tests

Comprehensive test suite for SCANYX using Pester 5.x framework.

## Table of Contents
- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Writing New Tests](#writing-new-tests)
- [CI/CD Integration](#cicd-integration)

---

## Quick Start

```powershell
# Install Pester (if not already installed)
Install-Module -Name Pester -Force -SkipPublisherCheck -MinimumVersion 5.0.0

# Run all tests
.\Tests\RunTests.ps1

# Run only unit tests
.\Tests\RunTests.ps1 -Category Unit

# Run with code coverage
.\Tests\RunTests.ps1 -CodeCoverage
```

---

## Prerequisites

### Required
- **PowerShell**: 5.1 or later
- **Pester**: 5.0.0 or later

### Installation

```powershell
# Check if Pester 5.x is installed
Get-Module Pester -ListAvailable

# Install Pester 5.x
Install-Module -Name Pester -Force -SkipPublisherCheck -MinimumVersion 5.0.0

# Verify installation
Import-Module Pester
(Get-Module Pester).Version
```

---

## Test Structure

```
Tests/
├── RunTests.ps1                 # Main test runner
├── README.md                    # This file
│
├── Unit/                        # Unit tests (individual functions)
│   ├── Validation.Tests.ps1    # Input validation tests
│   ├── CIDR.Tests.ps1          # CIDR expansion tests
│   ├── State.Tests.ps1         # State management tests
│   └── Results.Tests.ps1       # Result analysis tests
│
├── Integration/                 # Integration tests (component interaction)
│   ├── Configuration.Tests.ps1 # Config loading tests
│   ├── Sessions.Tests.ps1      # Session management tests
│   └── Workflows.Tests.ps1     # Workflow execution tests
│
├── Functional/                  # Functional tests (end-to-end)
│   ├── EndToEnd.Tests.ps1      # Complete scan scenarios
│   └── Scenarios.Tests.ps1     # Specific use case tests
│
├── Mocks/                       # Mock implementations
│   ├── Nmap.Mock.ps1           # Nmap command mocks
│   └── FileSystem.Mock.ps1     # File system mocks
│
└── Fixtures/                    # Test data
    ├── sample-hosts.txt        # Sample hosts file
    ├── sample-config.json      # Sample configuration
    └── sample-nmap-output.xml  # Sample Nmap output
```

---

## Running Tests

### Basic Usage

```powershell
# Run all tests
.\Tests\RunTests.ps1

# Run with detailed output
.\Tests\RunTests.ps1 -Output Detailed

# Run with diagnostic output (very verbose)
.\Tests\RunTests.ps1 -Output Diagnostic
```

### By Category

```powershell
# Unit tests only (fast)
.\Tests\RunTests.ps1 -Category Unit

# Integration tests only
.\Tests\RunTests.ps1 -Category Integration

# Functional tests only (slower)
.\Tests\RunTests.ps1 -Category Functional
```

### By Tag

```powershell
# Run only validation tests
.\Tests\RunTests.ps1 -Tag Validation

# Run only CIDR tests
.\Tests\RunTests.ps1 -Tag CIDR

# Run only state management tests
.\Tests\RunTests.ps1 -Tag State
```

### With Code Coverage

```powershell
# Generate code coverage report
.\Tests\RunTests.ps1 -CodeCoverage

# Coverage report saved to: coverage.xml (JaCoCo format)
```

### For CI/CD

```powershell
# Generate NUnit XML output for CI/CD
.\Tests\RunTests.ps1 -CI -OutputFile "TestResults.xml"

# Run in CI mode with code coverage
.\Tests\RunTests.ps1 -CI -CodeCoverage
```

---

## Test Examples

### Running Specific Test File

```powershell
# Run single test file
Invoke-Pester -Path .\Tests\Unit\Validation.Tests.ps1

# With detailed output
Invoke-Pester -Path .\Tests\Unit\Validation.Tests.ps1 -Output Detailed
```

### Running Specific Test

```powershell
# Run tests matching a pattern
Invoke-Pester -Path .\Tests\Unit\ -FullNameFilter "*Test-ValidIPOrHost*"
```

---

## Writing New Tests

### Unit Test Template

```powershell
# MyFunction.Tests.ps1

BeforeAll {
    # Load the main script
    . $PSScriptRoot\..\..\scanyx.ps1
}

Describe "MyFunction" -Tag "Unit", "MyTag" {
    Context "When input is valid" {
        It "Does something correctly" {
            $result = MyFunction "valid-input"
            $result | Should -Be "expected-output"
        }
    }

    Context "When input is invalid" {
        It "Handles error gracefully" {
            { MyFunction "invalid" } | Should -Throw
        }
    }
}
```

### Integration Test Template

```powershell
# MyIntegration.Tests.ps1

BeforeAll {
    . $PSScriptRoot\..\..\scanyx.ps1
    . $PSScriptRoot\..\Mocks\Nmap.Mock.ps1
}

Describe "MyIntegration" -Tag "Integration" {
    BeforeEach {
        # Setup test environment
        $testDir = $TestDrive
    }

    It "Integrates components correctly" {
        # Test code here
    }

    AfterEach {
        # Cleanup if needed
    }
}
```

### Best Practices

1. **Isolation**: Each test should be independent
2. **Cleanup**: Use `BeforeEach`/`AfterEach` for setup/teardown
3. **Clear Names**: Test names should describe what they test
4. **One Assertion**: Prefer one assertion per test when possible
5. **Use TestDrive**: Pester's `$TestDrive` for temporary files
6. **Mock External**: Mock Nmap, network calls, etc.

---

## Test Coverage Goals

| Component | Target Coverage | Current Status |
|-----------|----------------|----------------|
| Validation Functions | 90%+ | 🟡 In Progress |
| CIDR Functions | 85%+ | 🟡 In Progress |
| State Management | 80%+ | 🟡 In Progress |
| Configuration | 75%+ | 🟡 In Progress |
| Sessions | 70%+ | 🔴 TODO |
| Workflows | 70%+ | 🔴 TODO |
| End-to-End | Key scenarios | 🔴 TODO |

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Pester
        shell: pwsh
        run: Install-Module -Name Pester -Force -SkipPublisherCheck

      - name: Run Tests
        shell: pwsh
        run: .\Tests\RunTests.ps1 -CI -CodeCoverage

      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: TestResults.xml

      - name: Upload Coverage
        uses: actions/upload-artifact@v3
        with:
          name: coverage-report
          path: coverage.xml
```

---

## Troubleshooting

### Pester Version Conflicts

```powershell
# Remove old Pester versions
Get-Module Pester -ListAvailable | Where-Object Version -lt 5.0.0 | Uninstall-Module

# Install Pester 5.x
Install-Module -Name Pester -Force -SkipPublisherCheck -MinimumVersion 5.0.0
```

### Tests Failing Due to Nmap

Tests should NOT require real Nmap installation. If they fail:

1. Check that mocks are loaded: `. $PSScriptRoot\..\Mocks\Nmap.Mock.ps1`
2. Ensure `Mock-NmapCommand` is called in tests
3. Verify test isolation

### Tests Failing Due to Paths

- Use `$TestDrive` for temporary files
- Use `Join-Path` for path construction
- Avoid hardcoded paths

---

## Adding New Test Categories

To add a new test category:

1. Create directory: `Tests\MyCategory\`
2. Add tests: `Tests\MyCategory\MyTest.Tests.ps1`
3. Update `RunTests.ps1` to include new category
4. Update this README

---

## Useful Commands

```powershell
# List all tests without running
Invoke-Pester -Path .\Tests\ -DryRun

# Run tests and show timing
Invoke-Pester -Path .\Tests\ -Output Detailed

# Run failed tests only (after initial run)
Invoke-Pester -Path .\Tests\ -FailedTestsFile failed.txt

# Debug a specific test
Invoke-Pester -Path .\Tests\Unit\Validation.Tests.ps1 -Output Diagnostic
```

---

## Contributing

When adding new functionality to SCANYX:

1. ✅ Write tests first (TDD approach recommended)
2. ✅ Ensure existing tests pass
3. ✅ Add new tests for new features
4. ✅ Update this documentation
5. ✅ Run full suite: `.\Tests\RunTests.ps1 -CodeCoverage`

---

## Resources

- [Pester Documentation](https://pester.dev/docs/quick-start)
- [Pester GitHub](https://github.com/pester/Pester)
- [PowerShell Testing Best Practices](https://pester.dev/docs/usage/test-file-structure)

---

**Last Updated**: 2025-10-15
**SCANYX Version**: 2.8.0
**Pester Version**: 5.x
