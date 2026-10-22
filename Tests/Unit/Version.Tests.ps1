# Version.Tests.ps1
# The version is typed by hand in two places that cannot interpolate: the
# .NOTES help block and the release notes. Everything that prints it reads
# $script:ScanyxVersion. These keep the two in step - the banner said 2.8.1
# while .NOTES still said 2.8.0 for a while, and nothing noticed.

BeforeAll {
    . ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1'))
}

Describe "Version" -Tag "Unit", "Version" {
    It "Is declared once and the banner prints that one" {
        $script:ScanyxVersion | Should -Match '^\d+\.\d+\.\d+$'
        $source = Get-Content ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1')) -Raw
        # Nobody should be able to type a version into the banner again.
        $source | Should -Match 'Scanyx \(v\$script:ScanyxVersion\)'
    }

    It "Agrees with the version in the .NOTES help block" {
        $source = Get-Content ([IO.Path]::Combine($PSScriptRoot, '..', '..', 'scanyx.ps1')) -Raw
        $declared = [regex]::Match($source, '(?m)^Version:\s*(\S+)\s*$').Groups[1].Value
        $declared | Should -Be $script:ScanyxVersion
    }
}
