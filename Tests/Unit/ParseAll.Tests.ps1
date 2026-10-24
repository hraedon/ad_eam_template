#Requires -Version 5.1
# Runs without Active Directory: every .ps1 in the repo must parse.
BeforeDiscovery {
    $root  = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $files = Get-ChildItem -Path $root -Filter *.ps1 -Recurse -File |
        Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' } |
        ForEach-Object { @{ Name = $_.FullName.Substring($root.Length + 1); Path = $_.FullName } }
}
Describe 'Script syntax' {
    It '<Name> parses without errors' -ForEach $files {
        $tokens = $null; $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
        ($errs | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" }) | Should -BeNullOrEmpty
    }
}
