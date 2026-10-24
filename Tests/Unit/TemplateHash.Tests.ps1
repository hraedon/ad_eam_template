#Requires -Version 5.1
BeforeAll {
    $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $root 'Helpers/Get-LZTemplateBytes.ps1')
}
Describe 'T0 hardening template idempotency comparison' {
    It 'hash of new content equals hash of the file as written (BOM included)' {
        $content = "[Unicode]`r`nUnicode=yes`r`n[Group Membership]`r`n*S-1-5-21-1-2-3-512__Members = x`r`n"
        $path = Join-Path $TestDrive 'GptTmpl.inf'
        [System.IO.File]::WriteAllBytes($path, (Get-LZTemplateBytes -Content $content))
        $onDisk = [System.IO.File]::ReadAllBytes($path)
        $onDisk[0] | Should -Be 0xFF
        $onDisk[1] | Should -Be 0xFE
        (Get-LZBytesHash -Bytes $onDisk) | Should -Be (Get-LZBytesHash -Bytes (Get-LZTemplateBytes -Content $content))
    }
    It 'matches a file written by WriteAllText(Encoding.Unicode), as the old code did' {
        $content = "abc`r`n"
        $path = Join-Path $TestDrive 'old.inf'
        [System.IO.File]::WriteAllText($path, $content, [System.Text.Encoding]::Unicode)
        (Get-LZBytesHash -Bytes ([System.IO.File]::ReadAllBytes($path))) |
            Should -Be (Get-LZBytesHash -Bytes (Get-LZTemplateBytes -Content $content))
    }
    It 'differs when the content changes' {
        (Get-LZBytesHash -Bytes (Get-LZTemplateBytes -Content 'a')) |
            Should -Not -Be (Get-LZBytesHash -Bytes (Get-LZTemplateBytes -Content 'b'))
    }
}
