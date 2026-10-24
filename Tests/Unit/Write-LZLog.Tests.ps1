#Requires -Version 5.1
# Runs without Active Directory. Event Log sink is stubbed out.
BeforeAll {
    $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $root 'Helpers/Write-LZLog.ps1')
    $script:root = $root
}
Describe 'Write-LZLog' {
    BeforeEach {
        $script:csv = Join-Path $TestDrive ("log-{0}.csv" -f [guid]::NewGuid())
        # Skip the Windows-only Event Log sink (also absent on pwsh 7 / Linux).
        $script:LZEventLogReady = $false
    }
    It 'accepts every action string used by the modules' {
        $used = Get-ChildItem $script:root -Filter *.ps1 -Recurse -File |
            Where-Object { $_.FullName -notmatch '[\\/]Tests[\\/]' } |
            ForEach-Object { Select-String -Path $_.FullName -Pattern "-Action\s+'(\w+)'" -AllMatches } |
            ForEach-Object { $_.Matches | ForEach-Object { $_.Groups[1].Value } } | Sort-Object -Unique
        $used | Should -Contain 'Removed'
        foreach ($a in $used) {
            { Write-LZLog -LogPath $script:csv -Module 'T' -Action $a -ObjectType 'X' -ObjectDN 'dn' -Detail 'd' 6>$null } |
                Should -Not -Throw -Because "action '$a' must be in the ValidateSet"
        }
    }
    It 'records Removed rows that the removal summary counts' {
        Write-LZLog -LogPath $script:csv -Module 'T' -Action 'Removed' -ObjectType 'OU' -ObjectDN 'dn' -Detail 'd' 6>$null
        Write-LZLog -LogPath $script:csv -Module 'T' -Action 'Skipped' -ObjectType 'OU' -ObjectDN 'dn' -Detail 'd' 6>$null
        $log = Import-Csv $script:csv
        @($log | Where-Object { $_.Action -eq 'Removed' }).Count | Should -Be 1
        @($log | Where-Object { $_.Action -eq 'Error' }).Count   | Should -Be 0
    }
    It 'still rejects unknown actions' {
        { Write-LZLog -LogPath $script:csv -Module 'T' -Action 'Bogus' -ObjectType 'X' -ObjectDN 'd' -Detail 'd' } | Should -Throw
    }
}
