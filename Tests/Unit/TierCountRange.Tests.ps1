#Requires -Version 5.1
# Everything the deployer can create (-TierCount range) must be removable.
BeforeAll {
    function Get-Range($path) {
        $t = $null; $e = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$t, [ref]$e)
        $p = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'TierCount' }
        $a = $p.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateRange' }
        ($a.PositionalArguments | ForEach-Object { $_.Value }) -join ','
    }
    $script:root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Get = ${function:Get-Range}
}
Describe 'TierCount range' {
    It 'remover accepts the same range as the deployer' {
        $d = & $script:Get (Join-Path $script:root 'Deploy-ADLandingZone.ps1')
        $r = & $script:Get (Join-Path $script:root 'Remove-ADLandingZone.ps1')
        $d | Should -Be '2,10'
        $r | Should -Be $d
    }
}
