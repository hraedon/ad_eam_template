#Requires -Version 5.1
<#
.SYNOPSIS
    Returns the exact bytes written to disk for a UTF-16 LE (with BOM) INF template,
    plus a hash helper, so new content and an existing file are compared like for like.
#>
function Get-LZTemplateBytes {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Content)

    $enc      = [System.Text.Encoding]::Unicode   # UTF-16 LE; GetPreamble() is the BOM
    $preamble = $enc.GetPreamble()
    $body     = $enc.GetBytes($Content)
    $all      = New-Object byte[] ($preamble.Length + $body.Length)
    [Array]::Copy($preamble, 0, $all, 0, $preamble.Length)
    [Array]::Copy($body, 0, $all, $preamble.Length, $body.Length)
    , $all
}

function Get-LZBytesHash {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $sha.Dispose() }
}
