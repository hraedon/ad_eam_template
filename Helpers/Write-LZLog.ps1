<#
.SYNOPSIS
    Structured logging helper for the AD Landing Zone deployer.

.DESCRIPTION
    Writes a structured log entry to both the console and a CSV file.
    Every action taken by the deployer (created, skipped, modified, error) is
    recorded through this function.

.PARAMETER LogPath
    Full path to the CSV log file. Created on first write; appended on subsequent calls.

.PARAMETER Module
    The deployer module producing this log entry (e.g. PreFlight, OUs, Groups).

.PARAMETER Action
    Nature of the action: Created, Skipped, Modified, Error, Warning, or Info.

.PARAMETER ObjectType
    AD object class or category: OU, Group, Container, ACL, AuthPolicy, Silo,
    GroupMembership, KdsRootKey, Domain, Session.

.PARAMETER ObjectDN
    Full distinguished name of the affected object (or a descriptive path for
    non-AD items such as domain-level checks).

.PARAMETER Detail
    Human-readable description of what was done or why it was skipped/errored.
#>
function Write-LZLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][string]$Module,
        [Parameter(Mandatory)]
        [ValidateSet('Created','Skipped','Modified','Error','Warning','Info')]
        [string]$Action,
        [Parameter(Mandatory)][string]$ObjectType,
        [Parameter(Mandatory)][string]$ObjectDN,
        [Parameter(Mandatory)][string]$Detail
    )

    $entry = [PSCustomObject]@{
        Timestamp  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        Module     = $Module
        Action     = $Action
        ObjectType = $ObjectType
        ObjectDN   = $ObjectDN
        Detail     = $Detail
    }

    # Ensure the log directory exists before the first write.
    $logDir = Split-Path -Parent $LogPath
    if ($logDir -and -not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    # Console output -- colour-coded by action type.
    $color = switch ($Action) {
        'Created' { 'Green'   }
        'Skipped' { 'Yellow'  }
        'Modified'{ 'Cyan'    }
        'Error'   { 'Red'     }
        'Warning' { 'Magenta' }
        default   { 'White'   }
    }

    $consoleLine = '[{0}] [{1,-14}] [{2,-8}] {3,-20} | {4}' -f
        $entry.Timestamp, $Module, $Action, $ObjectType, $Detail

    Write-Host $consoleLine -ForegroundColor $color

    # Verbose stream includes the full DN for traceability without cluttering the
    # default console output.
    Write-Verbose "  DN: $ObjectDN"

    # CSV output -- append mode; Export-Csv creates the file on first call.
    $entry | Export-Csv -Path $LogPath -Append -NoTypeInformation -Encoding UTF8
}
