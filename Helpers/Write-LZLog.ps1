<#
.SYNOPSIS
    Structured logging helper for the AD Landing Zone deployer.

.DESCRIPTION
    Writes a structured log entry to three sinks simultaneously:
      1. Console  -- colour-coded for operator readability.
      2. CSV file -- append mode; the canonical deployment record.
      3. Windows Event Log -- Application log, source ADLandingZone.
         Provides an immutable, SIEM-consumable audit trail that a Domain Admin
         cannot silently edit. The Event Log is a secondary sink; if it is
         unavailable the function continues without error.

    Event IDs:
        1001 Created | 1002 Skipped | 1003 Modified | 1004 Error
        1005 Warning | 1006 Info    | 1007 WhatIf

.PARAMETER LogPath
    Full path to the CSV log file. Created on first write; appended on subsequent calls.

.PARAMETER Module
    The deployer module producing this log entry (e.g. PreFlight, OUs, Groups).

.PARAMETER Action
    Nature of the action: Created, Skipped, Modified, Error, Warning, Info, or WhatIf.
    WhatIf entries are written during -WhatIf preview runs; no AD objects are created.

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
        [ValidateSet('Created','Skipped','Modified','Error','Warning','Info','WhatIf')]
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
        'Created' { 'Green'    }
        'Skipped' { 'Yellow'   }
        'Modified'{ 'Cyan'     }
        'Error'   { 'Red'      }
        'Warning' { 'Magenta'  }
        'WhatIf'  { 'DarkCyan' }
        default   { 'White'    }
    }

    $consoleLine = '[{0}] [{1,-14}] [{2,-8}] {3,-20} | {4}' -f
        $entry.Timestamp, $Module, $Action, $ObjectType, $Detail

    Write-Host $consoleLine -ForegroundColor $color

    # Verbose stream includes the full DN for traceability without cluttering the
    # default console output.
    Write-Verbose "  DN: $ObjectDN"

    # CSV output -- append mode; Export-Csv creates the file on first call.
    $entry | Export-Csv -Path $LogPath -Append -NoTypeInformation -Encoding UTF8

    # ------------------------------------------------------------------
    # Event Log sink -- immutable secondary audit trail.
    #
    # Source 'ADLandingZone' is registered once per session in the
    # Application log. Registration requires admin rights (already
    # verified in pre-flight). All errors are non-fatal: if the Event
    # Log is unavailable, CSV + console remain the authoritative record.
    # ------------------------------------------------------------------
    if (-not $script:LZEventLogReady) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists('ADLandingZone')) {
                New-EventLog -LogName Application -Source 'ADLandingZone' -ErrorAction Stop
            }
            $script:LZEventLogReady = $true
        }
        catch {
            # Non-fatal. Mark as permanently unavailable for this session so
            # we do not re-attempt the registry write on every log call.
            $script:LZEventLogReady = $false
            Write-Verbose "Event Log source registration failed: $($_.Exception.Message)"
        }
    }

    if ($script:LZEventLogReady) {
        $eventId = switch ($Action) {
            'Created'  { 1001 }
            'Skipped'  { 1002 }
            'Modified' { 1003 }
            'Error'    { 1004 }
            'Warning'  { 1005 }
            'Info'     { 1006 }
            'WhatIf'   { 1007 }
            default    { 1000 }
        }
        $entryType = switch ($Action) {
            'Error'   { [System.Diagnostics.EventLogEntryType]::Error   }
            'Warning' { [System.Diagnostics.EventLogEntryType]::Warning }
            default   { [System.Diagnostics.EventLogEntryType]::Information }
        }
        # Key=value format for SIEM parsing without requiring a custom manifest.
        $eventMessage = "Module: $Module`nAction: $Action`nObjectType: $ObjectType`nObjectDN: $ObjectDN`nDetail: $Detail`nTimestamp: $($entry.Timestamp)"
        try {
            Write-EventLog -LogName Application -Source 'ADLandingZone' `
                -EventId $eventId -EntryType $entryType -Message $eventMessage -ErrorAction Stop
        }
        catch {
            Write-Verbose "Event Log write failed: $($_.Exception.Message)"
        }
    }
}
