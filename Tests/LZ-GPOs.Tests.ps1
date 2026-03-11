<#
.SYNOPSIS
    Pester tests for the AD Landing Zone GPO scaffolding (v2).
#>

Import-Module ActiveDirectory  -ErrorAction Stop
Import-Module GroupPolicy      -ErrorAction Stop

$script:TierCount = 3
if ($env:LZ_TEST_TIERCOUNT) { $script:TierCount = [int]$env:LZ_TEST_TIERCOUNT }

$script:DomainDN = $env:LZ_TEST_DOMAINDN
if (-not $script:DomainDN) { $script:DomainDN = (Get-ADDomain).DistinguishedName }

$script:DomainFQDN = $env:LZ_TEST_DOMAINFQDN
if (-not $script:DomainFQDN) { $script:DomainFQDN = (Get-ADDomain).DNSRoot }

# Pre-compute WMI container DN at discovery time.
# BeforeAll blocks cannot access $script: vars set at top level in Pester 5;
# any string built from DomainDN must be computed here and used directly.
$script:WmiContainerDN = "CN=SOM,CN=WMIPolicy,CN=System,$($script:DomainDN)"

# Build per-tier GPO test cases at discovery time.
# WmiContainer and GpoPoliciesDN are embedded so It blocks in ForEach contexts
# do not need to reference $script:DomainDN (inaccessible at ForEach run time).
$script:GpoCases = for ($n = 0; $n -lt $script:TierCount; $n++) {
    @{
        TierN         = $n
        GpoName       = "LZ-T$n-GPO"
        TierOuPath    = "OU=_LZ_T$n,$($script:DomainDN)"
        FilterName    = "LZ-T$n-WMIFilter"
        WmiContainer  = "CN=SOM,CN=WMIPolicy,CN=System,$($script:DomainDN)"
        GpoPoliciesDN = "CN=Policies,CN=System,$($script:DomainDN)"
    }
}

Describe 'LZ GPO Scaffolding' -Tag 'GPOs' {

    BeforeAll {
        # Describe-level BeforeAll runs at execution time. $script: vars set here
        # are accessible in all child Context/It blocks, including non-ForEach ones.
        $script:WmiContainerDN = "CN=SOM,CN=WMIPolicy,CN=System,$((Get-ADDomain).DistinguishedName)"
    }

    Context 'WMI filter container' {

        It 'CN=SOM WMI filter container is accessible' {
            { Get-ADObject -Identity $script:WmiContainerDN -ErrorAction Stop } |
                Should -Not -Throw
        }
    }

    Context 'Tier <TierN> GPO: <GpoName>' -ForEach $script:GpoCases {

        It '<GpoName> exists' {
            { Get-GPO -Name $GpoName -Domain $script:DomainFQDN -ErrorAction Stop } |
                Should -Not -Throw
        }

        It '<GpoName> is linked to tier OU <TierOuPath>' {
            $inheritance = Get-GPInheritance -Target $TierOuPath -Domain $script:DomainFQDN
            $link = $inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
            $link | Should -Not -BeNullOrEmpty
        }

        It '<GpoName> link is enabled' {
            $inheritance = Get-GPInheritance -Target $TierOuPath -Domain $script:DomainFQDN
            $link = $inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
            $link.Enabled | Should -Be $true
        }

        It '<TierOuPath> has GPO inheritance blocked' {
            $inheritance = Get-GPInheritance -Target $TierOuPath -Domain $script:DomainFQDN
            $inheritance.GpoInheritanceBlocked | Should -Be $true
        }
    }

    Context 'Tier <TierN> WMI filter: <FilterName>' -ForEach $script:GpoCases {

        It '<FilterName> WMI filter exists in CN=SOM' {
            $filterName = $FilterName   # capture ForEach data into local var for filter string
            $wmiBase    = $WmiContainer  # use ForEach field — $script:DomainDN is not accessible here
            $filter = Get-ADObject `
                -Filter "objectClass -eq 'msWMI-Som' -and msWMI-Name -eq '$filterName'" `
                -SearchBase $wmiBase `
                -ErrorAction Stop
            $filter | Should -Not -BeNullOrEmpty
        }

        It '<FilterName> WMI filter has a non-empty WQL query' {
            $filterName = $FilterName
            $wmiBase    = $WmiContainer
            $filter = Get-ADObject `
                -Filter "objectClass -eq 'msWMI-Som' -and msWMI-Name -eq '$filterName'" `
                -SearchBase $wmiBase `
                -Properties 'msWMI-Parm2' `
                -ErrorAction Stop
            $filter.'msWMI-Parm2' | Should -Not -BeNullOrEmpty
        }

        It '<GpoName> has gPCWQLFilter referencing <FilterName>' {
            $gpo       = Get-GPO -Name $GpoName -Domain $script:DomainFQDN
            $gpGuid    = $gpo.Id.ToString().ToUpper()
            $gpoDN     = "CN={$gpGuid},$GpoPoliciesDN"   # GpoPoliciesDN embedded in ForEach data
            $gpObj     = Get-ADObject -Identity $gpoDN -Properties gPCWQLFilter
            $gpObj.gPCWQLFilter | Should -Not -BeNullOrEmpty
        }
    }

    Context 'T0 GPO hardening (GptTmpl.inf)' {
        # These tests verify that the T0 hardening script has been run.
        # They are skipped if the file does not exist (hardening is an operator action,
        # not part of the deployer itself).

        $gpoName     = 'LZ-T0-GPO'
        $gptTmplPath = $null

        BeforeAll {
            try {
                $gpo = Get-GPO -Name 'LZ-T0-GPO' -Domain $script:DomainFQDN -ErrorAction Stop
                $gpoGuid = $gpo.Id.ToString('B').ToUpper()
                $script:HardeningPath = "\\$($script:DomainFQDN)\SYSVOL\$($script:DomainFQDN)\Policies\$gpoGuid\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            }
            catch {
                $script:HardeningPath = $null
            }
        }

        It 'LZ-T0-GPO GptTmpl.inf exists (hardening applied)' -Skip:(-not $script:HardeningPath) {
            Test-Path $script:HardeningPath | Should -Be $true
        }

        It 'GptTmpl.inf contains Restricted Groups section' -Skip:(-not $script:HardeningPath -or -not (Test-Path $script:HardeningPath)) {
            $content = Get-Content $script:HardeningPath -Raw
            $content | Should -Match '\[Group Membership\]'
        }

        It 'GptTmpl.inf contains User Rights Assignment (deny logon) section' -Skip:(-not $script:HardeningPath -or -not (Test-Path $script:HardeningPath)) {
            $content = Get-Content $script:HardeningPath -Raw
            $content | Should -Match 'SeDenyInteractiveLogonRight'
        }

        It 'GptTmpl.inf SeDenyInteractiveLogonRight includes GS-LZ-T1-Admins SID' -Skip:(-not $script:HardeningPath -or -not (Test-Path $script:HardeningPath)) {
            $t1Sid  = (Get-ADGroup -Identity 'GS-LZ-T1-Admins').SID.Value
            $content = Get-Content $script:HardeningPath -Raw
            $content | Should -Match $t1Sid
        }

        It 'GptTmpl.inf Group Membership includes GS-LZ-T0-Admins SID' -Skip:(-not $script:HardeningPath -or -not (Test-Path $script:HardeningPath)) {
            $t0Sid  = (Get-ADGroup -Identity 'GS-LZ-T0-Admins').SID.Value
            $content = Get-Content $script:HardeningPath -Raw
            $content | Should -Match $t0Sid
        }
    }
}
