#Requires -Version 5.1
<#
.SYNOPSIS
    CTI-ATTACKCollector.ps1
    Australian Phoenix CyberOps | Chadi Saliby

.DESCRIPTION
    Downloads the MITRE ATT&CK Enterprise STIX bundle from GitHub,
    resolves all techniques attributed to a named threat actor,
    and emits a hunt-ready JSON report with hypothesis statements
    for each technique.

    No TAXII server. No API keys. No commercial tooling required.
    Works on any Windows host with internet access to github.com.

.PARAMETER ActorName
    Partial or full ATT&CK group name (e.g. 'APT29', 'Lazarus', 'Sandworm').

.PARAMETER OutputPath
    Path for the JSON report output. Defaults to .\cti_report.json

.PARAMETER BundleUrl
    Override the STIX bundle URL. Defaults to MITRE ATT&CK Enterprise v15.

.PARAMETER CachePath
    Local cache path for the STIX bundle. Avoids re-downloading each run.
    Set to $null or '' to disable caching.

.EXAMPLE
    .\CTI-ATTACKCollector.ps1 -ActorName 'APT29' -OutputPath .\apt29_hunt.json -Verbose

.EXAMPLE
    .\CTI-ATTACKCollector.ps1 -ActorName 'Lazarus' -CachePath '' 
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ActorName,

    [string]$OutputPath  = '.\cti_report.json',

    [string]$BundleUrl   = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',

    [string]$CachePath   = "$env:TEMP\mitre_attack_enterprise.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── BANNER ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   CTI-ATTACKCollector  |  Phoenix CyberOps      ║" -ForegroundColor Cyan
Write-Host "  ║   MITRE ATT&CK GitHub Bundle Edition            ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── STEP 1: LOAD STIX BUNDLE ────────────────────────────────────────────────
function Get-StixBundle {
    param([string]$Url, [string]$Cache)

    # Use cache if available and less than 24 hours old
    if ($Cache -and (Test-Path $Cache)) {
        $age = (Get-Date) - (Get-Item $Cache).LastWriteTime
        if ($age.TotalHours -lt 24) {
            Write-Host "[+] Using cached STIX bundle ($([math]::Round($age.TotalMinutes)) min old)" -ForegroundColor Green
            $raw = Get-Content $Cache -Raw -Encoding UTF8
            return ($raw | ConvertFrom-Json)
        }
    }

    Write-Host "[*] Downloading MITRE ATT&CK Enterprise STIX bundle..." -ForegroundColor Yellow
    Write-Host "    $Url" -ForegroundColor DarkGray

    try {
        # Use TLS 1.2 explicitly — required for GitHub on older PS versions
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $raw = (New-Object System.Net.WebClient).DownloadString($Url)
    }
    catch {
        Write-Error "Download failed: $_`n`nCheck connectivity to raw.githubusercontent.com"
    }

    if ($Cache) {
        $raw | Out-File -FilePath $Cache -Encoding UTF8 -Force
        Write-Host "[+] Bundle cached to: $Cache" -ForegroundColor DarkGreen
    }

    return ($raw | ConvertFrom-Json)
}

# ── STEP 2: FIND ACTOR ──────────────────────────────────────────────────────
function Find-Actor {
    param([array]$Objects, [string]$Name)

    $matches = @($Objects | Where-Object {
        if ($_.type -ne 'intrusion-set') { return $false }
        if ($_.name -like "*$Name*")     { return $true  }
        # Safely check aliases — property may not exist on all intrusion-set objects
        $hasAliases = $_.PSObject.Properties.Name -contains 'aliases'
        if ($hasAliases -and $null -ne $_.aliases) {
            foreach ($a in @($_.aliases)) {
                if ($a -like "*$Name*") { return $true }
            }
        }
        return $false
    })

    if ($matches.Count -eq 0) {
        # Show available actors to help the caller
        Write-Host "`n[!] Actor '$Name' not found. Available groups (sample):" -ForegroundColor Red
        @($Objects | Where-Object { $_.type -eq 'intrusion-set' } |
            Select-Object -ExpandProperty name | Sort-Object | Select-Object -First 30) |
            ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkGray }
        Write-Error "Actor '$Name' not found in ATT&CK dataset. Check spelling above."
    }

    if ($matches.Count -gt 1) {
        Write-Host "[!] Multiple matches found — using first result:" -ForegroundColor Yellow
        $matches | ForEach-Object { Write-Host "    - $($_.name) [$($_.id)]" -ForegroundColor DarkGray }
    }

    return $matches[0]
}

# ── STEP 3: RESOLVE TECHNIQUES VIA RELATIONSHIPS ───────────────────────────
function Resolve-Techniques {
    param([array]$Objects, [psobject]$Actor)

    Write-Verbose "Resolving relationships for actor: $($Actor.name) [$($Actor.id)]"

    # relationships: actor --uses--> technique
    $relatedIds = @(
        $Objects | Where-Object {
            $_.type -eq 'relationship' -and
            $_.relationship_type -eq 'uses' -and
            $_.source_ref -eq $Actor.id
        } | Select-Object -ExpandProperty target_ref
    )

    Write-Verbose "Found $($relatedIds.Count) 'uses' relationships"

    if ($relatedIds.Count -eq 0) { return @() }

    # Filter to attack-patterns only (excludes tools, malware, etc.)
    # x_mitre_deprecated and revoked are optional STIX fields — guard every access
    $techniques = @(
        $Objects | Where-Object {
            if ($_.type -ne 'attack-pattern') { return $false }
            if ($_.id -notin $relatedIds)     { return $false }
            if (($_.PSObject.Properties.Name -contains 'x_mitre_deprecated') -and
                ($_.x_mitre_deprecated -eq $true)) { return $false }
            if (($_.PSObject.Properties.Name -contains 'revoked') -and
                ($_.revoked -eq $true)) { return $false }
            return $true
        }
    )

    return $techniques
}

# ── STEP 4: BUILD HUNT REPORT ───────────────────────────────────────────────
function Build-Report {
    param([psobject]$Actor, [array]$Techniques)

    $entries = @()

    foreach ($t in ($Techniques | Sort-Object name)) {

        # ATT&CK ID (e.g. T1059.001)
        $attackId = ''
        if ($t.PSObject.Properties.Name -contains 'external_references') {
            if ($null -ne $t.external_references) {
                $ref = @($t.external_references | Where-Object { $_.source_name -eq 'mitre-attack' })
                if ($ref.Count -gt 0) { $attackId = $ref[0].external_id }
            }
        }

        # Kill-chain phases
        $phases = ''
        if ($t.PSObject.Properties.Name -contains 'kill_chain_phases') {
            if ($null -ne $t.kill_chain_phases) {
                $phases = ($t.kill_chain_phases | ForEach-Object { $_.phase_name }) -join ', '
            }
        }

        # Data sources
        $dataSources = ''
        if ($t.PSObject.Properties.Name -contains 'x_mitre_data_sources') {
            if ($null -ne $t.x_mitre_data_sources) {
                $dataSources = $t.x_mitre_data_sources -join '; '
            }
        }

        # Platforms
        $platforms = ''
        if ($t.PSObject.Properties.Name -contains 'x_mitre_platforms') {
            if ($null -ne $t.x_mitre_platforms) {
                $platforms = $t.x_mitre_platforms -join ', '
            }
        }

        # Clean description (remove markdown newlines)
        $desc = ''
        if ($t.PSObject.Properties.Name -contains 'description') {
            if ($null -ne $t.description) {
                $desc = $t.description -replace '\r?\n', ' ' -replace '\s{2,}', ' '
            }
        }

        # Detection guidance from ATT&CK
        $detection = ''
        if ($t.PSObject.Properties.Name -contains 'x_mitre_detection') {
            if ($null -ne $t.x_mitre_detection) {
                $detection = $t.x_mitre_detection -replace '\r?\n', ' ' -replace '\s{2,}', ' '
            }
        }

        # Auto-generated hunt hypothesis
        $hypothesis = "If [$($Actor.name)] is active, evidence of [$attackId] '$($t.name)' " +
                      "should appear in data sources: [$dataSources]. " +
                      "Scope hunt to kill-chain phase(s): [$phases]."

        $entries += [ordered]@{
            technique_id    = $attackId
            technique_name  = $t.name
            is_subtechnique = (($t.PSObject.Properties.Name -contains 'x_mitre_is_subtechnique') -and ($t.x_mitre_is_subtechnique -eq $true))
            kill_chain      = $phases
            platforms       = $platforms
            data_sources    = $dataSources
            description     = $desc
            detection       = $detection
            hunt_hypothesis = $hypothesis
            attack_url      = "https://attack.mitre.org/techniques/$($attackId -replace '\.','/')"
        }
    }

    return [ordered]@{
        report_meta = [ordered]@{
            tool            = 'CTI-ATTACKCollector.ps1'
            author          = 'Australian Phoenix CyberOps'
            generated_at    = (Get-Date -Format 'o')
            actor_name      = $Actor.name
            actor_id        = $Actor.id
            actor_aliases   = if (($Actor.PSObject.Properties.Name -contains 'aliases') -and ($null -ne $Actor.aliases)) { $Actor.aliases -join ', ' } else { '' }
            technique_count = $Techniques.Count
            source          = 'MITRE ATT&CK Enterprise (GitHub STIX Bundle)'
        }
        techniques = $entries
    }
}

# ── STEP 5: CONSOLE SUMMARY TABLE ───────────────────────────────────────────
function Show-Summary {
    param([array]$Entries)

    Write-Host ""
    Write-Host "  ID            Technique                                     Phase" -ForegroundColor Cyan
    Write-Host "  ──────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

    foreach ($e in $Entries) {
        $id    = $e.technique_id.PadRight(14)
        $name  = $e.technique_name.Substring(0, [Math]::Min(46, $e.technique_name.Length)).PadRight(48)
        $phase = $e.kill_chain

        $colour = if ($e.is_subtechnique) { 'Gray' } else { 'White' }
        Write-Host "  $id$name$phase" -ForegroundColor $colour
    }
    Write-Host ""
}

# ── MAIN ────────────────────────────────────────────────────────────────────
$bundle     = Get-StixBundle -Url $BundleUrl -Cache $CachePath
$allObjects = @($bundle.objects)
Write-Host "[+] Loaded $($allObjects.Count) STIX objects from ATT&CK bundle" -ForegroundColor Green

$actor      = Find-Actor -Objects $allObjects -Name $ActorName
Write-Host "[+] Actor resolved: $($actor.name) [$($actor.id)]" -ForegroundColor Green

$aliases = if (($actor.PSObject.Properties.Name -contains 'aliases') -and ($null -ne $actor.aliases)) { $actor.aliases -join ', ' } else { 'none' }
Write-Host "    Aliases : $aliases" -ForegroundColor DarkGray

$techniques = Resolve-Techniques -Objects $allObjects -Actor $actor
Write-Host "[+] Techniques resolved: $($techniques.Count) active, non-deprecated" -ForegroundColor Green

$report = Build-Report -Actor $actor -Techniques $techniques
$json   = $report | ConvertTo-Json -Depth 10

$json | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
Write-Host "[+] Hunt report written to: $OutputPath" -ForegroundColor Green

Show-Summary -Entries $report.techniques

Write-Host "[*] Done. Load $OutputPath into your TIP, SIEM, or Phoenix CTI Forge." -ForegroundColor Cyan
Write-Host ""