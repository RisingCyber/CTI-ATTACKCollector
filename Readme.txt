# CTI-ATTACKCollector

> **Hunt behaviour, not bytes.**  
> A zero-dependency PowerShell tool that resolves every MITRE ATT&CK technique attributed to a named threat actor and emits a hunt-ready JSON report. One hypothesis statement per technique, ready for SIEM ingestion or TIP import.

**Author:** Chadi Saliby
**Organisation:** [Australian Phoenix CyberOps]
**Licence:** MIT

---

## Why This Exists

Most CTI pipelines optimise for indicator volume IoCs. A SIEM fires an alert on a malicious IP, the analyst blocks it, the adversary rotates to a new one in less than 40 seconds.

Techniques the *how* of an intrusion are expensive to change. When your detections are built on TTPs rather than IoCs, you force the adversary to retrain, retool, and rethink following the Pyramid of pain. That is where the real defensive advantage compounds.

This script operationalises that principle. Give it an actor name. Get back every technique they use, mapped to kill-chain phase, observable data sources, MITRE detection guidance, and a pre-formed hunt hypothesis you can run today.

---

## Requirements

| Requirement | Detail |
|
| PowerShell | 5.1 or higher (Windows built-in) |
| Network access | `raw.githubusercontent.com` (HTTPS/443) |
| Execution policy | `RemoteSigned` or `Bypass` |
| External tools | None - no API keys or no TAXII servers |

**Set execution policy if needed:**
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

---

## Quick Start

```powershell
# Basic — outputs cti_report.json in current directory
.\CTI-ATTACKCollector.ps1 -ActorName 'APT29'
.\CTI-ATTACKCollector.ps1 -ActorName 'APT28' -OutputPath .\apt28_hunt.json -Verbose 

# Named output file
.\CTI-ATTACKCollector.ps1 -ActorName 'Lazarus' -OutputPath .\lazarus_hunt.json

# Verbose mode — shows relationship resolution detail
.\CTI-ATTACKCollector.ps1 -ActorName 'Sandworm' -Verbose

# Disable caching — always re-download the bundle
.\CTI-ATTACKCollector.ps1 -ActorName 'APT41' -CachePath ''
```

---

## Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-ActorName` | Yes | — | Full or partial ATT&CK group name. Case-insensitive. Matches on name and aliases. |
| `-OutputPath` | No | `.\cti_report.json` | Path for the JSON report output. |
| `-BundleUrl` | No | MITRE GitHub (Enterprise) | Override the STIX bundle URL , useful for pinning a specific ATT&CK version. |
| `-CachePath` | No | `$env:TEMP\mitre_attack_enterprise.json` | Local cache for the bundle. Reused for 24 hours. Set to `''` to disable. |

**Actor name matching** is partial and alias-aware. `'APT29'`, `'Cozy Bear'`, and `'Midnight Blizzard'` all resolve to the same group. If your input matches multiple groups, the script picks the first and lists all matches so you can refine.

If the actor is not found, the script prints the first 30 available group names to help you correct the spelling.

---

## Output

### Console

```
  ╔══════════════════════════════════════════════════╗
  ║   CTI-ATTACKCollector  |   Phoenix CyberOps      ║
  ║   MITRE ATT&CK GitHub Bundle Edition             ║
  ╚══════════════════════════════════════════════════╝

[+] Using cached STIX bundle (14 min old)
[+] Loaded 29842 STIX objects from ATT&CK bundle
[+] Actor resolved: APT29 [intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542]
    Aliases : Cozy Bear, The Dukes, Midnight Blizzard, ...
[+] Techniques resolved: 43 active, non-deprecated

  ID            Technique                                     Phase
  ──────────────────────────────────────────────────────────────────
  T1003         OS Credential Dumping                         credential-access
  T1021.001     Remote Services: Remote Desktop Protocol      lateral-movement
  T1059.001     Command and Scripting: PowerShell             execution
  ...

[*] Done. Load .\cti_report.json into your TIP, SIEM, or Phoenix CTI Forge.
```

Parent techniques are shown in **white**. Sub-techniques are shown in grey.

### JSON Report Structure

```json
{
  "report_meta": {
    "tool": "CTI-ATTACKCollector.ps1",
    "author": "Australian Phoenix CyberOps",
    "generated_at": "2026-06-28T14:32:00.000+10:00",
    "actor_name": "APT29",
    "actor_id": "intrusion-set--899ce53f-...",
    "actor_aliases": "Cozy Bear, The Dukes, Midnight Blizzard",
    "technique_count": 43,
    "source": "MITRE ATT&CK Enterprise (GitHub STIX Bundle)"
  },
  "techniques": [
    {
      "technique_id": "T1059.001",
      "technique_name": "Command and Scripting Interpreter: PowerShell",
      "is_subtechnique": true,
      "kill_chain": "execution",
      "platforms": "Windows",
      "data_sources": "Command: Command Execution; Process: Process Creation; ...",
      "description": "Adversaries may abuse PowerShell commands and scripts...",
      "detection": "If proper logging is enabled, PowerShell will log...",
      "hunt_hypothesis": "If [APT29] is active, evidence of [T1059.001] 'Command and Scripting Interpreter: PowerShell' should appear in data sources: [Command: Command Execution; Process: Process Creation]. Scope hunt to kill-chain phase(s): [execution].",
      "attack_url": "https://attack.mitre.org/techniques/T1059/001"
    }
  ]
}
```

Every `hunt_hypothesis` field is a ready-to-use statement that names the actor, technique ID, observable data sources, and kill-chain phase. Copy it directly into a hunt ticket, a TIP note, or a detection engineering brief.

---

## How It Works

```
1. GET  raw.githubusercontent.com/mitre/cti/.../enterprise-attack.json
         └─ ~12 MB STIX 2.x bundle, cached for 24 hours

2. FIND  intrusion-set objects matching ActorName (name + aliases)

3. WALK  relationship objects where:
           source_ref == actor.id
           relationship_type == 'uses'
           target_ref resolves to an attack-pattern

4. FILTER  deprecated and revoked techniques

5. BUILD   one report entry per technique:
             ATT&CK ID, kill-chain phase, data sources,
             platforms, description, detection guidance,
             auto-generated hunt hypothesis, ATT&CK URL

6. EMIT    JSON report + console summary table
```

The script uses the MITRE ATT&CK STIX bundle on GitHub rather than the TAXII API. The TAXII endpoint requires specific network access that is frequently blocked in enterprise environments. The GitHub bundle is plain HTTPS and works everywhere `raw.githubusercontent.com` is reachable.

TLS 1.2 is forced explicitly via `[Net.ServicePointManager]::SecurityProtocol` to ensure compatibility with Windows hosts running older .NET versions where TLS negotiation defaults are insufficient for GitHub.

---

## Downstream Usage

**Feed into a SIEM (Splunk example):**
```powershell
# Generate report
.\CTI-ATTACKCollector.ps1 -ActorName 'APT29' -OutputPath .\apt29.json

# The JSON is ready for Splunk's | inputlookup or a KV store push
```

**Feed into Phoenix CTI Forge:**  
The JSON output schema is compatible with Phoenix CTI Forge's import format. Drop the file into the Forge's import panel for interactive hypothesis triage and detection rule generation.


**Pin to a specific ATT&CK version:**
```powershell
# ATT&CK v14 bundle (example — check MITRE CTI GitHub for available tags)
$v14 = 'https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v14.0/enterprise-attack/enterprise-attack.json'
.\CTI-ATTACKCollector.ps1 -ActorName 'Lazarus' -BundleUrl $v14 -CachePath ''
```

---

## Strict Mode Notes

The script runs under `Set-StrictMode -Version Latest`. STIX objects are sparse — optional properties (`revoked`, `x_mitre_deprecated`, `aliases`, `description`, `kill_chain_phases`, etc.) may be absent on individual objects. Every optional property access is guarded with a `PSObject.Properties.Name -contains` existence check before the property is touched. This prevents `PropertyNotFoundException` on partial STIX records and is the only pattern that is safe under strict mode with `ConvertFrom-Json` output.

```powershell
# Pattern used throughout — the only strict-mode-safe approach
if ($obj.PSObject.Properties.Name -contains 'propertyName') {
    if ($null -ne $obj.propertyName) {
        # safe to use here
    }
}
```

## Licence

MIT. Use freely. Attribution appreciated but not required.

---

## Related Work

- [MITRE ATT&CK](https://attack.mitre.org) — the framework this tool is built on
- [MITRE CTI GitHub](https://github.com/mitre/cti) — the STIX bundle source
