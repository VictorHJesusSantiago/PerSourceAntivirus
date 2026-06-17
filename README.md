# PerSourceAntivirus

Personal antivirus project: scans files, metadata, and network traffic across the system to detect
vulnerabilities, known malware, and suspicious behavior.

## Architecture

Clean Architecture with CQRS (MediatR):

- `PerSourceAntivirus.Domain` — entities and enums (`ScannedFile`, `ThreatStatus`, `YaraMatch`, `PeAnalysisResult`, `ScriptAnalysisResult`, `NetworkConnectionEvent`, …)
- `PerSourceAntivirus.Application` — use cases (commands/queries) and interface abstractions
- `PerSourceAntivirus.Infrastructure` — implementations: SHA-256 + entropy, YARA scanning (dnYara), PE analysis (PeNet), script analysis, network capture (SharpPcap), SQLite persistence (EF Core)
- `PerSourceAntivirus.Cli` — command-line entry point

## CLI Commands

```bash
dotnet build

# Scan all files under <path>: SHA-256, entropy, YARA signatures, PE structure analysis, script analysis
dotnet run --project src/PerSourceAntivirus.Cli -- scan <path>

# List all previously scanned files with threat status, PE flag, script type, YARA hit count
dotnet run --project src/PerSourceAntivirus.Cli -- list

# Move a MALICIOUS/SUSPICIOUS file to the quarantine directory (get the ID from 'list')
dotnet run --project src/PerSourceAntivirus.Cli -- quarantine <file-id>

# Restore a quarantined file to its original path
dotnet run --project src/PerSourceAntivirus.Cli -- restore <file-id>

# Watch a directory in real time — scan every new/modified file automatically
dotnet run --project src/PerSourceAntivirus.Cli -- watch <path>

# Fetch the latest IP blocklist from the configured threat feed and reload in memory
dotnet run --project src/PerSourceAntivirus.Cli -- update-blocklist

# List available network capture devices (requires Npcap)
dotnet run --project src/PerSourceAntivirus.Cli -- devices

# Capture network traffic for N seconds (default 30) and persist connection events
dotnet run --project src/PerSourceAntivirus.Cli -- monitor [--seconds N] [--device NAME]

# List captured connection events
dotnet run --project src/PerSourceAntivirus.Cli -- connections [--blocklisted]
```

Results are stored in `persourceav.db` (SQLite) created in the working directory.

## Threat Detection

`scan` assigns each file one of:

| Status | Condition |
|---|---|
| `MALICIOUS` | YARA match with tag `malicious` |
| `SUSPICIOUS` | Any YARA match (other tag) OR PE anomaly OR suspicious script pattern detected |
| `Clean` | No matches or anomalies |

### YARA Rules (`data/yara-rules/default.yar`)

Bundled starter rules:

- **EICAR_Test_File** — standard EICAR antivirus test string (tag: `malicious`)
- **Suspicious_PowerShell_Download_Execute** — IEX + WebClient download patterns (tag: `suspicious`)
- **Suspicious_Office_Macro_AutoExec** — Office macro auto-run + shell spawn (tag: `suspicious`)
- **Possible_Packed_Executable** — PE section with entropy ≥ 7.5 (tag: `suspicious`)
- **Suspicious_WindowsAPI_ProcessInjection** — Process injection API imports (tag: `suspicious`)

Add your own `.yar` files to `data/yara-rules/` or change the path via `appsettings.json`:

```json
{ "Yara": { "RulesDirectory": "data/yara-rules" } }
```

### Script Analysis

Heuristic analysis for `.ps1`, `.vbs`, `.bat`/`.cmd`, and `.js` files. Detects:

| Flag | Description |
|---|---|
| `HasObfuscation` | Base64 decode, `IEX`/`Invoke-Expression`, `eval()`, `Chr()` encoding |
| `HasNetworkAccess` | `WebClient`/`DownloadString`, `XMLHttpRequest`, `XMLHTTP`, `bitsadmin` |
| `HasProcessExecution` | `Start-Process`, `WScript.Shell`, `Shell.Application`, `net user` |
| `HasFileSystemAccess` | `Get-Content`, `Set-Content`, `FileSystemObject`, `reg add` |

Additional specific patterns: AMSI bypass, execution policy bypass, UAC bypass, credential theft, registry manipulation, scheduled task creation.

### PE Analysis

For `.exe`/`.dll` files, analyzes:
- Architecture (32/64-bit), type (EXE/DLL), managed (.NET), and code-signing status
- Section entropy (≥ 7.5 flags as possibly packed)
- Suspicious imports: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtUnmapViewOfSection`, `SetThreadContext`

### IP Blocklist (`data/ip-blocklist.txt`)

One IP address per line; lines starting with `#` are comments. Use `update-blocklist` to fetch from
a threat intelligence feed, or manually populate the file.

Configure paths and update URL via `appsettings.json`:

```json
{
  "Network": {
    "IpBlocklistFile": "data/ip-blocklist.txt",
    "BlocklistUpdateUrl": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
  }
}
```

### Quarantine

Quarantined files are moved to the `quarantine/` directory (configurable) and renamed with a
`.quarantine` suffix to prevent accidental execution. The original path is recorded in the database.

```json
{ "Quarantine": { "Directory": "quarantine" } }
```

## Network Monitoring

Live packet capture requires **Npcap** (Windows): <https://npcap.com/>

Install Npcap, then use `devices` to list interfaces and `monitor` to start capturing.

## Tests

```bash
dotnet test
```

29 tests covering: SHA-256 + entropy, YARA rule compile/scan, PE analysis on real managed assemblies,
script analysis for PS1/VBS/BAT/JS, file quarantine and restore, FileSystemWatcher real-time detection,
blocklist provider, graceful no-Npcap degradation, and threat-status logic with mocked dependencies.

## Roadmap

- ~~PowerShell/script analysis~~ ✓ implemented
- ~~Real-time file system monitoring and quarantine~~ ✓ implemented
- ~~IP blocklist auto-update from threat intelligence feeds~~ ✓ implemented
- EF Core migrations (currently uses `EnsureCreated`)
- Hash-based reputation lookup (VirusTotal API or local blocklist)
- Parallel file scanning for large directories
- Scheduled / background scans
