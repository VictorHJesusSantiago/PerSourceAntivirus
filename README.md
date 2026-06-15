# PerSourceAntivirus

Personal antivirus project: scans files, metadata and network traffic across the system to find
vulnerabilities, known malware and suspicious behavior.

## Architecture

Clean Architecture with CQRS (MediatR):

- `PerSourceAntivirus.Domain` — entities and enums (e.g. `ScannedFile`, `ThreatStatus`)
- `PerSourceAntivirus.Application` — use cases (commands/queries) and abstractions
- `PerSourceAntivirus.Infrastructure` — implementations: file hashing/entropy, SQLite persistence (EF Core)
- `PerSourceAntivirus.Cli` — command-line entry point

## Running

```bash
dotnet build
dotnet run --project src/PerSourceAntivirus.Cli -- scan <path>
dotnet run --project src/PerSourceAntivirus.Cli -- list
```

`scan <path>` recursively hashes (SHA-256) and computes the Shannon entropy of every file under
`<path>`, storing results in a local SQLite database (`persourceav.db`). `list` prints all
previously scanned files.

## Tests

```bash
dotnet test
```

## Roadmap

Planned modules (each added as its own Infrastructure implementation + Application commands):

- YARA-based signature scanning (dnYara)
- PE file structure analysis (PeNet)
- Network traffic monitoring / DNS sinkhole (SharpPcap)
- PowerShell/script analysis
- Real-time file system monitoring and quarantine
