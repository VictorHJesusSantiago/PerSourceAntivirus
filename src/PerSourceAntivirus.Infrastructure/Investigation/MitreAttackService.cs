using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Investigation;

public sealed class MitreAttackService : IMitreAttackService
{
    private static readonly Dictionary<string, MitreAttackMapping> Mappings = new()
    {
        ["ProcessHollowingAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "ProcessHollowingAlert",
            TechniqueId   = "T1055.012",
            TechniqueName = "Process Injection: Process Hollowing",
            Tactic        = "Defense Evasion, Privilege Escalation",
            Description   = "Adversaries hollow out a legitimate process and inject malicious code.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1055/012/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["ReflectiveDllInjectionAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "ReflectiveDllInjectionAlert",
            TechniqueId   = "T1055.001",
            TechniqueName = "Process Injection: Dynamic-link Library Injection",
            Tactic        = "Defense Evasion, Privilege Escalation",
            Description   = "Adversaries inject a DLL into a process to execute malicious code.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1055/001/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["WmiPersistenceAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "WmiPersistenceAlert",
            TechniqueId   = "T1546.003",
            TechniqueName = "Event Triggered Execution: Windows Management Instrumentation Event Subscription",
            Tactic        = "Persistence, Privilege Escalation",
            Description   = "Adversaries abuse WMI event subscriptions to execute malicious code.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1546/003/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["ComHijackAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "ComHijackAlert",
            TechniqueId   = "T1546.015",
            TechniqueName = "Event Triggered Execution: Component Object Model Hijacking",
            Tactic        = "Persistence, Privilege Escalation",
            Description   = "Adversaries hijack COM objects to execute malicious code.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1546/015/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["AutostartEntry"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "AutostartEntry",
            TechniqueId   = "T1053.005",
            TechniqueName = "Scheduled Task/Job: Scheduled Task",
            Tactic        = "Execution, Persistence, Privilege Escalation",
            Description   = "Adversaries abuse scheduled tasks to execute malicious code.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1053/005/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["ProcessDoppelgangingAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "ProcessDoppelgangingAlert",
            TechniqueId   = "T1055.013",
            TechniqueName = "Process Injection: Process Doppelgänging",
            Tactic        = "Defense Evasion, Privilege Escalation",
            Description   = "Adversaries use transactions to load malicious code via doppelgänging.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1055/013/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["AtomBombingAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "AtomBombingAlert",
            TechniqueId   = "T1055.008",
            TechniqueName = "Process Injection: Thread Local Storage",
            Tactic        = "Defense Evasion, Privilege Escalation",
            Description   = "Adversaries inject malicious code via atom tables.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1055/008/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["NtdllUnhookingAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "NtdllUnhookingAlert",
            TechniqueId   = "T1562.001",
            TechniqueName = "Impair Defenses: Disable or Modify Tools",
            Tactic        = "Defense Evasion",
            Description   = "Adversaries unhook ntdll to bypass security monitoring.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1562/001/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["DirectSyscallAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "DirectSyscallAlert",
            TechniqueId   = "T1106",
            TechniqueName = "Native API",
            Tactic        = "Execution",
            Description   = "Adversaries call native OS APIs directly to bypass hooks.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1106/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["KeyloggerDetectionAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "KeyloggerDetectionAlert",
            TechniqueId   = "T1056.001",
            TechniqueName = "Input Capture: Keylogging",
            Tactic        = "Collection, Credential Access",
            Description   = "Adversaries capture keystrokes to obtain credentials and other sensitive data.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1056/001/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["PortScanAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "PortScanAlert",
            TechniqueId   = "T1046",
            TechniqueName = "Network Service Discovery",
            Tactic        = "Discovery",
            Description   = "Adversaries scan for open ports and running network services.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1046/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["SmbLateralMovementAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "SmbLateralMovementAlert",
            TechniqueId   = "T1021.002",
            TechniqueName = "Remote Services: SMB/Windows Admin Shares",
            Tactic        = "Lateral Movement",
            Description   = "Adversaries use SMB and Windows admin shares for lateral movement.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1021/002/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["RansomwareAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "RansomwareAlert",
            TechniqueId   = "T1486",
            TechniqueName = "Data Encrypted for Impact",
            Tactic        = "Impact",
            Description   = "Adversaries encrypt data to interrupt availability and extort payment.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1486/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["ClipboardHijackAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "ClipboardHijackAlert",
            TechniqueId   = "T1185",
            TechniqueName = "Browser Session Hijacking",
            Tactic        = "Collection",
            Description   = "Adversaries hijack browser sessions through clipboard manipulation.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1185/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["MbrWriteAttemptAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "MbrWriteAttemptAlert",
            TechniqueId   = "T1542.003",
            TechniqueName = "Pre-OS Boot: Bootkit",
            Tactic        = "Defense Evasion, Persistence",
            Description   = "Adversaries install bootkits to persist before OS load.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1542/003/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["LolBinAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "LolBinAlert",
            TechniqueId   = "T1218",
            TechniqueName = "System Binary Proxy Execution",
            Tactic        = "Defense Evasion",
            Description   = "Adversaries abuse trusted system binaries to proxy execution.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1218/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["AmsiBypassAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "AmsiBypassAlert",
            TechniqueId   = "T1562.001",
            TechniqueName = "Impair Defenses: Disable or Modify Tools",
            Tactic        = "Defense Evasion",
            Description   = "Adversaries bypass AMSI to prevent detection of malicious scripts.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1562/001/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["DgaAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "DgaAlert",
            TechniqueId   = "T1568.002",
            TechniqueName = "Dynamic Resolution: Domain Generation Algorithms",
            Tactic        = "Command and Control",
            Description   = "Adversaries use DGA to dynamically generate C2 domain names.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1568/002/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["BeaconingAnalysis"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "BeaconingAnalysis",
            TechniqueId   = "T1071",
            TechniqueName = "Application Layer Protocol",
            Tactic        = "Command and Control",
            Description   = "Adversaries use application layer protocols for C2 beaconing.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1071/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
        ["PuaAlert"] = new MitreAttackMapping
        {
            Id            = Guid.NewGuid(),
            AlertType     = "PuaAlert",
            TechniqueId   = "T1496",
            TechniqueName = "Resource Hijacking",
            Tactic        = "Impact",
            Description   = "Adversaries abuse system resources for their own benefit.",
            MitreUrl      = "https://attack.mitre.org/techniques/T1496/",
            CreatedAtUtc  = DateTime.UtcNow,
        },
    };

    public MitreAttackMapping? GetMapping(string alertType)
        => Mappings.TryGetValue(alertType, out var mapping) ? mapping : null;

    public IReadOnlyList<MitreAttackMapping> GetAllMappings()
        => Mappings.Values.ToList();

    public string GetMitreUrl(string techniqueId)
        => $"https://attack.mitre.org/techniques/{techniqueId.Replace(".", "/")}/";
}
