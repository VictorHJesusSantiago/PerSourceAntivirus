using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.LolBin;

// TODO: Register in DependencyInjection.cs as: services.AddSingleton<ILolBinDetector, LolBinDetector>();
public sealed class LolBinDetector : ILolBinDetector
{
    private static readonly LolBinEntry[] KnownLolBins =
    [
        new("certutil.exe", "Certificate utility used for download/decode", "T1105",
            ["-urlcache", "-split", "-decode", "http://", "https://", "ftp://"]),
        new("mshta.exe", "HTML Application host used to execute scripts", "T1218.005",
            ["javascript:", "vbscript:", "http://", "https://", ".hta"]),
        new("regsvr32.exe", "Register COM servers, can exec remote scripts", "T1218.010",
            ["/s", "/n", "/i:", "scrobj.dll", "http://", "https://"]),
        new("rundll32.exe", "Run DLLs, often abused for shellcode", "T1218.011",
            ["javascript:", "vbscript:", "shell32.dll,ShellExec_RunDLL", "advpack.dll,LaunchINFSection"]),
        new("wmic.exe", "WMI command line, can exec processes remotely", "T1047",
            ["process call create", "os get", "/node:", "shadowcopy delete"]),
        new("bitsadmin.exe", "Background Intelligent Transfer, used for download", "T1197",
            ["/transfer", "/download", "/addfile", "http://", "https://"]),
        new("msiexec.exe", "Windows Installer, can install from remote URL", "T1218.007",
            ["/i", "/y", "/z", "http://", "https://", "/q", "/quiet"]),
        new("installutil.exe", ".NET installer utility, can run arbitrary code", "T1218.004",
            ["/logfile=", "/logtoconsole=", "/u "]),
        new("cmstp.exe", "Microsoft Connection Manager Profile Installer", "T1218.003",
            ["/ni", "/s", ".inf", "http://", "https://"]),
        new("pcalua.exe", "Program Compatibility Assistant, can execute files", "T1218",
            ["-a ", "-c ", "http://", "https://"]),
        new("odbcconf.exe", "ODBC configuration tool, can load arbitrary DLLs", "T1218.008",
            ["/s", "/a", "REGSVR", ".dll"]),
        new("wscript.exe", "Windows Script Host", "T1059.005",
            ["http://", "https://", "//e:vbscript", "//e:javascript", ".vbs", ".js"]),
        new("cscript.exe", "Windows Script Host (console)", "T1059.005",
            ["http://", "https://", "//e:vbscript", "//e:javascript"]),
        new("powershell.exe", "PowerShell, often abused for download/exec", "T1059.001",
            ["-enc", "-encodedcommand", "-nop", "-noprofile", "-windowstyle hidden", "iex", "invoke-expression", "downloadstring", "webclient"]),
        new("cmd.exe", "Command shell, used for various LOLBin chains", "T1059.003",
            ["/c certutil", "/c mshta", "/c wscript", "/c cscript", "echo.*|.*cmd"]),
        new("regasm.exe", "Register .NET assembly as COM, can run code", "T1218.009",
            [".dll", "/u ", "http://", "https://"]),
        new("regsvcs.exe", "Register .NET component services", "T1218.009",
            [".dll", "/u "]),
        new("forfiles.exe", "Iterate files and run commands", "T1202",
            ["/m", "/c ", "cmd", "mshta", "powershell"]),
        new("at.exe", "Task scheduler (legacy), can persist malware", "T1053.002",
            ["\\\\", "cmd.exe", "powershell.exe"]),
        new("schtasks.exe", "Task scheduler, commonly used for persistence", "T1053.005",
            ["/create", "/sc", "/tr", "cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"]),
    ];

    // High-risk binaries that get severity 8 when a pattern matches
    private static readonly HashSet<string> HighRiskBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "certutil.exe", "mshta.exe"
    };

    public LolBinDetectionResult? Analyze(string processName, string arguments)
    {
        var entry = KnownLolBins.FirstOrDefault(e =>
            string.Equals(e.Name, processName, StringComparison.OrdinalIgnoreCase));

        if (entry is null)
            return null;

        // Check if any suspicious argument pattern appears in the arguments
        var matchedPattern = entry.SuspiciousArgPatterns.FirstOrDefault(pattern =>
            arguments.Contains(pattern, StringComparison.OrdinalIgnoreCase));

        if (matchedPattern is not null)
        {
            var severity = HighRiskBinaries.Contains(processName) ? 8 : 6;
            return new LolBinDetectionResult(entry.Name, entry.Description, entry.MitreTechnique, severity);
        }

        // Process name matched but no suspicious pattern — low severity monitoring
        return new LolBinDetectionResult(entry.Name, entry.Description, entry.MitreTechnique, 3);
    }

    public IReadOnlyList<LolBinEntry> GetKnownLolBins() => KnownLolBins;
}
