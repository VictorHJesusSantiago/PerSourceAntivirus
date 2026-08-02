namespace PerSourceAntivirus.Infrastructure.Detection.Heuristics;

// Pure path-based decision logic shared by DllHijackDetector and UnsignedBinaryDetector.
//
// Both detectors' real judgement is "is this path where it should be?", which is string
// comparison — no P/Invoke needed to test it, and getting it wrong means either missing a
// hijack or flooding the operator with false positives on legitimate system DLLs.
public static class ModuleLocationHeuristics
{
    // DLLs that Windows resolves from System32; a copy loaded from anywhere else is the classic
    // search-order hijack / planted-DLL pattern.
    public static readonly IReadOnlySet<string> KnownSystemDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "kernel32.dll", "user32.dll", "advapi32.dll", "ole32.dll", "oleaut32.dll",
        "comctl32.dll", "shell32.dll", "gdi32.dll", "ws2_32.dll", "version.dll",
        "dwmapi.dll", "uxtheme.dll", "winmm.dll", "propsys.dll", "dbghelp.dll",
        "imm32.dll", "ntdll.dll", "msvcrt.dll", "crypt32.dll", "wininet.dll",
        "urlmon.dll", "secur32.dll", "shlwapi.dll", "setupapi.dll", "winhttp.dll",
        "netapi32.dll", "userenv.dll", "cryptsp.dll", "profapi.dll", "dnsapi.dll"
    };

    public static bool IsKnownSystemDll(string moduleName) => KnownSystemDlls.Contains(moduleName);

    // A trusted location is System32, SysWOW64 or the WinSxS side-by-side store. Comparison is
    // case-insensitive and prefix-based because callers pass full module paths.
    public static bool IsTrustedSystemDirectory(string directory, IReadOnlyCollection<string> trustedDirectories)
    {
        if (string.IsNullOrEmpty(directory)) return false;
        return trustedDirectories.Any(trusted =>
            trusted.Length > 0 && directory.StartsWith(trusted, StringComparison.OrdinalIgnoreCase));
    }

    // True when a known system DLL name is loaded from outside the trusted directories.
    public static bool IsSearchOrderHijack(
        string moduleName, string moduleDirectory, IReadOnlyCollection<string> trustedDirectories)
        => IsKnownSystemDll(moduleName) && !IsTrustedSystemDirectory(moduleDirectory, trustedDirectories);

    // Locations malware commonly drops executables into. Used to decide whether an unsigned
    // binary is worth alerting on — unsigned software under Program Files is unremarkable.
    public static bool IsSuspiciousExecutableLocation(
        string filePath, IReadOnlyCollection<string> suspiciousDirectories)
    {
        if (string.IsNullOrEmpty(filePath)) return false;
        return suspiciousDirectories.Any(dir =>
            dir.Length > 0 && filePath.StartsWith(dir, StringComparison.OrdinalIgnoreCase));
    }
}
