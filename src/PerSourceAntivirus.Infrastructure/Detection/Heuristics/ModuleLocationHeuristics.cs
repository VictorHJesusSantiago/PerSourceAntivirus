namespace PerSourceAntivirus.Infrastructure.Detection.Heuristics;

public static class ModuleLocationHeuristics
{
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

    public static bool IsTrustedSystemDirectory(string directory, IReadOnlyCollection<string> trustedDirectories)
    {
        if (string.IsNullOrEmpty(directory)) return false;
        return trustedDirectories.Any(trusted =>
            trusted.Length > 0 && directory.StartsWith(trusted, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsSearchOrderHijack(
        string moduleName, string moduleDirectory, IReadOnlyCollection<string> trustedDirectories)
        => IsKnownSystemDll(moduleName) && !IsTrustedSystemDirectory(moduleDirectory, trustedDirectories);

    public static bool IsSuspiciousExecutableLocation(
        string filePath, IReadOnlyCollection<string> suspiciousDirectories)
    {
        if (string.IsNullOrEmpty(filePath)) return false;
        return suspiciousDirectories.Any(dir =>
            dir.Length > 0 && filePath.StartsWith(dir, StringComparison.OrdinalIgnoreCase));
    }
}
