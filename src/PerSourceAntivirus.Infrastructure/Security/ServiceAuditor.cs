using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Security;

[SupportedOSPlatform("windows")]
public sealed class ServiceAuditor : IServiceAuditor
{
    private static readonly string[] SystemRoots =
    [
        @"C:\Windows\System32\",
        @"C:\Windows\SysWOW64\",
        @"C:\Program Files\",
        @"C:\Program Files (x86)\",
        @"C:\Windows\"
    ];

    private static readonly string[] SuspiciousRoots =
    [
        @"C:\Users\",
        @"C:\Temp\",
        @"C:\Windows\Temp\",
        @"C:\ProgramData\Temp\"
    ];

    public async Task<IReadOnlyList<ServiceAuditFinding>> AuditAsync(CancellationToken ct)
    {
        var results = new List<ServiceAuditFinding>();
        var now = DateTime.UtcNow;

        await Task.Run(() =>
        {
            foreach (var svc in ServiceController.GetServices())
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var imagePath = GetServiceImagePath(svc.ServiceName);
                    if (string.IsNullOrWhiteSpace(imagePath)) continue;

                    var binaryPath = ExtractBinaryPath(imagePath);
                    var isSystem = IsSystemPath(binaryPath);
                    var isUnquoted = HasUnquotedPath(imagePath);
                    var isWritable = !isSystem && IsWritablePath(binaryPath);
                    var isSuspiciousPath = IsSuspiciousRoot(binaryPath);

                    if (!isUnquoted && !isWritable && !isSuspiciousPath) continue;

                    string findingType;
                    int severity;
                    if (isUnquoted && isWritable) { findingType = "UnquotedAndWritable"; severity = 9; }
                    else if (isWritable) { findingType = "WritableBinary"; severity = 8; }
                    else if (isUnquoted) { findingType = "UnquotedPath"; severity = 7; }
                    else { findingType = "SuspiciousPath"; severity = 6; }

                    results.Add(new ServiceAuditFinding
                    {
                        Id = Guid.NewGuid(),
                        ServiceName = svc.ServiceName,
                        ServiceDisplayName = svc.DisplayName,
                        BinaryPath = imagePath,
                        IsUnquotedPath = isUnquoted,
                        IsWritablePath = isWritable,
                        IsSystemService = isSystem,
                        FindingType = findingType,
                        Severity = severity,
                        AuditedAtUtc = now
                    });
                }
                catch { }
                finally { svc.Dispose(); }
            }
        }, ct);

        return results;
    }

    private static string GetServiceImagePath(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
            return key?.GetValue("ImagePath")?.ToString() ?? string.Empty;
        }
        catch { return string.Empty; }
    }

    private static string ExtractBinaryPath(string imagePath)
    {
        var path = imagePath.Trim();
        if (path.StartsWith('"'))
        {
            var end = path.IndexOf('"', 1);
            return end > 0 ? path[1..end] : path.Trim('"');
        }
        var spaceIdx = path.IndexOf(' ');
        if (spaceIdx > 0 && path[..spaceIdx].Contains('.'))
            return path[..spaceIdx];
        return path;
    }

    private static bool HasUnquotedPath(string imagePath)
    {
        var path = imagePath.Trim();
        if (path.StartsWith('"')) return false;
        if (!path.Contains(' ')) return false;
        var exeIdx = path.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx < 0) return false;
        return path[..exeIdx].Contains(' ');
    }

    private static bool IsSystemPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        return SystemRoots.Any(r => path.StartsWith(r, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsSuspiciousRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        return SuspiciousRoots.Any(r => path.StartsWith(r, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsWritablePath(string binaryPath)
    {
        try
        {
            var dir = Path.GetDirectoryName(binaryPath);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return false;

            var acl = new DirectoryInfo(dir).GetAccessControl();
            var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));

            var usersAndEveryone = new[]
            {
                new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null)
            };

            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;
                var sid = rule.IdentityReference as SecurityIdentifier;
                if (sid == null) continue;
                if (!usersAndEveryone.Any(u => u.Equals(sid))) continue;
                if ((rule.FileSystemRights & (FileSystemRights.Write | FileSystemRights.Modify |
                     FileSystemRights.FullControl | FileSystemRights.WriteData)) != 0)
                    return true;
            }
            return false;
        }
        catch { return false; }
    }
}
