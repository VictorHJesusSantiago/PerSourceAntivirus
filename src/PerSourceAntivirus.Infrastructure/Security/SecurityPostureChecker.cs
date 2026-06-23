using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Security;

[SupportedOSPlatform("windows")]
public sealed class SecurityPostureChecker : ISecurityPostureChecker
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFirmwareEnvironmentVariable(
        string lpName, string lpGuid, IntPtr pBuffer, uint nSize);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserGetInfo(
        string servername, string username, int level, out IntPtr bufptr);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct USER_INFO_1
    {
        public string usri1_name;
        public string usri1_password;
        public uint usri1_password_age;
        public uint usri1_priv;
        public string usri1_home_dir;
        public string usri1_comment;
        public uint usri1_flags;
        public string usri1_script_path;
    }

    private const uint UF_ACCOUNTDISABLE = 0x0002;

    public Task<IReadOnlyList<SecurityPostureIssue>> RunChecksAsync(CancellationToken ct)
    {
        var issues = new List<SecurityPostureIssue>();

        TryCheck(() => CheckRegistryDword(
            RegistryHive.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA", 1,
            "UAC Disabled", "User Account Control (UAC) is disabled or not configured.",
            "Authentication", 9), issues);

        TryCheck(() => CheckRegistryDword(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1", 0,
            "SMBv1 Enabled", "SMBv1 is enabled. It is a legacy protocol vulnerable to EternalBlue and similar exploits.",
            "Network", 8), issues);

        TryCheck(() => CheckRegistryDword(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "UserAuthentication", 1,
            "RDP NLA Disabled", "RDP Network Level Authentication (NLA) is not enforced.",
            "RemoteAccess", 7), issues);

        TryCheck(() => CheckRegistryDword(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
            "EnableFirewall", 1,
            "Firewall Domain Profile Disabled", "Windows Firewall is disabled for the Domain profile.",
            "Firewall", 8), issues);

        TryCheck(() => CheckRegistryDword(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
            "EnableFirewall", 1,
            "Firewall Private Profile Disabled", "Windows Firewall is disabled for the Private/Standard profile.",
            "Firewall", 8), issues);

        TryCheck(() => CheckRegistryDword(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
            "EnableFirewall", 1,
            "Firewall Public Profile Disabled", "Windows Firewall is disabled for the Public profile.",
            "Firewall", 9), issues);

        TryCheck(() => CheckAutoplay(), issues);

        TryCheck(() => CheckRegistryDwordRange(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Lsa",
            "RunAsPPL", [1, 2],
            "LSA Protection Disabled", "LSA Protection (RunAsPPL) is not enabled. LSASS is vulnerable to credential theft.",
            "LSA", 8), issues);

        TryCheck(() => CheckCredentialGuard(), issues);
        TryCheck(() => CheckSecureBoot(), issues);
        TryCheck(() => CheckLocalAdminAccount(), issues);
        TryCheck(() => CheckAuditPolicy(), issues);

        return Task.FromResult<IReadOnlyList<SecurityPostureIssue>>(issues);
    }

    private static void TryCheck(Func<SecurityPostureIssue?> check, List<SecurityPostureIssue> issues)
    {
        try
        {
            var issue = check();
            if (issue != null)
                issues.Add(issue);
        }
        catch { }
    }

    private static SecurityPostureIssue? CheckRegistryDword(
        RegistryHive hive, string subKey, string valueName, int expectedValue,
        string checkName, string description, string category, int severity)
    {
        using var key = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64)
            .OpenSubKey(subKey);

        int currentValue = -1;
        if (key != null)
        {
            var raw = key.GetValue(valueName);
            if (raw is int i) currentValue = i;
        }

        if (currentValue == expectedValue)
            return null;

        return new SecurityPostureIssue
        {
            Id = Guid.NewGuid(),
            CheckName = checkName,
            CurrentValue = currentValue == -1 ? "not set" : currentValue.ToString(),
            ExpectedValue = expectedValue.ToString(),
            IssueDescription = description,
            Category = category,
            Severity = severity,
            CheckedAtUtc = DateTime.UtcNow
        };
    }

    private static SecurityPostureIssue? CheckRegistryDwordRange(
        RegistryHive hive, string subKey, string valueName, int[] acceptedValues,
        string checkName, string description, string category, int severity)
    {
        using var key = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64)
            .OpenSubKey(subKey);

        int currentValue = -1;
        if (key != null)
        {
            var raw = key.GetValue(valueName);
            if (raw is int i) currentValue = i;
        }

        if (acceptedValues.Contains(currentValue))
            return null;

        return new SecurityPostureIssue
        {
            Id = Guid.NewGuid(),
            CheckName = checkName,
            CurrentValue = currentValue == -1 ? "not set" : currentValue.ToString(),
            ExpectedValue = string.Join(" or ", acceptedValues),
            IssueDescription = description,
            Category = category,
            Severity = severity,
            CheckedAtUtc = DateTime.UtcNow
        };
    }

    private static SecurityPostureIssue? CheckAutoplay()
    {
        using var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
            .OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer");

        int currentValue = -1;
        if (key != null)
        {
            var raw = key.GetValue("NoDriveTypeAutoRun");
            if (raw is int i) currentValue = i;
        }

        if (currentValue == 0xFF || currentValue == 255)
            return null;

        return new SecurityPostureIssue
        {
            Id = Guid.NewGuid(),
            CheckName = "Autoplay Not Fully Disabled",
            CurrentValue = currentValue == -1 ? "not set" : $"0x{currentValue:X2}",
            ExpectedValue = "0xFF (255)",
            IssueDescription = "Autoplay is not fully disabled. Setting NoDriveTypeAutoRun=0xFF disables it for all drive types.",
            Category = "Autoplay",
            Severity = 6,
            CheckedAtUtc = DateTime.UtcNow
        };
    }

    private static SecurityPostureIssue? CheckCredentialGuard()
    {
        using var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
            .OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard");

        int vbs = -1;
        int lsaCfg = -1;

        if (key != null)
        {
            var rawVbs = key.GetValue("EnableVirtualizationBasedSecurity");
            if (rawVbs is int iv) vbs = iv;

            var rawLsa = key.GetValue("LsaCfgFlags");
            if (rawLsa is int il) lsaCfg = il;
        }

        if (vbs == 1 && lsaCfg == 1)
            return null;

        return new SecurityPostureIssue
        {
            Id = Guid.NewGuid(),
            CheckName = "Credential Guard Disabled",
            CurrentValue = $"VBS={vbs}, LsaCfgFlags={lsaCfg}",
            ExpectedValue = "VBS=1, LsaCfgFlags=1",
            IssueDescription = "Credential Guard is not enabled. Virtualization-based security for LSA credentials is not active.",
            Category = "CredentialGuard",
            Severity = 6,
            CheckedAtUtc = DateTime.UtcNow
        };
    }

    private static SecurityPostureIssue? CheckSecureBoot()
    {
        try
        {
            var buf = Marshal.AllocHGlobal(4);
            try
            {
                var ret = GetFirmwareEnvironmentVariable(
                    "SecureBoot",
                    "{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
                    buf, 1);

                if (ret == 0)
                    return null;

                var value = Marshal.ReadByte(buf);
                if (value == 1)
                    return null;

                return new SecurityPostureIssue
                {
                    Id = Guid.NewGuid(),
                    CheckName = "Secure Boot Disabled",
                    CurrentValue = value.ToString(),
                    ExpectedValue = "1",
                    IssueDescription = "Secure Boot is disabled. The system does not verify boot loader integrity at startup.",
                    Category = "SecureBoot",
                    Severity = 7,
                    CheckedAtUtc = DateTime.UtcNow
                };
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        catch
        {
            return null;
        }
    }

    private static SecurityPostureIssue? CheckLocalAdminAccount()
    {
        var result = NetUserGetInfo(null!, "Administrator", 1, out var bufPtr);
        if (result != 0)
            return null;

        try
        {
            var info = Marshal.PtrToStructure<USER_INFO_1>(bufPtr);
            bool disabled = (info.usri1_flags & UF_ACCOUNTDISABLE) != 0;

            if (disabled)
                return null;

            return new SecurityPostureIssue
            {
                Id = Guid.NewGuid(),
                CheckName = "Built-in Administrator Account Enabled",
                CurrentValue = "Enabled",
                ExpectedValue = "Disabled or renamed",
                IssueDescription = "The built-in Administrator account is enabled. It should be disabled or renamed to reduce attack surface.",
                Category = "UserAccounts",
                Severity = 6,
                CheckedAtUtc = DateTime.UtcNow
            };
        }
        finally
        {
            NetApiBufferFree(bufPtr);
        }
    }

    private static SecurityPostureIssue? CheckAuditPolicy()
    {
        try
        {
            var securityLog = EventLog.GetEventLogs()
                .FirstOrDefault(l => l.Log.Equals("Security", StringComparison.OrdinalIgnoreCase));

            if (securityLog == null)
            {
                return new SecurityPostureIssue
                {
                    Id = Guid.NewGuid(),
                    CheckName = "Security Audit Log Unavailable",
                    CurrentValue = "Not found",
                    ExpectedValue = "Present with recent entries",
                    IssueDescription = "The Security event log could not be accessed. Audit logging may be disabled or inaccessible.",
                    Category = "Auditing",
                    Severity = 5,
                    CheckedAtUtc = DateTime.UtcNow
                };
            }

            var recentCutoff = DateTime.Now.AddDays(-1);
            var entries = securityLog.Entries;
            bool hasRecentEntries = false;

            for (int i = Math.Max(0, entries.Count - 100); i < entries.Count; i++)
            {
                try
                {
                    if (entries[i].TimeGenerated >= recentCutoff)
                    {
                        hasRecentEntries = true;
                        break;
                    }
                }
                catch { }
            }

            securityLog.Dispose();

            if (hasRecentEntries)
                return null;

            return new SecurityPostureIssue
            {
                Id = Guid.NewGuid(),
                CheckName = "No Recent Security Audit Events",
                CurrentValue = "No recent entries",
                ExpectedValue = "Recent audit events present",
                IssueDescription = "No security audit events found in the last 24 hours. Audit policy may be misconfigured.",
                Category = "Auditing",
                Severity = 5,
                CheckedAtUtc = DateTime.UtcNow
            };
        }
        catch
        {
            return null;
        }
    }
}
