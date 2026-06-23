using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.SystemIntegration;

[SupportedOSPlatform("windows")]
public sealed class AppLockerIntegration : IAppLockerIntegration
{
    public async Task<AppLockerStatus> GetStatusAsync(CancellationToken ct = default)
    {
        return await Task.Run(() =>
        {
            var isEnabled = false;
            var policyMode = "NotConfigured";
            var enforcedPaths = Array.Empty<string>();
            var isWdacEnabled = false;

            try
            {
                using var srpKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\SrpV2");
                if (srpKey != null)
                {
                    isEnabled = true;
                    var subKeyNames = srpKey.GetSubKeyNames();
                    var modes = new List<string>();
                    var paths = new List<string>();

                    foreach (var subKeyName in subKeyNames)
                    {
                        try
                        {
                            using var subKey = srpKey.OpenSubKey(subKeyName);
                            if (subKey == null) continue;

                            var enforcementMode = subKey.GetValue("EnforcementMode")?.ToString();
                            if (!string.IsNullOrEmpty(enforcementMode))
                                modes.Add($"{subKeyName}={enforcementMode}");

                            foreach (var ruleName in subKey.GetSubKeyNames())
                            {
                                try
                                {
                                    using var ruleKey = subKey.OpenSubKey(ruleName);
                                    if (ruleKey == null) continue;
                                    var conditions = ruleKey.GetValue("Conditions")?.ToString();
                                    if (!string.IsNullOrEmpty(conditions))
                                        paths.Add(conditions);
                                }
                                catch { }
                            }
                        }
                        catch { }
                    }

                    policyMode = modes.Count > 0 ? string.Join("; ", modes) : "Configured";
                    enforcedPaths = paths.ToArray();
                }
            }
            catch { }

            try
            {
                using var ciKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Config");
                if (ciKey != null)
                {
                    var valueNames = ciKey.GetValueNames();
                    isWdacEnabled = valueNames.Any(v =>
                        v.Equals("VerboseHashes", StringComparison.OrdinalIgnoreCase) ||
                        v.Equals("PolicyGuid", StringComparison.OrdinalIgnoreCase));
                }
            }
            catch { }

            return new AppLockerStatus(isEnabled, policyMode, enforcedPaths, isWdacEnabled);
        }, ct);
    }

    public bool IntegrateWithAppWhitelist(IReadOnlyList<AppWhitelistEntry> entries)
    {
        var hashEntries = entries
            .Where(e => e.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase)
                && e.EntryType.Equals("Hash", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (hashEntries.Count == 0)
            return false;

        try
        {
            var xmlSb = new StringBuilder();
            xmlSb.AppendLine("<AppLockerPolicy Version=\"1\">");
            xmlSb.AppendLine("  <RuleCollection Type=\"Exe\" EnforcementMode=\"Enabled\">");

            foreach (var entry in hashEntries)
            {
                var ruleId = Guid.NewGuid().ToString("B").ToUpperInvariant();
                var escapedDesc = System.Security.SecurityElement.Escape(entry.Description) ?? entry.Description;
                var escapedVal = System.Security.SecurityElement.Escape(entry.Value) ?? entry.Value;

                xmlSb.AppendLine($"    <FileHashRule Id=\"{ruleId}\" Name=\"Allow {escapedDesc}\" Description=\"\" UserOrGroupSid=\"S-1-1-0\" Action=\"Allow\">");
                xmlSb.AppendLine("      <Conditions>");
                xmlSb.AppendLine($"        <FileHashCondition>");
                xmlSb.AppendLine($"          <FileHash Type=\"SHA256\" Data=\"{escapedVal}\" SourceFileName=\"{escapedDesc}\" SourceFileLength=\"0\"/>");
                xmlSb.AppendLine("        </FileHashCondition>");
                xmlSb.AppendLine("      </Conditions>");
                xmlSb.AppendLine("    </FileHashRule>");
            }

            xmlSb.AppendLine("  </RuleCollection>");
            xmlSb.AppendLine("</AppLockerPolicy>");

            var tempFile = Path.Combine(Path.GetTempPath(), $"appLocker_{Guid.NewGuid():N}.xml");
            File.WriteAllText(tempFile, xmlSb.ToString(), Encoding.UTF8);

            try
            {
                using var ps = SysProcess.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NonInteractive -Command \"Set-AppLockerPolicy -XMLPolicy '{tempFile}' -Merge\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    Verb = "runas"
                });
                ps?.WaitForExit(10_000);
            }
            catch { }
            finally
            {
                try { File.Delete(tempFile); } catch { }
            }

            return true;
        }
        catch
        {
            return false;
        }
    }
}
