using System.Management;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Threading.Channels;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Process;

[SupportedOSPlatform("windows")]
public class WmiProcessMonitor : IProcessMonitor
{
    private static readonly HashSet<string> SuspiciousParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "iexplore.exe", "chrome.exe", "firefox.exe", "msedge.exe",
        "acrord32.exe", "acrobat.exe"
    };

    private static readonly HashSet<string> SuspiciousChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
        "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
        "certutil.exe", "bitsadmin.exe"
    };

    public async IAsyncEnumerable<ProcessEventData> WatchAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var channel = Channel.CreateUnbounded<ProcessEventData>();
        cancellationToken.Register(() => channel.Writer.TryComplete());

        ManagementEventWatcher? watcher = null;
        try
        {
            watcher = new ManagementEventWatcher(
                "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");

            watcher.EventArrived += (_, e) =>
            {
                try
                {
                    var process = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                    var name = (string)(process["Name"] ?? "");
                    var pid = Convert.ToInt32(process["ProcessId"]);
                    var parentPid = Convert.ToInt32(process["ParentProcessId"]);
                    var cmdLine = (string)(process["CommandLine"] ?? "");

                    var parentName = GetProcessNameById(parentPid);
                    var isSuspicious = SuspiciousChildren.Contains(name) && SuspiciousParents.Contains(parentName);
                    var reason = isSuspicious ? $"{parentName} spawned {name}" : null;

                    channel.Writer.TryWrite(new ProcessEventData(pid, name, parentPid, parentName, cmdLine, isSuspicious, reason));
                }
                catch { }
            };

            watcher.Start();

            await foreach (var ev in channel.Reader.ReadAllAsync(cancellationToken))
            {
                yield return ev;
            }
        }
        finally
        {
            try { watcher?.Stop(); } catch { }
            watcher?.Dispose();
        }
    }

    private static string GetProcessNameById(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT Name FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject obj in searcher.Get())
                return (string)(obj["Name"] ?? "");
        }
        catch { }
        return string.Empty;
    }
}
