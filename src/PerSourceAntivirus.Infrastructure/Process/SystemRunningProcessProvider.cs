using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Process;

public class SystemRunningProcessProvider : IRunningProcessProvider
{
    public IReadOnlyList<RunningProcessSnapshot> GetSnapshot()
    {
        var results = new List<RunningProcessSnapshot>();

        foreach (var process in System.Diagnostics.Process.GetProcesses())
        {
            string? exePath;
            try
            {
                exePath = process.MainModule?.FileName;
            }
            catch
            {
                exePath = null;
            }

            results.Add(new RunningProcessSnapshot(process.Id, process.ProcessName, exePath));
        }

        return results;
    }
}
