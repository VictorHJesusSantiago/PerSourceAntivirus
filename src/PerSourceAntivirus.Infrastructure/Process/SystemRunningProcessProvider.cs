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
                // MainModule access requires SeDebugPrivilege for some system processes;
                // catch any exception and continue rather than skipping the entire snapshot.
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
