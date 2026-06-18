namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IRunningProcessProvider
{
    IReadOnlyList<RunningProcessSnapshot> GetSnapshot();
}

public record RunningProcessSnapshot(int ProcessId, string ProcessName, string? ExecutablePath);
