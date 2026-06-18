namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ICpuEmulator
{
    Task<EmulationSummary> EmulateAsync(string filePath, byte[] code, int maxInstructions = 10_000, CancellationToken ct = default);
}

public record EmulationSummary(
    int InstructionCount,
    int ApiCallsIntercepted,
    bool IsSuspicious,
    IReadOnlyList<string> DetectedPatterns);
