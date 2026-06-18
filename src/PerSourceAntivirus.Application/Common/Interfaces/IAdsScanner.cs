namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAdsScanner
{
    IReadOnlyList<AdsStreamData> ScanStreams(string filePath);
}

public record AdsStreamData(string StreamName, long StreamSize, bool IsSuspicious, string Reason);
