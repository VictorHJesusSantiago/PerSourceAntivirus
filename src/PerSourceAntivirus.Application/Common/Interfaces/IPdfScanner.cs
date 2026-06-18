namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IPdfScanner
{
    bool CanScan(string filePath);
    PdfScanData? Scan(string filePath);
}

public record PdfScanData(
    bool HasJavaScript,
    bool HasOpenAction,
    bool HasLaunchAction,
    bool HasRichMedia,
    bool HasXfa,
    bool HasEmbeddedFiles,
    bool HasObjStm,
    IReadOnlyList<string> MaliciousObjectTypes,
    int RiskScore);
