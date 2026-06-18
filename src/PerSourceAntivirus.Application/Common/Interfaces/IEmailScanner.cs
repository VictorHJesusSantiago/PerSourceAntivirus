namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IEmailScanner
{
    bool CanScan(string filePath);
    EmailScanData? Scan(string filePath);
}

public record EmailScanData(
    int AttachmentCount,
    int SuspiciousAttachmentCount,
    int PhishingLinkCount,
    IReadOnlyList<string> SuspiciousAttachmentNames,
    IReadOnlyList<string> PhishingIndicators,
    bool HasSpoofedSender,
    int RiskScore);
