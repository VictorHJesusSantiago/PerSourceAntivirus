using PerSourceAntivirus.Application.Common.Interfaces;
using UglyToad.PdfPig;

namespace PerSourceAntivirus.Infrastructure.Pdf;

public sealed class PdfPigScanner : IPdfScanner
{
    public bool CanScan(string filePath)
        => string.Equals(Path.GetExtension(filePath), ".pdf", StringComparison.OrdinalIgnoreCase);

    public PdfScanData? Scan(string filePath)
    {
        try
        {
            var bytes = System.IO.File.ReadAllBytes(filePath);
            var rawText = System.Text.Encoding.Latin1.GetString(bytes);

            var hasJavaScript = rawText.Contains("/JS", StringComparison.Ordinal)
                             || rawText.Contains("/JavaScript", StringComparison.Ordinal);
            var hasOpenAction = rawText.Contains("/OpenAction", StringComparison.Ordinal);
            var hasLaunchAction = rawText.Contains("/Launch", StringComparison.Ordinal);
            var hasRichMedia = rawText.Contains("/RichMedia", StringComparison.Ordinal);
            var hasXfa = rawText.Contains("/XFA", StringComparison.Ordinal);
            var hasEmbeddedFiles = rawText.Contains("/EmbeddedFile", StringComparison.Ordinal)
                                || rawText.Contains("/EmbeddedFiles", StringComparison.Ordinal);
            var hasObjStm = rawText.Contains("/ObjStm", StringComparison.Ordinal);

            try
            {
                using var doc = PdfDocument.Open(filePath);
                _ = doc.Information;
            }
            catch {  }

            var maliciousTypes = new List<string>();
            if (hasJavaScript) maliciousTypes.Add("JavaScript");
            if (hasOpenAction) maliciousTypes.Add("OpenAction");
            if (hasLaunchAction) maliciousTypes.Add("Launch");
            if (hasRichMedia) maliciousTypes.Add("RichMedia");
            if (hasXfa) maliciousTypes.Add("XFA");
            if (hasEmbeddedFiles) maliciousTypes.Add("EmbeddedFiles");
            if (hasObjStm) maliciousTypes.Add("ObjStm");

            int riskScore = 0;
            if (hasJavaScript) riskScore += 3;
            if (hasOpenAction) riskScore += 2;
            if (hasLaunchAction) riskScore += 4;
            if (hasRichMedia) riskScore += 1;
            if (hasXfa) riskScore += 2;
            if (hasEmbeddedFiles) riskScore += 1;
            if (hasObjStm) riskScore += 1;

            return new PdfScanData(
                HasJavaScript: hasJavaScript,
                HasOpenAction: hasOpenAction,
                HasLaunchAction: hasLaunchAction,
                HasRichMedia: hasRichMedia,
                HasXfa: hasXfa,
                HasEmbeddedFiles: hasEmbeddedFiles,
                HasObjStm: hasObjStm,
                MaliciousObjectTypes: maliciousTypes,
                RiskScore: riskScore);
        }
        catch
        {
            return null;
        }
    }
}
