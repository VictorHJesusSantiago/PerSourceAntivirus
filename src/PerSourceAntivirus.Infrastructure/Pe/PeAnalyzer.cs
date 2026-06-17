using PeNet;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Infrastructure.Common;

namespace PerSourceAntivirus.Infrastructure.Pe;

public class PeAnalyzer : IPeAnalyzer
{
    private const double HighEntropyThreshold = 7.5;
    private const int FewImportsThreshold = 5;

    private static readonly string[] SuspiciousApiNames =
    [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "SetThreadContext",
        "QueueUserAPC",
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress"
    ];

    public PeAnalysisData? Analyze(string filePath)
    {
        if (!HasMzHeader(filePath))
        {
            return null;
        }

        PeFile peFile;
        try
        {
            peFile = new PeFile(filePath);
        }
        catch
        {
            return null;
        }

        if (peFile.ImageNtHeaders is null)
        {
            return null;
        }

        var sections = (peFile.ImageSectionHeaders ?? [])
            .Select(section => new PeSectionData(
                section.Name ?? string.Empty,
                section.SizeOfRawData,
                ShannonEntropy.Calculate(section.ToArray())))
            .ToList();

        var suspiciousImports = (peFile.ImportedFunctions ?? [])
            .Where(import => import.Name is not null && SuspiciousApiNames.Contains(import.Name, StringComparer.OrdinalIgnoreCase))
            .Select(import => $"{import.DLL}!{import.Name}")
            .Distinct()
            .ToList();

        var anomalies = new List<string>();
        if (sections.Any(section => section.Entropy >= HighEntropyThreshold))
        {
            anomalies.Add("HighEntropySection");
        }

        if ((peFile.ImportedFunctions?.Length ?? 0) < FewImportsThreshold)
        {
            anomalies.Add("FewImports");
        }

        if (suspiciousImports.Count > 0)
        {
            anomalies.Add("SuspiciousImports");
        }

        return new PeAnalysisData(
            peFile.Is64Bit,
            peFile.IsDll,
            peFile.IsDotNet,
            peFile.IsAuthenticodeSigned,
            sections,
            suspiciousImports,
            anomalies);
    }

    private static bool HasMzHeader(string filePath)
    {
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length < 2)
            {
                return false;
            }

            Span<byte> header = stackalloc byte[2];
            return stream.Read(header) == 2 && header[0] == (byte)'M' && header[1] == (byte)'Z';
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }
}
