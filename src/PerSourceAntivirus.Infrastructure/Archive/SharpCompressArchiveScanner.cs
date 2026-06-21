using PerSourceAntivirus.Application.Common.Interfaces;
using SharpCompress.Archives;
using SharpCompress.Common;
using SharpCompress.Readers;

namespace PerSourceAntivirus.Infrastructure.Archive;

// TODO: Register in DependencyInjection.cs as: services.AddSingleton<IArchiveScanner, SharpCompressArchiveScanner>();
public sealed class SharpCompressArchiveScanner : IArchiveScanner
{
    private static readonly HashSet<string> SupportedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".cab", ".iso"
    };

    private static readonly HashSet<string> SuspiciousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".cmd", ".scr", ".com", ".pif"
    };

    public bool CanScan(string filePath)
        => SupportedExtensions.Contains(Path.GetExtension(filePath));

    public Task<ArchiveScanSummary> ScanAsync(string filePath, CancellationToken ct = default)
        => ScanInternalAsync(filePath, depth: 0, ct);

    private async Task<ArchiveScanSummary> ScanInternalAsync(string filePath, int depth, CancellationToken ct)
    {
        int totalEntries = 0;
        int suspiciousEntries = 0;
        bool hasZipBomb = false;
        var suspiciousPaths = new List<string>();
        long totalUncompressedSize = 0;

        try
        {
            using var archive = ArchiveFactory.Open(filePath, new ReaderOptions { LookForHeader = true });

            foreach (var entry in archive.Entries)
            {
                ct.ThrowIfCancellationRequested();

                if (entry.IsDirectory) continue;
                if (entry.Size == 0) continue;
                if (totalEntries >= 1000) break;

                totalEntries++;
                totalUncompressedSize += entry.Size;

                // Zip bomb: total uncompressed > 500 MB
                if (totalUncompressedSize > 500_000_000L)
                {
                    hasZipBomb = true;
                }

                // Zip bomb: single entry compression ratio > 100:1
                if (entry.CompressedSize > 0 && entry.Size / entry.CompressedSize > 100)
                {
                    hasZipBomb = true;
                }

                // Skip entries too large to extract (> 50 MB)
                if (entry.Size > 50_000_000L)
                    continue;

                bool isSuspicious = false;
                var entryExtension = Path.GetExtension(entry.Key ?? string.Empty);

                // Suspicious extension check
                if (SuspiciousExtensions.Contains(entryExtension))
                    isSuspicious = true;

                // Extract content for deeper analysis
                try
                {
                    using var ms = new MemoryStream();
                    using var entryStream = entry.OpenEntryStream();
                    await entryStream.CopyToAsync(ms, ct);
                    var bytes = ms.ToArray();

                    // PE header check (MZ)
                    if (bytes.Length >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A)
                        isSuspicious = true;

                    // Entropy check
                    var entropy = ComputeEntropy(bytes);
                    if (entropy > 7.5)
                        isSuspicious = true;

                    // Recursively scan nested archives (up to depth 3)
                    if (depth < 3 && CanScanExtension(entryExtension) && bytes.Length > 0)
                    {
                        var tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + entryExtension);
                        try
                        {
                            await System.IO.File.WriteAllBytesAsync(tempPath, bytes, ct);
                            var nestedResult = await ScanInternalAsync(tempPath, depth + 1, ct);
                            totalEntries += nestedResult.TotalEntries;
                            suspiciousEntries += nestedResult.SuspiciousEntries;
                            suspiciousPaths.AddRange(nestedResult.SuspiciousEntryPaths);
                            if (nestedResult.HasZipBomb) hasZipBomb = true;
                        }
                        finally
                        {
                            try { System.IO.File.Delete(tempPath); } catch { }
                        }
                    }
                }
                catch { }

                if (isSuspicious)
                {
                    suspiciousEntries++;
                    suspiciousPaths.Add(entry.Key ?? string.Empty);
                }
            }
        }
        catch { }

        return new ArchiveScanSummary(totalEntries, suspiciousEntries, hasZipBomb, suspiciousPaths);
    }

    private bool CanScanExtension(string extension)
        => SupportedExtensions.Contains(extension);

    private static double ComputeEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;
        var freq = new int[256];
        foreach (var b in data) freq[b]++;
        double entropy = 0;
        foreach (var f in freq)
        {
            if (f == 0) continue;
            var p = (double)f / data.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
