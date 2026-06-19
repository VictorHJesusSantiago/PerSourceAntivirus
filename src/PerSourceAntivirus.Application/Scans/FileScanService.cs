using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Application.Scans;

public class FileScanService(
    IFileHashCalculator hashCalculator,
    IYaraScanner yaraScanner,
    IPeAnalyzer peAnalyzer,
    IScriptAnalyzer scriptAnalyzer,
    IExclusionList exclusionList,
    IScannedFileRepository repository,
    IHashReputationService reputationService,
    IFileMetadataAnalyzer metadataAnalyzer,
    IOfficeMacroAnalyzer macroAnalyzer,
    IAdsScanner? adsScanner = null,
    IArchiveScanner? archiveScanner = null,
    IPdfScanner? pdfScanner = null,
    IEmailScanner? emailScanner = null,
    ISteganographyDetector? steganographyDetector = null)
{
    /// <summary>
    /// Pure analysis — no DB write. Thread-safe: can be called concurrently for different files.
    /// Returns null if the file is excluded, whitelisted, unchanged (incremental), or unreadable.
    /// </summary>
    public async Task<ScannedFile?> AnalyzeFileAsync(
        string filePath,
        IReadOnlyDictionary<string, string>? existingHashes = null,
        CancellationToken cancellationToken = default)
    {
        if (exclusionList.IsExcludedFile(filePath))
        {
            return null;
        }

        FileHashResult hashResult;
        try
        {
            hashResult = await hashCalculator.ComputeAsync(filePath, cancellationToken);
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }

        // Incremental: skip file if hash hasn't changed since last scan.
        if (existingHashes is not null &&
            existingHashes.TryGetValue(filePath, out var knownHash) &&
            knownHash == hashResult.Sha256Hash)
        {
            return null;
        }

        // Trusted hash: persist as Clean without further analysis.
        if (exclusionList.IsWhitelistedHash(hashResult.Sha256Hash))
        {
            return new ScannedFile
            {
                Id = Guid.NewGuid(),
                FilePath = filePath,
                FileName = Path.GetFileName(filePath),
                SizeBytes = hashResult.SizeBytes,
                Sha256Hash = hashResult.Sha256Hash,
                Entropy = hashResult.Entropy,
                ScannedAtUtc = DateTime.UtcNow,
                ThreatStatus = ThreatStatus.Clean
            };
        }

        var yaraMatches    = yaraScanner.ScanFile(filePath);
        var peData         = peAnalyzer.Analyze(filePath);
        var scriptData     = scriptAnalyzer.Analyze(filePath);
        var metadataData   = metadataAnalyzer.Analyze(filePath);
        var macroData      = macroAnalyzer.Analyze(filePath);
        var reputationData = await reputationService.CheckAsync(hashResult.Sha256Hash, cancellationToken);

        var scannedFile = new ScannedFile
        {
            Id = Guid.NewGuid(),
            FilePath = filePath,
            FileName = Path.GetFileName(filePath),
            SizeBytes = hashResult.SizeBytes,
            Sha256Hash = hashResult.Sha256Hash,
            Entropy = hashResult.Entropy,
            ScannedAtUtc = DateTime.UtcNow,
            ThreatStatus = DetermineThreatStatus(yaraMatches, peData, scriptData, reputationData, metadataData, macroData)
        };

        scannedFile.YaraMatches = yaraMatches
            .Select(m => new YaraMatch
            {
                Id = Guid.NewGuid(),
                ScannedFileId = scannedFile.Id,
                RuleIdentifier = m.RuleIdentifier,
                Tags = string.Join(",", m.Tags)
            })
            .ToList();

        if (peData is not null)
        {
            scannedFile.PeAnalysis = new PeAnalysisResult
            {
                Id = Guid.NewGuid(),
                ScannedFileId = scannedFile.Id,
                Is64Bit = peData.Is64Bit,
                IsDll = peData.IsDll,
                IsDotNet = peData.IsDotNet,
                IsSigned = peData.IsSigned,
                SuspiciousImports = string.Join(",", peData.SuspiciousImports),
                Anomalies = string.Join(",", peData.Anomalies),
                Sections = peData.Sections
                    .Select(s => new PeSection
                    {
                        Id = Guid.NewGuid(),
                        Name = s.Name,
                        SizeOfRawData = s.SizeOfRawData,
                        Entropy = s.Entropy
                    })
                    .ToList()
            };
        }

        if (scriptData is not null)
        {
            scannedFile.ScriptAnalysis = new ScriptAnalysisResult
            {
                Id = Guid.NewGuid(),
                ScannedFileId = scannedFile.Id,
                ScriptType = scriptData.ScriptType,
                HasObfuscation = scriptData.HasObfuscation,
                HasNetworkAccess = scriptData.HasNetworkAccess,
                HasProcessExecution = scriptData.HasProcessExecution,
                HasFileSystemAccess = scriptData.HasFileSystemAccess,
                SuspiciousPatterns = string.Join(",", scriptData.SuspiciousPatterns)
            };
        }

        if (reputationData is not null)
        {
            scannedFile.HashReputation = new HashReputationResult
            {
                Id = Guid.NewGuid(),
                ScannedFileId = scannedFile.Id,
                PositiveDetections = reputationData.PositiveDetections,
                TotalEngines = reputationData.TotalEngines,
                IsMalicious = reputationData.IsMalicious,
                Source = reputationData.Source,
                ReportUrl = reputationData.ReportUrl,
                CheckedAtUtc = DateTime.UtcNow
            };
        }

        if (metadataData is not null)
        {
            scannedFile.FileMetadata = new FileMetadataAnalysisResult
            {
                Id = Guid.NewGuid(),
                ScannedFileId = scannedFile.Id,
                Author = metadataData.Author,
                Creator = metadataData.Creator,
                DocumentCreatedUtc = metadataData.DocumentCreatedUtc,
                DocumentModifiedUtc = metadataData.DocumentModifiedUtc,
                HasEmbeddedFiles = metadataData.HasEmbeddedFiles,
                HasJavaScript = metadataData.HasJavaScript,
                IsPolyglot = metadataData.IsPolyglot,
                Anomalies = string.Join(",", metadataData.Anomalies)
            };
        }

        if (macroData is not null)
        {
            scannedFile.OfficeMacro = new OfficeMacroAnalysisResult
            {
                Id = Guid.NewGuid(),
                ScannedFileId = scannedFile.Id,
                HasMacros = macroData.HasMacros,
                HasAutoExec = macroData.HasAutoExec,
                HasNetworkAccess = macroData.HasNetworkAccess,
                HasProcessExecution = macroData.HasProcessExecution,
                HasObfuscation = macroData.HasObfuscation,
                SuspiciousPatterns = string.Join(",", macroData.SuspiciousPatterns)
            };
        }

        // ADS scanning (Windows NTFS only)
        if (adsScanner != null)
        {
            var streams = adsScanner.ScanStreams(filePath);
            if (streams.Count > 0)
            {
                // If any suspicious ADS found, elevate threat status
                if (streams.Any(s => s.IsSuspicious) && scannedFile.ThreatStatus == ThreatStatus.Clean)
                    scannedFile.ThreatStatus = ThreatStatus.Suspicious;
            }
        }

        // Archive scanning
        if (archiveScanner?.CanScan(filePath) == true)
        {
            var archiveSummary = await archiveScanner.ScanAsync(filePath, cancellationToken);
            if (archiveSummary.HasZipBomb || archiveSummary.SuspiciousEntries > 0)
            {
                if (scannedFile.ThreatStatus == ThreatStatus.Clean)
                    scannedFile.ThreatStatus = ThreatStatus.Suspicious;
            }
        }

        // PDF scanning
        if (pdfScanner?.CanScan(filePath) == true)
        {
            var pdfData = pdfScanner.Scan(filePath);
            if (pdfData?.RiskScore >= 3 && scannedFile.ThreatStatus == ThreatStatus.Clean)
                scannedFile.ThreatStatus = ThreatStatus.Suspicious;
            if (pdfData?.RiskScore >= 6)
                scannedFile.ThreatStatus = ThreatStatus.Malicious;
        }

        // Email scanning
        if (emailScanner?.CanScan(filePath) == true)
        {
            var emailData = emailScanner.Scan(filePath);
            if (emailData?.RiskScore >= 4 && scannedFile.ThreatStatus == ThreatStatus.Clean)
                scannedFile.ThreatStatus = ThreatStatus.Suspicious;
        }

        // Steganography detection
        if (steganographyDetector?.CanAnalyze(filePath) == true)
        {
            var stegoData = steganographyDetector.Analyze(filePath);
            if (stegoData?.IsSuspicious == true && scannedFile.ThreatStatus == ThreatStatus.Clean)
                scannedFile.ThreatStatus = ThreatStatus.Suspicious;
        }

        return scannedFile;
    }

    /// <summary>
    /// Loads existing path→hash map for incremental scanning. Must be called before the parallel loop.
    /// </summary>
    public Task<IReadOnlyDictionary<string, string>> GetExistingHashesAsync(
        IEnumerable<string> filePaths,
        CancellationToken cancellationToken = default)
        => repository.GetExistingHashesAsync(filePaths, cancellationToken);

    /// <summary>
    /// Persist a previously analyzed file. Must be called from a single thread (DbContext is not thread-safe).
    /// </summary>
    public async Task PersistAsync(ScannedFile scannedFile, CancellationToken cancellationToken = default)
    {
        await repository.AddAsync(scannedFile, cancellationToken);
    }

    /// <summary>
    /// Convenience method: analyze + persist in one call (used by the watch command).
    /// </summary>
    public async Task<ScannedFile?> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        var scannedFile = await AnalyzeFileAsync(filePath, cancellationToken: cancellationToken);
        if (scannedFile is not null)
        {
            await PersistAsync(scannedFile, cancellationToken);
        }

        return scannedFile;
    }

    private static ThreatStatus DetermineThreatStatus(
        IReadOnlyList<YaraRuleMatch> yaraMatches,
        PeAnalysisData? peData,
        ScriptAnalysisData? scriptData,
        HashReputationData? reputationData,
        FileMetadataData? metadataData,
        OfficeMacroData? macroData)
    {
        // Malicious: reputation confirmed OR YARA rule tagged malicious
        if (reputationData?.IsMalicious == true || yaraMatches.Any(m => m.Tags.Contains("malicious")))
            return ThreatStatus.Malicious;

        // Malicious: macro with auto-exec that also downloads or spawns processes
        if (macroData is { HasMacros: true, HasAutoExec: true } &&
            (macroData.HasNetworkAccess || macroData.HasProcessExecution))
            return ThreatStatus.Malicious;

        // Suspicious: any lower-confidence indicator
        if (yaraMatches.Count > 0 ||
            (peData?.Anomalies.Count ?? 0) > 0 ||
            (scriptData?.SuspiciousPatterns.Count ?? 0) > 0 ||
            (reputationData?.PositiveDetections ?? 0) > 0 ||
            metadataData?.IsPolyglot == true ||
            (metadataData?.Anomalies.Count ?? 0) >= 2 ||
            (macroData is { HasMacros: true } &&
                (macroData.HasAutoExec || macroData.HasObfuscation ||
                 macroData.HasNetworkAccess || macroData.HasProcessExecution)))
        {
            return ThreatStatus.Suspicious;
        }

        return ThreatStatus.Clean;
    }
}
