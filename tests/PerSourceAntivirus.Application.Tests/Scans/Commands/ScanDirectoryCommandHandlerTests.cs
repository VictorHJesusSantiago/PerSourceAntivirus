using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Scans.Commands.ScanDirectory;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Tests.Scans.Commands;

public class ScanDirectoryCommandHandlerTests
{
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

            var handler = new ScanDirectoryCommandHandler(hashCalculator, repository);

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

            var handler = new ScanDirectoryCommandHandler(hashCalculator, repository);

            var result = await handler.Handle(new ScanDirectoryCommand(rootPath), CancellationToken.None);

            result.FilesScanned.Should().Be(0);
            await repository.DidNotReceive().AddAsync(Arg.Any<ScannedFile>(), Arg.Any<CancellationToken>());
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }
}
