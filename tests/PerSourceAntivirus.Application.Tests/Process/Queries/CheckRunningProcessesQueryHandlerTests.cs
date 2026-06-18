using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Process.Queries.CheckRunningProcesses;

namespace PerSourceAntivirus.Application.Tests.Process.Queries;

public class CheckRunningProcessesQueryHandlerTests
{
    private static CheckRunningProcessesQueryHandler Build(
        IRunningProcessProvider? provider     = null,
        IFileHashCalculator?     hasher       = null,
        IHashReputationService?  reputation   = null)
    {
        provider   ??= Substitute.For<IRunningProcessProvider>();
        hasher     ??= Substitute.For<IFileHashCalculator>();
        reputation ??= Substitute.For<IHashReputationService>();
        return new CheckRunningProcessesQueryHandler(provider, hasher, reputation);
    }

    [Fact]
    public async Task Handle_ReturnsEmpty_WhenNoProcesses()
    {
        var provider = Substitute.For<IRunningProcessProvider>();
        provider.GetSnapshot().Returns([]);

        var handler = Build(provider);
        var result  = await handler.Handle(new CheckRunningProcessesQuery(), CancellationToken.None);

        result.Should().BeEmpty();
    }

    [Fact]
    public async Task Handle_IncludesProcessesWithNullExePath_AsNotMalicious()
    {
        var provider = Substitute.For<IRunningProcessProvider>();
        provider.GetSnapshot().Returns([new RunningProcessSnapshot(4, "System", null)]);

        var handler = Build(provider);
        var result  = await handler.Handle(new CheckRunningProcessesQuery(), CancellationToken.None);

        result.Should().HaveCount(1);
        result[0].Sha256Hash.Should().BeNull();
        result[0].IsMalicious.Should().BeFalse();
    }

    [Fact]
    public async Task Handle_FlagsMalicious_WhenReputationServiceMatchesHash()
    {
        var exePath = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(exePath, [1, 2, 3]);
            const string badHash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

            var provider = Substitute.For<IRunningProcessProvider>();
            provider.GetSnapshot().Returns([new RunningProcessSnapshot(1234, "evil.exe", exePath)]);

            var hasher = Substitute.For<IFileHashCalculator>();
            hasher.ComputeAsync(exePath, Arg.Any<CancellationToken>())
                  .Returns(new FileHashResult(badHash, 0.0, 3));

            var reputation = Substitute.For<IHashReputationService>();
            reputation.CheckAsync(badHash, Arg.Any<CancellationToken>())
                      .Returns(new HashReputationData(1, 1, true, "LocalList", null));

            var handler = Build(provider, hasher, reputation);
            var result  = await handler.Handle(new CheckRunningProcessesQuery(), CancellationToken.None);

            result.Should().HaveCount(1);
            result[0].IsMalicious.Should().BeTrue();
            result[0].Sha256Hash.Should().Be(badHash);
            result[0].ReputationSource.Should().Be("LocalList");
        }
        finally { File.Delete(exePath); }
    }

    [Fact]
    public async Task Handle_DeduplicatesExePath_OnlyHashesOnce()
    {
        var exePath = "/usr/bin/node";

        var provider = Substitute.For<IRunningProcessProvider>();
        provider.GetSnapshot().Returns([
            new RunningProcessSnapshot(100, "node", exePath),
            new RunningProcessSnapshot(101, "node", exePath),
            new RunningProcessSnapshot(102, "node", exePath),
        ]);

        var hasher = Substitute.For<IFileHashCalculator>();
        hasher.ComputeAsync(exePath, Arg.Any<CancellationToken>())
              .Returns(new FileHashResult("aaa", 0.0, 1));

        var reputation = Substitute.For<IHashReputationService>();
        reputation.CheckAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                  .Returns((HashReputationData?)null);

        var handler = Build(provider, hasher, reputation);
        var result  = await handler.Handle(new CheckRunningProcessesQuery(), CancellationToken.None);

        result.Should().HaveCount(3);
        await hasher.Received(1).ComputeAsync(exePath, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_HandlesMissingFile_Gracefully()
    {
        var provider = Substitute.For<IRunningProcessProvider>();
        provider.GetSnapshot().Returns([new RunningProcessSnapshot(999, "gone.exe", "/nonexistent/path.exe")]);

        var hasher = Substitute.For<IFileHashCalculator>();
        hasher.ComputeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
              .Returns<FileHashResult>(_ => throw new FileNotFoundException());

        var handler = Build(provider, hasher);
        var result  = await handler.Handle(new CheckRunningProcessesQuery(), CancellationToken.None);

        result.Should().HaveCount(1);
        result[0].Sha256Hash.Should().BeNull();
        result[0].IsMalicious.Should().BeFalse();
    }
}
