using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Sandbox.Commands.AnalyzeBehavior;

namespace PerSourceAntivirus.Application.Tests.Sandbox.Commands;

public class AnalyzeBehaviorCommandHandlerTests
{
    private static AnalyzeBehaviorCommandHandler Build(IEnhancedSandboxRunner? runner = null)
    {
        runner ??= Substitute.For<IEnhancedSandboxRunner>();
        return new AnalyzeBehaviorCommandHandler(runner);
    }

    [Fact]
    public async Task Handle_PassesFilePathAndTimeoutToRunner()
    {
        var runner = Substitute.For<IEnhancedSandboxRunner>();
        var report = new BehaviorReport(
            FilePath: @"C:\samples\sample.exe",
            ExecutedSuccessfully: true,
            ExecutionTime: TimeSpan.FromSeconds(5),
            ProcessesCreated: new List<string>(),
            FilesCreated: new List<string>(),
            FilesDeleted: new List<string>(),
            RegistryKeysModified: new List<string>(),
            NetworkConnections: new List<string>(),
            SuspiciousIndicators: new List<string>(),
            OverallVerdict: "Clean");
        runner.AnalyzeAsync(Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>()).Returns(report);

        await Build(runner).Handle(new AnalyzeBehaviorCommand(@"C:\samples\sample.exe", 45), CancellationToken.None);

        await runner.Received(1).AnalyzeAsync(
            @"C:\samples\sample.exe",
            TimeSpan.FromSeconds(45),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsReportWithCorrectVerdict()
    {
        var runner = Substitute.For<IEnhancedSandboxRunner>();
        var report = new BehaviorReport(
            FilePath: @"C:\samples\benign.exe",
            ExecutedSuccessfully: true,
            ExecutionTime: TimeSpan.FromSeconds(10),
            ProcessesCreated: new List<string>(),
            FilesCreated: new List<string>(),
            FilesDeleted: new List<string>(),
            RegistryKeysModified: new List<string>(),
            NetworkConnections: new List<string>(),
            SuspiciousIndicators: new List<string>(),
            OverallVerdict: "Clean");
        runner.AnalyzeAsync(Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>()).Returns(report);

        var result = await Build(runner).Handle(new AnalyzeBehaviorCommand(@"C:\samples\benign.exe"), CancellationToken.None);

        result.OverallVerdict.Should().Be("Clean");
        result.FilePath.Should().Be(@"C:\samples\benign.exe");
    }

    [Fact]
    public async Task Handle_PropagatesMaliciousVerdict_WhenSuspiciousIndicatorsPresent()
    {
        var runner = Substitute.For<IEnhancedSandboxRunner>();
        var report = new BehaviorReport(
            FilePath: @"C:\samples\evil.exe",
            ExecutedSuccessfully: true,
            ExecutionTime: TimeSpan.FromSeconds(3),
            ProcessesCreated: new List<string> { "cmd.exe", "powershell.exe" },
            FilesCreated: new List<string> { @"C:\Windows\System32\evil.dll" },
            FilesDeleted: new List<string>(),
            RegistryKeysModified: new List<string> { @"HKCU\Software\Run\Persist" },
            NetworkConnections: new List<string> { "185.234.218.50:4444" },
            SuspiciousIndicators: new List<string> { "Process injection detected", "C2 communication detected" },
            OverallVerdict: "Malicious");
        runner.AnalyzeAsync(Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>()).Returns(report);

        var result = await Build(runner).Handle(new AnalyzeBehaviorCommand(@"C:\samples\evil.exe"), CancellationToken.None);

        result.OverallVerdict.Should().Be("Malicious");
        result.SuspiciousIndicators.Should().HaveCount(2);
    }
}
