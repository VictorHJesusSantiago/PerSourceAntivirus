using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Process.Commands.ScanProcessMemory;

namespace PerSourceAntivirus.Application.Tests.Process.Commands;

public class ScanProcessMemoryCommandHandlerTests
{
    private static ScanProcessMemoryCommandHandler Build(IProcessMemoryScanner? scanner = null)
    {
        scanner ??= Substitute.For<IProcessMemoryScanner>();
        return new ScanProcessMemoryCommandHandler(scanner);
    }

    [Fact]
    public async Task Handle_DelegatesToScanner_WithCorrectPid()
    {
        var scanner = Substitute.For<IProcessMemoryScanner>();
        var expected = new ProcessMemoryScanResult(1234, "test.exe", 5, [], true);
        scanner.ScanProcessAsync(1234, Arg.Any<CancellationToken>()).Returns(expected);

        var result = await Build(scanner).Handle(new ScanProcessMemoryCommand(1234), CancellationToken.None);

        result.Should().Be(expected);
        await scanner.Received(1).ScanProcessAsync(1234, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsFailure_WhenScannerReturnsError()
    {
        var scanner = Substitute.For<IProcessMemoryScanner>();
        scanner.ScanProcessAsync(9999, Arg.Any<CancellationToken>())
            .Returns(new ProcessMemoryScanResult(9999, "unknown", 0, [], false, "OpenProcess failed: Win32 error 5"));

        var result = await Build(scanner).Handle(new ScanProcessMemoryCommand(9999), CancellationToken.None);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("Win32 error 5");
    }

    [Fact]
    public async Task Handle_ReturnsMatches_WhenYaraRulesHit()
    {
        var scanner = Substitute.For<IProcessMemoryScanner>();
        var matches = new List<ProcessMemoryMatch>
        {
            new(0x7FF000000000L, 4096, "Shellcode_MeterpreterPayload", ["malicious", "shellcode"]),
        };
        scanner.ScanProcessAsync(5678, Arg.Any<CancellationToken>())
            .Returns(new ProcessMemoryScanResult(5678, "evil.exe", 12, matches, true));

        var result = await Build(scanner).Handle(new ScanProcessMemoryCommand(5678), CancellationToken.None);

        result.Success.Should().BeTrue();
        result.Matches.Should().HaveCount(1);
        result.Matches[0].RuleIdentifier.Should().Be("Shellcode_MeterpreterPayload");
    }
}
