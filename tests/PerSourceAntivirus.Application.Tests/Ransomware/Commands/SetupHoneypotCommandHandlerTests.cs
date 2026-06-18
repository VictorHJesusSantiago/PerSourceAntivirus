using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Ransomware.Commands.SetupHoneypot;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Tests.Ransomware.Commands;

public class SetupHoneypotCommandHandlerTests
{
    private static SetupHoneypotCommandHandler Build(
        IHoneypotManager? mgr = null,
        IHoneypotRepository? repo = null)
    {
        mgr ??= Substitute.For<IHoneypotManager>();
        repo ??= Substitute.For<IHoneypotRepository>();
        return new SetupHoneypotCommandHandler(mgr, repo);
    }

    [Fact]
    public async Task Handle_PersistsEachCreatedPath()
    {
        var mgr = Substitute.For<IHoneypotManager>();
        mgr.SetupHoneypotsAsync(Arg.Any<CancellationToken>())
           .Returns(new List<string>
           {
               @"C:\Users\test\Desktop\_psav_decoy_passwords.txt",
               @"C:\Users\test\Desktop\_psav_decoy_wallet.dat",
           });

        var repo = Substitute.For<IHoneypotRepository>();

        var result = await Build(mgr, repo).Handle(new SetupHoneypotCommand(), CancellationToken.None);

        result.FilesCreated.Should().Be(2);
        result.Paths.Should().HaveCount(2);
        await repo.Received(2).AddAsync(Arg.Any<HoneypotFile>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsEmptyResult_WhenNoDirectoriesExist()
    {
        var mgr = Substitute.For<IHoneypotManager>();
        mgr.SetupHoneypotsAsync(Arg.Any<CancellationToken>())
           .Returns(new List<string>());

        var repo = Substitute.For<IHoneypotRepository>();

        var result = await Build(mgr, repo).Handle(new SetupHoneypotCommand(), CancellationToken.None);

        result.FilesCreated.Should().Be(0);
        await repo.DidNotReceive().AddAsync(Arg.Any<HoneypotFile>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_SetsDecoyTypeFromExtension()
    {
        var mgr = Substitute.For<IHoneypotManager>();
        mgr.SetupHoneypotsAsync(Arg.Any<CancellationToken>())
           .Returns(new List<string> { @"C:\Desktop\_psav_decoy_wallet.dat" });

        var repo = Substitute.For<IHoneypotRepository>();

        await Build(mgr, repo).Handle(new SetupHoneypotCommand(), CancellationToken.None);

        await repo.Received(1).AddAsync(
            Arg.Is<HoneypotFile>(h => h.DecoyType == "dat"),
            Arg.Any<CancellationToken>());
    }
}
