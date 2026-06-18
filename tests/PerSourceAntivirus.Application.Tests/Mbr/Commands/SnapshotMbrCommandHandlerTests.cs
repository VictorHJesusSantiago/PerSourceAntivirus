using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Mbr.Commands.SnapshotMbr;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Tests.Mbr.Commands;

public class SnapshotMbrCommandHandlerTests
{
    private static SnapshotMbrCommandHandler Build(
        IMbrProtectionService? svc  = null,
        IMbrSnapshotRepository? rep = null)
    {
        svc ??= Substitute.For<IMbrProtectionService>();
        rep ??= Substitute.For<IMbrSnapshotRepository>();
        return new SnapshotMbrCommandHandler(svc, rep);
    }

    [Fact]
    public async Task Handle_SavesSnapshot_AndMarksAsBaseline_WhenFirstSnapshot()
    {
        var svc = Substitute.For<IMbrProtectionService>();
        svc.ReadMbrHashAsync(0, Arg.Any<CancellationToken>())
           .Returns(new MbrReadResult("aabbccdd" + new string('0', 56), 512, true));

        var rep = Substitute.For<IMbrSnapshotRepository>();
        rep.GetLatestBaselineAsync(0, Arg.Any<CancellationToken>())
           .Returns((MbrSnapshot?)null);

        var handler = Build(svc, rep);
        var result  = await handler.Handle(new SnapshotMbrCommand(0), CancellationToken.None);

        result.IsBaseline.Should().BeTrue();
        result.Sha256Hash.Should().StartWith("aabbccdd");
        result.DriveIndex.Should().Be(0);
        await rep.Received(1).AddAsync(Arg.Is<MbrSnapshot>(s => s.IsBaseline), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_DoesNotMarkAsBaseline_WhenBaselineAlreadyExists()
    {
        var svc = Substitute.For<IMbrProtectionService>();
        svc.ReadMbrHashAsync(0, Arg.Any<CancellationToken>())
           .Returns(new MbrReadResult(new string('a', 64), 512, true));

        var rep = Substitute.For<IMbrSnapshotRepository>();
        rep.GetLatestBaselineAsync(0, Arg.Any<CancellationToken>())
           .Returns(new MbrSnapshot { IsBaseline = true, Sha256Hash = new string('b', 64) });

        var handler = Build(svc, rep);
        var result  = await handler.Handle(new SnapshotMbrCommand(0), CancellationToken.None);

        result.IsBaseline.Should().BeFalse();
    }

    [Fact]
    public async Task Handle_Throws_WhenMbrReadFails()
    {
        var svc = Substitute.For<IMbrProtectionService>();
        svc.ReadMbrHashAsync(0, Arg.Any<CancellationToken>())
           .Returns(new MbrReadResult(null, 0, false, "Access denied."));

        var handler = Build(svc);
        await handler.Invoking(h => h.Handle(new SnapshotMbrCommand(0), CancellationToken.None))
            .Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Access denied*");
    }
}
