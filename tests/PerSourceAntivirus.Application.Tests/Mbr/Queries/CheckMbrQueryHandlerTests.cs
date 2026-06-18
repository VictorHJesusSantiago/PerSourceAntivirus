using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Mbr.Queries.CheckMbr;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Tests.Mbr.Queries;

public class CheckMbrQueryHandlerTests
{
    private const string BaselineHash = "aabb" + "0000000000000000000000000000000000000000000000000000000000";
    private const string DifferentHash = "ccdd" + "0000000000000000000000000000000000000000000000000000000000";

    private static CheckMbrQueryHandler Build(
        IMbrProtectionService? svc  = null,
        IMbrSnapshotRepository? rep = null)
    {
        svc ??= Substitute.For<IMbrProtectionService>();
        rep ??= Substitute.For<IMbrSnapshotRepository>();
        return new CheckMbrQueryHandler(svc, rep);
    }

    [Fact]
    public async Task Handle_ReturnsNoBaseline_WhenNoSnapshotExists()
    {
        var svc = Substitute.For<IMbrProtectionService>();
        svc.ReadMbrHashAsync(0, Arg.Any<CancellationToken>())
           .Returns(new MbrReadResult(BaselineHash, 512, true));

        var rep = Substitute.For<IMbrSnapshotRepository>();
        rep.GetLatestBaselineAsync(0, Arg.Any<CancellationToken>())
           .Returns((MbrSnapshot?)null);

        var result = await Build(svc, rep).Handle(new CheckMbrQuery(0), CancellationToken.None);

        result.HasBaseline.Should().BeFalse();
        result.HashMatched.Should().BeFalse();
        result.CurrentHash.Should().Be(BaselineHash);
    }

    [Fact]
    public async Task Handle_ReturnsMatched_WhenHashesEqual()
    {
        var svc = Substitute.For<IMbrProtectionService>();
        svc.ReadMbrHashAsync(0, Arg.Any<CancellationToken>())
           .Returns(new MbrReadResult(BaselineHash, 512, true));

        var rep = Substitute.For<IMbrSnapshotRepository>();
        rep.GetLatestBaselineAsync(0, Arg.Any<CancellationToken>())
           .Returns(new MbrSnapshot { Sha256Hash = BaselineHash, IsBaseline = true });

        var result = await Build(svc, rep).Handle(new CheckMbrQuery(0), CancellationToken.None);

        result.HasBaseline.Should().BeTrue();
        result.HashMatched.Should().BeTrue();
        result.ErrorMessage.Should().BeNull();
    }

    [Fact]
    public async Task Handle_ReturnsMismatch_WhenHashesDiffer()
    {
        var svc = Substitute.For<IMbrProtectionService>();
        svc.ReadMbrHashAsync(0, Arg.Any<CancellationToken>())
           .Returns(new MbrReadResult(DifferentHash, 512, true));

        var rep = Substitute.For<IMbrSnapshotRepository>();
        rep.GetLatestBaselineAsync(0, Arg.Any<CancellationToken>())
           .Returns(new MbrSnapshot { Sha256Hash = BaselineHash, IsBaseline = true });

        var result = await Build(svc, rep).Handle(new CheckMbrQuery(0), CancellationToken.None);

        result.HasBaseline.Should().BeTrue();
        result.HashMatched.Should().BeFalse();
        result.CurrentHash.Should().Be(DifferentHash);
        result.BaselineHash.Should().Be(BaselineHash);
    }

    [Fact]
    public async Task Handle_ReturnsError_WhenMbrReadFails()
    {
        var svc = Substitute.For<IMbrProtectionService>();
        svc.ReadMbrHashAsync(0, Arg.Any<CancellationToken>())
           .Returns(new MbrReadResult(null, 0, false, "Access denied."));

        var rep = Substitute.For<IMbrSnapshotRepository>();
        rep.GetLatestBaselineAsync(0, Arg.Any<CancellationToken>())
           .Returns((MbrSnapshot?)null);

        var result = await Build(svc, rep).Handle(new CheckMbrQuery(0), CancellationToken.None);

        result.ErrorMessage.Should().Contain("Access denied");
        result.HashMatched.Should().BeFalse();
    }
}
