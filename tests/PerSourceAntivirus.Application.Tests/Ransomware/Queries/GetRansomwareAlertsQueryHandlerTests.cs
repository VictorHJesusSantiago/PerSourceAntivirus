using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Ransomware.Queries.GetRansomwareAlerts;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Application.Tests.Ransomware.Queries;

public class GetRansomwareAlertsQueryHandlerTests
{
    private static GetRansomwareAlertsQueryHandler Build(IRansomwareAlertRepository? repo = null)
    {
        repo ??= Substitute.For<IRansomwareAlertRepository>();
        return new GetRansomwareAlertsQueryHandler(repo);
    }

    [Fact]
    public async Task Handle_ReturnsAllAlerts_WhenOnlyCriticalIsFalse()
    {
        var repo = Substitute.For<IRansomwareAlertRepository>();
        repo.GetAllAsync(false, Arg.Any<CancellationToken>())
            .Returns(new List<RansomwareAlert>
            {
                new() { Severity = RansomwareSeverity.Warning,  EventType = RansomwareEventType.MassEncryptionDetected },
                new() { Severity = RansomwareSeverity.Critical, EventType = RansomwareEventType.HoneypotTouched },
            });

        var result = await Build(repo).Handle(new GetRansomwareAlertsQuery(false), CancellationToken.None);

        result.Should().HaveCount(2);
        await repo.Received(1).GetAllAsync(false, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ForwardsOnlyCriticalFlag()
    {
        var repo = Substitute.For<IRansomwareAlertRepository>();
        repo.GetAllAsync(true, Arg.Any<CancellationToken>())
            .Returns(new List<RansomwareAlert>
            {
                new() { Severity = RansomwareSeverity.Critical, EventType = RansomwareEventType.HoneypotTouched },
            });

        var result = await Build(repo).Handle(new GetRansomwareAlertsQuery(true), CancellationToken.None);

        result.Should().HaveCount(1);
        result[0].Severity.Should().Be(RansomwareSeverity.Critical);
    }

    [Fact]
    public async Task Handle_ReturnsEmpty_WhenNoAlertsRecorded()
    {
        var repo = Substitute.For<IRansomwareAlertRepository>();
        repo.GetAllAsync(Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(new List<RansomwareAlert>());

        var result = await Build(repo).Handle(new GetRansomwareAlertsQuery(), CancellationToken.None);

        result.Should().BeEmpty();
    }
}
