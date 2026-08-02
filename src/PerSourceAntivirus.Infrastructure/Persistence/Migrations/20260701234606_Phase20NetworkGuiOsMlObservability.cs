using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PerSourceAntivirus.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Phase20NetworkGuiOsMlObservability : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ActiveLearningSamples",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Sha256 = table.Column<string>(type: "TEXT", nullable: false),
                    FeaturesJson = table.Column<string>(type: "TEXT", nullable: false),
                    IsMalicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    RecordedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ActiveLearningSamples", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditLogChainEntries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    SequenceNumber = table.Column<long>(type: "INTEGER", nullable: false),
                    EventDescription = table.Column<string>(type: "TEXT", nullable: false),
                    PreviousHash = table.Column<string>(type: "TEXT", nullable: false),
                    EntryHash = table.Column<string>(type: "TEXT", nullable: false),
                    RecordedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLogChainEntries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DnsTunnelingAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    SourceAddress = table.Column<string>(type: "TEXT", nullable: false),
                    QueryDomain = table.Column<string>(type: "TEXT", nullable: false),
                    QueriesInWindow = table.Column<int>(type: "INTEGER", nullable: false),
                    AverageLabelEntropy = table.Column<double>(type: "REAL", nullable: false),
                    AverageQueryLength = table.Column<double>(type: "REAL", nullable: false),
                    DetectionReason = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DnsTunnelingAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "GeoIpBlockAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    RemoteAddress = table.Column<string>(type: "TEXT", nullable: false),
                    CountryCode = table.Column<string>(type: "TEXT", nullable: false),
                    Direction = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GeoIpBlockAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ProcessFirewallRules",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessPath = table.Column<string>(type: "TEXT", nullable: false),
                    Action = table.Column<string>(type: "TEXT", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", nullable: true),
                    AddedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProcessFirewallRules", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RemoteAgentEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    SourceHost = table.Column<string>(type: "TEXT", nullable: false),
                    DeviceVendor = table.Column<string>(type: "TEXT", nullable: false),
                    DeviceProduct = table.Column<string>(type: "TEXT", nullable: false),
                    SignatureId = table.Column<string>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    ExtensionsJson = table.Column<string>(type: "TEXT", nullable: true),
                    ReceivedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RemoteAgentEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SecureBootStatusSnapshots",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    SecureBootEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    BootloaderPath = table.Column<string>(type: "TEXT", nullable: false),
                    BootloaderSigned = table.Column<bool>(type: "INTEGER", nullable: false),
                    BootloaderTrusted = table.Column<bool>(type: "INTEGER", nullable: false),
                    BootloaderHashSha256 = table.Column<string>(type: "TEXT", nullable: false),
                    Anomalies = table.Column<string>(type: "TEXT", nullable: true),
                    CheckedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecureBootStatusSnapshots", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UsbDeviceEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    PnpDeviceId = table.Column<string>(type: "TEXT", nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    VendorProductId = table.Column<string>(type: "TEXT", nullable: true),
                    WasAllowed = table.Column<bool>(type: "INTEGER", nullable: false),
                    ActionTaken = table.Column<string>(type: "TEXT", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UsbDeviceEvents", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ActiveLearningSamples_RecordedAtUtc",
                table: "ActiveLearningSamples",
                column: "RecordedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogChainEntries_SequenceNumber",
                table: "AuditLogChainEntries",
                column: "SequenceNumber",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DnsTunnelingAlerts_DetectedAtUtc",
                table: "DnsTunnelingAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_GeoIpBlockAlerts_DetectedAtUtc",
                table: "GeoIpBlockAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ProcessFirewallRules_ProcessPath",
                table: "ProcessFirewallRules",
                column: "ProcessPath");

            migrationBuilder.CreateIndex(
                name: "IX_RemoteAgentEvents_ReceivedAtUtc",
                table: "RemoteAgentEvents",
                column: "ReceivedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_SecureBootStatusSnapshots_CheckedAtUtc",
                table: "SecureBootStatusSnapshots",
                column: "CheckedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_UsbDeviceEvents_DetectedAtUtc",
                table: "UsbDeviceEvents",
                column: "DetectedAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ActiveLearningSamples");

            migrationBuilder.DropTable(
                name: "AuditLogChainEntries");

            migrationBuilder.DropTable(
                name: "DnsTunnelingAlerts");

            migrationBuilder.DropTable(
                name: "GeoIpBlockAlerts");

            migrationBuilder.DropTable(
                name: "ProcessFirewallRules");

            migrationBuilder.DropTable(
                name: "RemoteAgentEvents");

            migrationBuilder.DropTable(
                name: "SecureBootStatusSnapshots");

            migrationBuilder.DropTable(
                name: "UsbDeviceEvents");
        }
    }
}
