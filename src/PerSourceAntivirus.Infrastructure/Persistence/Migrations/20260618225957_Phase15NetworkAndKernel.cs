using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PerSourceAntivirus.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Phase15NetworkAndKernel : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ArpSpoofingAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    AttackerMac = table.Column<string>(type: "TEXT", nullable: false),
                    VictimIp = table.Column<string>(type: "TEXT", nullable: false),
                    LegitimateKnownMac = table.Column<string>(type: "TEXT", nullable: false),
                    SpoofedMac = table.Column<string>(type: "TEXT", nullable: false),
                    DetectionReason = table.Column<string>(type: "TEXT", nullable: false),
                    DuplicateCount = table.Column<int>(type: "INTEGER", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ArpSpoofingAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "KeyloggerDetectionAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectionMethod = table.Column<string>(type: "TEXT", nullable: false),
                    SuspiciousDetail = table.Column<string>(type: "TEXT", nullable: false),
                    ModulePath = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KeyloggerDetectionAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "LlmnrPoisoningAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Protocol = table.Column<string>(type: "TEXT", nullable: false),
                    QueryName = table.Column<string>(type: "TEXT", nullable: false),
                    QuerierIp = table.Column<string>(type: "TEXT", nullable: false),
                    ResponderIp = table.Column<string>(type: "TEXT", nullable: false),
                    ResponderMac = table.Column<string>(type: "TEXT", nullable: false),
                    SpoofedIp = table.Column<string>(type: "TEXT", nullable: false),
                    DetectionReason = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LlmnrPoisoningAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "NetworkIntrusionAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    SignatureName = table.Column<string>(type: "TEXT", nullable: false),
                    SourceIp = table.Column<string>(type: "TEXT", nullable: false),
                    SourcePort = table.Column<int>(type: "INTEGER", nullable: false),
                    DestinationIp = table.Column<string>(type: "TEXT", nullable: false),
                    DestinationPort = table.Column<int>(type: "INTEGER", nullable: false),
                    Protocol = table.Column<string>(type: "TEXT", nullable: false),
                    MatchedPattern = table.Column<string>(type: "TEXT", nullable: false),
                    PayloadLength = table.Column<int>(type: "INTEGER", nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NetworkIntrusionAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SafeFolderViolationAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    ProtectedPath = table.Column<string>(type: "TEXT", nullable: false),
                    AttemptedOperation = table.Column<string>(type: "TEXT", nullable: false),
                    WasBlocked = table.Column<bool>(type: "INTEGER", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SafeFolderViolationAlerts", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ArpSpoofingAlerts_DetectedAtUtc",
                table: "ArpSpoofingAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_KeyloggerDetectionAlerts_DetectedAtUtc",
                table: "KeyloggerDetectionAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_KeyloggerDetectionAlerts_Severity",
                table: "KeyloggerDetectionAlerts",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_LlmnrPoisoningAlerts_DetectedAtUtc",
                table: "LlmnrPoisoningAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_NetworkIntrusionAlerts_DetectedAtUtc",
                table: "NetworkIntrusionAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_NetworkIntrusionAlerts_Severity",
                table: "NetworkIntrusionAlerts",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_SafeFolderViolationAlerts_DetectedAtUtc",
                table: "SafeFolderViolationAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_SafeFolderViolationAlerts_WasBlocked",
                table: "SafeFolderViolationAlerts",
                column: "WasBlocked");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ArpSpoofingAlerts");

            migrationBuilder.DropTable(
                name: "KeyloggerDetectionAlerts");

            migrationBuilder.DropTable(
                name: "LlmnrPoisoningAlerts");

            migrationBuilder.DropTable(
                name: "NetworkIntrusionAlerts");

            migrationBuilder.DropTable(
                name: "SafeFolderViolationAlerts");
        }
    }
}
