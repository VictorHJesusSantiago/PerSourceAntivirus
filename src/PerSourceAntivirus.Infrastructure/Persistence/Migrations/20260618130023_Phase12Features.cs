using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PerSourceAntivirus.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Phase12Features : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ComHijackAlerts",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    AlertType = table.Column<string>(type: "TEXT", nullable: false),
                    ClsidOrPath = table.Column<string>(type: "TEXT", nullable: false),
                    SuspiciousPath = table.Column<string>(type: "TEXT", nullable: false),
                    LegitimateSystemPath = table.Column<string>(type: "TEXT", nullable: true),
                    Severity = table.Column<string>(type: "TEXT", nullable: false),
                    IsAcknowledged = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ComHijackAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ExploitFindings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    BaseAddress = table.Column<long>(type: "INTEGER", nullable: false),
                    ConfidenceScore = table.Column<float>(type: "REAL", nullable: false),
                    DetectedPatterns = table.Column<string>(type: "TEXT", nullable: false),
                    IsAcknowledged = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ExploitFindings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RootkitFindings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    FindingType = table.Column<int>(type: "INTEGER", nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: true),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: true),
                    IsAcknowledged = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RootkitFindings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TlsInspectionEvents",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    CapturedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    TargetHost = table.Column<string>(type: "TEXT", nullable: false),
                    TargetPort = table.Column<int>(type: "INTEGER", nullable: false),
                    Method = table.Column<string>(type: "TEXT", nullable: false),
                    RequestPath = table.Column<string>(type: "TEXT", nullable: false),
                    ResponseStatus = table.Column<int>(type: "INTEGER", nullable: false),
                    IsSuspicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    SuspiciousReason = table.Column<string>(type: "TEXT", nullable: true),
                    RequestBodySize = table.Column<int>(type: "INTEGER", nullable: false),
                    ResponseBodySize = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TlsInspectionEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UefiFindings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    TableName = table.Column<string>(type: "TEXT", nullable: false),
                    SignatureName = table.Column<string>(type: "TEXT", nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    MatchOffset = table.Column<int>(type: "INTEGER", nullable: false),
                    IsAcknowledged = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UefiFindings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "WmiPersistenceAlerts",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    FilterName = table.Column<string>(type: "TEXT", nullable: false),
                    ConsumerName = table.Column<string>(type: "TEXT", nullable: false),
                    ConsumerType = table.Column<string>(type: "TEXT", nullable: false),
                    QueryLanguage = table.Column<string>(type: "TEXT", nullable: false),
                    Query = table.Column<string>(type: "TEXT", nullable: false),
                    ScriptOrCommand = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<string>(type: "TEXT", nullable: false),
                    IsAcknowledged = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WmiPersistenceAlerts", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ComHijackAlerts_DetectedAtUtc",
                table: "ComHijackAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ExploitFindings_DetectedAtUtc",
                table: "ExploitFindings",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_RootkitFindings_DetectedAtUtc",
                table: "RootkitFindings",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_TlsInspectionEvents_CapturedAtUtc",
                table: "TlsInspectionEvents",
                column: "CapturedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_TlsInspectionEvents_IsSuspicious",
                table: "TlsInspectionEvents",
                column: "IsSuspicious");

            migrationBuilder.CreateIndex(
                name: "IX_UefiFindings_DetectedAtUtc",
                table: "UefiFindings",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_WmiPersistenceAlerts_DetectedAtUtc",
                table: "WmiPersistenceAlerts",
                column: "DetectedAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ComHijackAlerts");

            migrationBuilder.DropTable(
                name: "ExploitFindings");

            migrationBuilder.DropTable(
                name: "RootkitFindings");

            migrationBuilder.DropTable(
                name: "TlsInspectionEvents");

            migrationBuilder.DropTable(
                name: "UefiFindings");

            migrationBuilder.DropTable(
                name: "WmiPersistenceAlerts");
        }
    }
}
