using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PerSourceAntivirus.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AdvancedFeatures : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DnsQueryEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CapturedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    QueryName = table.Column<string>(type: "TEXT", nullable: false),
                    QueryType = table.Column<string>(type: "TEXT", nullable: false),
                    SourceAddress = table.Column<string>(type: "TEXT", nullable: false),
                    IsSuspicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    SuspicionReason = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DnsQueryEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "HashReputationResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ScannedFileId = table.Column<Guid>(type: "TEXT", nullable: false),
                    PositiveDetections = table.Column<int>(type: "INTEGER", nullable: false),
                    TotalEngines = table.Column<int>(type: "INTEGER", nullable: false),
                    IsMalicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    Source = table.Column<string>(type: "TEXT", nullable: false),
                    ReportUrl = table.Column<string>(type: "TEXT", nullable: true),
                    CheckedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HashReputationResults", x => x.Id);
                    table.ForeignKey(
                        name: "FK_HashReputationResults_ScannedFiles_ScannedFileId",
                        column: x => x.ScannedFileId,
                        principalTable: "ScannedFiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ProcessEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ParentProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    ParentProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    CommandLine = table.Column<string>(type: "TEXT", nullable: false),
                    IsSuspicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    SuspicionReason = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProcessEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ScheduledScans",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Path = table.Column<string>(type: "TEXT", nullable: false),
                    IntervalMinutes = table.Column<int>(type: "INTEGER", nullable: false),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    LastRunAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScheduledScans", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_HashReputationResults_ScannedFileId",
                table: "HashReputationResults",
                column: "ScannedFileId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DnsQueryEvents");

            migrationBuilder.DropTable(
                name: "HashReputationResults");

            migrationBuilder.DropTable(
                name: "ProcessEvents");

            migrationBuilder.DropTable(
                name: "ScheduledScans");
        }
    }
}
