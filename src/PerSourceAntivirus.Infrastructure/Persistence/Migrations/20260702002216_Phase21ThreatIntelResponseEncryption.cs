using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PerSourceAntivirus.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Phase21ThreatIntelResponseEncryption : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "HostIsolationEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Action = table.Column<string>(type: "TEXT", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", nullable: false),
                    TriggeredAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HostIsolationEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PlaybookExecutionLogs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    RuleId = table.Column<Guid>(type: "TEXT", nullable: false),
                    RuleName = table.Column<string>(type: "TEXT", nullable: false),
                    AlertType = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: true),
                    FilePath = table.Column<string>(type: "TEXT", nullable: true),
                    ActionsExecuted = table.Column<string>(type: "TEXT", nullable: false),
                    Success = table.Column<bool>(type: "INTEGER", nullable: false),
                    ErrorMessage = table.Column<string>(type: "TEXT", nullable: true),
                    ExecutedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PlaybookExecutionLogs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ResponsePlaybookRules",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    TriggerAlertType = table.Column<string>(type: "TEXT", nullable: false),
                    MinSeverity = table.Column<int>(type: "INTEGER", nullable: false),
                    Actions = table.Column<string>(type: "TEXT", nullable: false),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ResponsePlaybookRules", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SampleSubmissionRecords",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    OriginalFilePath = table.Column<string>(type: "TEXT", nullable: false),
                    PackagedArchivePath = table.Column<string>(type: "TEXT", nullable: false),
                    SubmittedToUrl = table.Column<string>(type: "TEXT", nullable: true),
                    Submitted = table.Column<bool>(type: "INTEGER", nullable: false),
                    Success = table.Column<bool>(type: "INTEGER", nullable: false),
                    ErrorMessage = table.Column<string>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SampleSubmissionRecords", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_HostIsolationEvents_TriggeredAtUtc",
                table: "HostIsolationEvents",
                column: "TriggeredAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_PlaybookExecutionLogs_ExecutedAtUtc",
                table: "PlaybookExecutionLogs",
                column: "ExecutedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_SampleSubmissionRecords_CreatedAtUtc",
                table: "SampleSubmissionRecords",
                column: "CreatedAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "HostIsolationEvents");

            migrationBuilder.DropTable(
                name: "PlaybookExecutionLogs");

            migrationBuilder.DropTable(
                name: "ResponsePlaybookRules");

            migrationBuilder.DropTable(
                name: "SampleSubmissionRecords");
        }
    }
}
