using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PerSourceAntivirus.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Phase17EdrAndBrowserProtection : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AlertTriages",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    AlertType = table.Column<string>(type: "TEXT", nullable: false),
                    AlertId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    AutoSeverityScore = table.Column<int>(type: "INTEGER", nullable: false),
                    Notes = table.Column<string>(type: "TEXT", nullable: false),
                    TriagedBy = table.Column<string>(type: "TEXT", nullable: false),
                    IncidentId = table.Column<Guid>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    TriagedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AlertTriages", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AmsiBypassAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    BypassMethod = table.Column<string>(type: "TEXT", nullable: false),
                    Details = table.Column<string>(type: "TEXT", nullable: false),
                    AffectedFunction = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AmsiBypassAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AppWhitelistEntries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    EntryType = table.Column<string>(type: "TEXT", nullable: false),
                    Value = table.Column<string>(type: "TEXT", nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    Action = table.Column<string>(type: "TEXT", nullable: false),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AppWhitelistEntries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "BrowserCredentialAccessAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Browser = table.Column<string>(type: "TEXT", nullable: false),
                    CredentialFilePath = table.Column<string>(type: "TEXT", nullable: false),
                    AccessingProcess = table.Column<string>(type: "TEXT", nullable: false),
                    AccessingPid = table.Column<int>(type: "INTEGER", nullable: false),
                    WasBlocked = table.Column<bool>(type: "INTEGER", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BrowserCredentialAccessAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "BrowserExtensionFindings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Browser = table.Column<string>(type: "TEXT", nullable: false),
                    ExtensionId = table.Column<string>(type: "TEXT", nullable: false),
                    ExtensionName = table.Column<string>(type: "TEXT", nullable: false),
                    Version = table.Column<string>(type: "TEXT", nullable: false),
                    Permissions = table.Column<string>(type: "TEXT", nullable: false),
                    IsSuspicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    RiskReason = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    AuditedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BrowserExtensionFindings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CfgViolationAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    ViolationAddress = table.Column<string>(type: "TEXT", nullable: false),
                    ExceptionCode = table.Column<string>(type: "TEXT", nullable: false),
                    Details = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CfgViolationAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CustomIocs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    IocType = table.Column<string>(type: "TEXT", nullable: false),
                    Value = table.Column<string>(type: "TEXT", nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    Tags = table.Column<string>(type: "TEXT", nullable: false),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastMatchedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CustomIocs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "FileActivityEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ImagePath = table.Column<string>(type: "TEXT", nullable: false),
                    FilePath = table.Column<string>(type: "TEXT", nullable: false),
                    FileName = table.Column<string>(type: "TEXT", nullable: false),
                    Operation = table.Column<string>(type: "TEXT", nullable: false),
                    FileSize = table.Column<long>(type: "INTEGER", nullable: false),
                    Sha256Hash = table.Column<string>(type: "TEXT", nullable: false),
                    IsSuspicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    OccurredAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FileActivityEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Incidents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Title = table.Column<string>(type: "TEXT", nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    AlertCount = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ResolvedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Incidents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "MitreAttackMappings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    AlertType = table.Column<string>(type: "TEXT", nullable: false),
                    TechniqueId = table.Column<string>(type: "TEXT", nullable: false),
                    TechniqueName = table.Column<string>(type: "TEXT", nullable: false),
                    Tactic = table.Column<string>(type: "TEXT", nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    MitreUrl = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MitreAttackMappings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ProcessCreationEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ImagePath = table.Column<string>(type: "TEXT", nullable: false),
                    FileName = table.Column<string>(type: "TEXT", nullable: false),
                    CommandLine = table.Column<string>(type: "TEXT", nullable: false),
                    Sha256Hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    ParentProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    ParentImagePath = table.Column<string>(type: "TEXT", nullable: false),
                    UserName = table.Column<string>(type: "TEXT", nullable: false),
                    IntegrityLevel = table.Column<string>(type: "TEXT", nullable: false),
                    IsSuspicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProcessCreationEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PuaAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    ImagePath = table.Column<string>(type: "TEXT", nullable: false),
                    Category = table.Column<string>(type: "TEXT", nullable: false),
                    DetectionReason = table.Column<string>(type: "TEXT", nullable: false),
                    DetectionDetails = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PuaAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RegistryActivityEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    KeyPath = table.Column<string>(type: "TEXT", nullable: false),
                    ValueName = table.Column<string>(type: "TEXT", nullable: false),
                    Operation = table.Column<string>(type: "TEXT", nullable: false),
                    OldData = table.Column<string>(type: "TEXT", nullable: false),
                    NewData = table.Column<string>(type: "TEXT", nullable: false),
                    IsSuspicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    OccurredAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RegistryActivityEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ScriptSandboxResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ScriptType = table.Column<string>(type: "TEXT", nullable: false),
                    ScriptHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    ScriptPreview = table.Column<string>(type: "TEXT", nullable: false),
                    AmsiScore = table.Column<int>(type: "INTEGER", nullable: false),
                    WasSandboxed = table.Column<bool>(type: "INTEGER", nullable: false),
                    BehavioralFindings = table.Column<string>(type: "TEXT", nullable: false),
                    Verdict = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    AnalyzedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScriptSandboxResults", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "StixFeedSources",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    Url = table.Column<string>(type: "TEXT", nullable: false),
                    FeedType = table.Column<string>(type: "TEXT", nullable: false),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    LastUpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastStatus = table.Column<string>(type: "TEXT", nullable: false),
                    IocCount = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StixFeedSources", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "StixIocs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    FeedSourceId = table.Column<Guid>(type: "TEXT", nullable: false),
                    IocType = table.Column<string>(type: "TEXT", nullable: false),
                    Value = table.Column<string>(type: "TEXT", nullable: false),
                    Labels = table.Column<string>(type: "TEXT", nullable: false),
                    Confidence = table.Column<double>(type: "REAL", nullable: false),
                    ThreatActors = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StixIocs", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AlertTriages_CreatedAtUtc",
                table: "AlertTriages",
                column: "CreatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_AlertTriages_IncidentId",
                table: "AlertTriages",
                column: "IncidentId");

            migrationBuilder.CreateIndex(
                name: "IX_AlertTriages_Status",
                table: "AlertTriages",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_AmsiBypassAlerts_DetectedAtUtc",
                table: "AmsiBypassAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_AmsiBypassAlerts_Severity",
                table: "AmsiBypassAlerts",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_AppWhitelistEntries_EntryType_Value",
                table: "AppWhitelistEntries",
                columns: new[] { "EntryType", "Value" });

            migrationBuilder.CreateIndex(
                name: "IX_AppWhitelistEntries_IsEnabled",
                table: "AppWhitelistEntries",
                column: "IsEnabled");

            migrationBuilder.CreateIndex(
                name: "IX_BrowserCredentialAccessAlerts_DetectedAtUtc",
                table: "BrowserCredentialAccessAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_BrowserCredentialAccessAlerts_Severity",
                table: "BrowserCredentialAccessAlerts",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_BrowserExtensionFindings_AuditedAtUtc",
                table: "BrowserExtensionFindings",
                column: "AuditedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_BrowserExtensionFindings_IsSuspicious",
                table: "BrowserExtensionFindings",
                column: "IsSuspicious");

            migrationBuilder.CreateIndex(
                name: "IX_CfgViolationAlerts_DetectedAtUtc",
                table: "CfgViolationAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_CfgViolationAlerts_Severity",
                table: "CfgViolationAlerts",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_CustomIocs_IocType_Value",
                table: "CustomIocs",
                columns: new[] { "IocType", "Value" });

            migrationBuilder.CreateIndex(
                name: "IX_CustomIocs_IsActive",
                table: "CustomIocs",
                column: "IsActive");

            migrationBuilder.CreateIndex(
                name: "IX_FileActivityEvents_IsSuspicious",
                table: "FileActivityEvents",
                column: "IsSuspicious");

            migrationBuilder.CreateIndex(
                name: "IX_FileActivityEvents_OccurredAtUtc",
                table: "FileActivityEvents",
                column: "OccurredAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_FileActivityEvents_ProcessId",
                table: "FileActivityEvents",
                column: "ProcessId");

            migrationBuilder.CreateIndex(
                name: "IX_Incidents_CreatedAtUtc",
                table: "Incidents",
                column: "CreatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_Incidents_Severity",
                table: "Incidents",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_Incidents_Status",
                table: "Incidents",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_MitreAttackMappings_AlertType",
                table: "MitreAttackMappings",
                column: "AlertType",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ProcessCreationEvents_CreatedAtUtc",
                table: "ProcessCreationEvents",
                column: "CreatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ProcessCreationEvents_IsSuspicious",
                table: "ProcessCreationEvents",
                column: "IsSuspicious");

            migrationBuilder.CreateIndex(
                name: "IX_ProcessCreationEvents_ProcessId",
                table: "ProcessCreationEvents",
                column: "ProcessId");

            migrationBuilder.CreateIndex(
                name: "IX_PuaAlerts_Category",
                table: "PuaAlerts",
                column: "Category");

            migrationBuilder.CreateIndex(
                name: "IX_PuaAlerts_DetectedAtUtc",
                table: "PuaAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_PuaAlerts_Severity",
                table: "PuaAlerts",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_RegistryActivityEvents_IsSuspicious",
                table: "RegistryActivityEvents",
                column: "IsSuspicious");

            migrationBuilder.CreateIndex(
                name: "IX_RegistryActivityEvents_OccurredAtUtc",
                table: "RegistryActivityEvents",
                column: "OccurredAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_RegistryActivityEvents_ProcessId",
                table: "RegistryActivityEvents",
                column: "ProcessId");

            migrationBuilder.CreateIndex(
                name: "IX_ScriptSandboxResults_AnalyzedAtUtc",
                table: "ScriptSandboxResults",
                column: "AnalyzedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ScriptSandboxResults_Verdict",
                table: "ScriptSandboxResults",
                column: "Verdict");

            migrationBuilder.CreateIndex(
                name: "IX_StixIocs_FeedSourceId",
                table: "StixIocs",
                column: "FeedSourceId");

            migrationBuilder.CreateIndex(
                name: "IX_StixIocs_IocType_Value",
                table: "StixIocs",
                columns: new[] { "IocType", "Value" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AlertTriages");

            migrationBuilder.DropTable(
                name: "AmsiBypassAlerts");

            migrationBuilder.DropTable(
                name: "AppWhitelistEntries");

            migrationBuilder.DropTable(
                name: "BrowserCredentialAccessAlerts");

            migrationBuilder.DropTable(
                name: "BrowserExtensionFindings");

            migrationBuilder.DropTable(
                name: "CfgViolationAlerts");

            migrationBuilder.DropTable(
                name: "CustomIocs");

            migrationBuilder.DropTable(
                name: "FileActivityEvents");

            migrationBuilder.DropTable(
                name: "Incidents");

            migrationBuilder.DropTable(
                name: "MitreAttackMappings");

            migrationBuilder.DropTable(
                name: "ProcessCreationEvents");

            migrationBuilder.DropTable(
                name: "PuaAlerts");

            migrationBuilder.DropTable(
                name: "RegistryActivityEvents");

            migrationBuilder.DropTable(
                name: "ScriptSandboxResults");

            migrationBuilder.DropTable(
                name: "StixFeedSources");

            migrationBuilder.DropTable(
                name: "StixIocs");
        }
    }
}
