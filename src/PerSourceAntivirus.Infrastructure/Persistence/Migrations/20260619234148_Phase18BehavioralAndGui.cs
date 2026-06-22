using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PerSourceAntivirus.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Phase18BehavioralAndGui : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "FirmwareVariableSnapshots",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    VariableName = table.Column<string>(type: "TEXT", nullable: false),
                    VariableNamespace = table.Column<string>(type: "TEXT", nullable: false),
                    CurrentValueHash = table.Column<string>(type: "TEXT", nullable: false),
                    BaselineValueHash = table.Column<string>(type: "TEXT", nullable: false),
                    IsSuspicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    ChangeDescription = table.Column<string>(type: "TEXT", nullable: false),
                    SnapshotAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FirmwareVariableSnapshots", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "HypervisorDetectionResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    IsVirtualMachine = table.Column<bool>(type: "INTEGER", nullable: false),
                    HypervisorType = table.Column<string>(type: "TEXT", nullable: false),
                    DetectionMethods = table.Column<string>(type: "TEXT", nullable: false),
                    CpuidLeaf = table.Column<string>(type: "TEXT", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HypervisorDetectionResults", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "KernelPatchGuardAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    BypassMethodType = table.Column<string>(type: "TEXT", nullable: false),
                    Details = table.Column<string>(type: "TEXT", nullable: false),
                    TargetFunction = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KernelPatchGuardAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "MemoryDumpResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    DumpFilePath = table.Column<string>(type: "TEXT", nullable: false),
                    ExtractedStrings = table.Column<string>(type: "TEXT", nullable: false),
                    ExtractedIps = table.Column<string>(type: "TEXT", nullable: false),
                    ExtractedUrls = table.Column<string>(type: "TEXT", nullable: false),
                    SuspiciousImports = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MemoryDumpResults", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "NotificationRecords",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    NotificationType = table.Column<string>(type: "TEXT", nullable: false),
                    Title = table.Column<string>(type: "TEXT", nullable: false),
                    Message = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    RelatedEntityType = table.Column<string>(type: "TEXT", nullable: false),
                    RelatedEntityId = table.Column<Guid>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    AcknowledgedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NotificationRecords", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ScanProfiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    ProfileType = table.Column<string>(type: "TEXT", nullable: false),
                    IncludePaths = table.Column<string>(type: "TEXT", nullable: false),
                    ExcludePaths = table.Column<string>(type: "TEXT", nullable: false),
                    FileExtensions = table.Column<string>(type: "TEXT", nullable: false),
                    MaxFileSizeBytes = table.Column<long>(type: "INTEGER", nullable: false),
                    IsDefault = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanProfiles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SupplyChainAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    FilePath = table.Column<string>(type: "TEXT", nullable: false),
                    Publisher = table.Column<string>(type: "TEXT", nullable: false),
                    CertificateThumbprint = table.Column<string>(type: "TEXT", nullable: false),
                    AlertType = table.Column<string>(type: "TEXT", nullable: false),
                    Details = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SupplyChainAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ThreatReports",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ReportType = table.Column<string>(type: "TEXT", nullable: false),
                    PeriodStart = table.Column<DateTime>(type: "TEXT", nullable: false),
                    PeriodEnd = table.Column<DateTime>(type: "TEXT", nullable: false),
                    OutputFilePath = table.Column<string>(type: "TEXT", nullable: false),
                    TotalFilesScanned = table.Column<int>(type: "INTEGER", nullable: false),
                    TotalThreats = table.Column<int>(type: "INTEGER", nullable: false),
                    TotalSuspicious = table.Column<int>(type: "INTEGER", nullable: false),
                    TopThreatTypes = table.Column<string>(type: "TEXT", nullable: false),
                    GeneratedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ThreatReports", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_FirmwareVariableSnapshots_IsSuspicious",
                table: "FirmwareVariableSnapshots",
                column: "IsSuspicious");

            migrationBuilder.CreateIndex(
                name: "IX_FirmwareVariableSnapshots_SnapshotAtUtc",
                table: "FirmwareVariableSnapshots",
                column: "SnapshotAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_HypervisorDetectionResults_DetectedAtUtc",
                table: "HypervisorDetectionResults",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_HypervisorDetectionResults_IsVirtualMachine",
                table: "HypervisorDetectionResults",
                column: "IsVirtualMachine");

            migrationBuilder.CreateIndex(
                name: "IX_KernelPatchGuardAlerts_DetectedAtUtc",
                table: "KernelPatchGuardAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_KernelPatchGuardAlerts_Severity",
                table: "KernelPatchGuardAlerts",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_MemoryDumpResults_CreatedAtUtc",
                table: "MemoryDumpResults",
                column: "CreatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_MemoryDumpResults_ProcessId",
                table: "MemoryDumpResults",
                column: "ProcessId");

            migrationBuilder.CreateIndex(
                name: "IX_NotificationRecords_CreatedAtUtc",
                table: "NotificationRecords",
                column: "CreatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_NotificationRecords_Status",
                table: "NotificationRecords",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_ScanProfiles_CreatedAtUtc",
                table: "ScanProfiles",
                column: "CreatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ScanProfiles_IsDefault",
                table: "ScanProfiles",
                column: "IsDefault");

            migrationBuilder.CreateIndex(
                name: "IX_SupplyChainAlerts_DetectedAtUtc",
                table: "SupplyChainAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_SupplyChainAlerts_Severity",
                table: "SupplyChainAlerts",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_ThreatReports_GeneratedAtUtc",
                table: "ThreatReports",
                column: "GeneratedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ThreatReports_ReportType",
                table: "ThreatReports",
                column: "ReportType");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "FirmwareVariableSnapshots");

            migrationBuilder.DropTable(
                name: "HypervisorDetectionResults");

            migrationBuilder.DropTable(
                name: "KernelPatchGuardAlerts");

            migrationBuilder.DropTable(
                name: "MemoryDumpResults");

            migrationBuilder.DropTable(
                name: "NotificationRecords");

            migrationBuilder.DropTable(
                name: "ScanProfiles");

            migrationBuilder.DropTable(
                name: "SupplyChainAlerts");

            migrationBuilder.DropTable(
                name: "ThreatReports");
        }
    }
}
