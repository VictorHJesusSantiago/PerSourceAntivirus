using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PerSourceAntivirus.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Phase16SecurityAndPrivacy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AutostartEntries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Location = table.Column<string>(type: "TEXT", nullable: false),
                    EntryName = table.Column<string>(type: "TEXT", nullable: false),
                    Command = table.Column<string>(type: "TEXT", nullable: false),
                    Publisher = table.Column<string>(type: "TEXT", nullable: false),
                    IsKnown = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsSuspicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    Classification = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    AuditedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AutostartEntries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "BeaconingAnalyses",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    DestinationIp = table.Column<string>(type: "TEXT", nullable: false),
                    DestinationPort = table.Column<int>(type: "INTEGER", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    AverageIntervalSeconds = table.Column<double>(type: "REAL", nullable: false),
                    JitterVariance = table.Column<double>(type: "REAL", nullable: false),
                    PayloadSizeVariance = table.Column<double>(type: "REAL", nullable: false),
                    SampleCount = table.Column<int>(type: "INTEGER", nullable: false),
                    IsOutsideBusinessHours = table.Column<bool>(type: "INTEGER", nullable: false),
                    BeaconingScore = table.Column<int>(type: "INTEGER", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BeaconingAnalyses", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ClipboardHijackAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    OriginalContent = table.Column<string>(type: "TEXT", nullable: false),
                    SuspectedWalletAddress = table.Column<string>(type: "TEXT", nullable: false),
                    AddressType = table.Column<string>(type: "TEXT", nullable: false),
                    WasBlocked = table.Column<bool>(type: "INTEGER", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClipboardHijackAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "MbrWriteAttemptAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    DriveNumber = table.Column<int>(type: "INTEGER", nullable: false),
                    Sector = table.Column<long>(type: "INTEGER", nullable: false),
                    WasBlocked = table.Column<bool>(type: "INTEGER", nullable: false),
                    DetectionMethod = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MbrWriteAttemptAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "MicrophoneAccessEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    DevicePath = table.Column<string>(type: "TEXT", nullable: false),
                    WasBlocked = table.Column<bool>(type: "INTEGER", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MicrophoneAccessEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "OpenPortInfos",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Protocol = table.Column<string>(type: "TEXT", nullable: false),
                    LocalPort = table.Column<int>(type: "INTEGER", nullable: false),
                    RemoteAddress = table.Column<string>(type: "TEXT", nullable: false),
                    RemotePort = table.Column<int>(type: "INTEGER", nullable: false),
                    State = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    IsKnownRisk = table.Column<bool>(type: "INTEGER", nullable: false),
                    RiskDescription = table.Column<string>(type: "TEXT", nullable: false),
                    ScannedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OpenPortInfos", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PortScanAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    SourceIp = table.Column<string>(type: "TEXT", nullable: false),
                    TargetPorts = table.Column<string>(type: "TEXT", nullable: false),
                    ConnectionCount = table.Column<int>(type: "INTEGER", nullable: false),
                    TimeWindowMs = table.Column<double>(type: "REAL", nullable: false),
                    DetectionMethod = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PortScanAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ScreenCaptureAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    TargetWindowTitle = table.Column<string>(type: "TEXT", nullable: false),
                    CaptureMethod = table.Column<string>(type: "TEXT", nullable: false),
                    WasBlocked = table.Column<bool>(type: "INTEGER", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScreenCaptureAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ScreenLockerAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectionMethod = table.Column<string>(type: "TEXT", nullable: false),
                    HasKeyboardHook = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasMouseHook = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasFullscreenWindow = table.Column<bool>(type: "INTEGER", nullable: false),
                    WasTerminated = table.Column<bool>(type: "INTEGER", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScreenLockerAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SecurityPostureIssues",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CheckName = table.Column<string>(type: "TEXT", nullable: false),
                    CurrentValue = table.Column<string>(type: "TEXT", nullable: false),
                    ExpectedValue = table.Column<string>(type: "TEXT", nullable: false),
                    IssueDescription = table.Column<string>(type: "TEXT", nullable: false),
                    Category = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    CheckedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityPostureIssues", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SensitiveDataFindings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    FilePath = table.Column<string>(type: "TEXT", nullable: false),
                    DataType = table.Column<string>(type: "TEXT", nullable: false),
                    MatchSnippet = table.Column<string>(type: "TEXT", nullable: false),
                    LineNumber = table.Column<int>(type: "INTEGER", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    FoundAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SensitiveDataFindings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ServiceAuditFindings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ServiceName = table.Column<string>(type: "TEXT", nullable: false),
                    ServiceDisplayName = table.Column<string>(type: "TEXT", nullable: false),
                    BinaryPath = table.Column<string>(type: "TEXT", nullable: false),
                    IsUnquotedPath = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsWritablePath = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsSystemService = table.Column<bool>(type: "INTEGER", nullable: false),
                    FindingType = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    AuditedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ServiceAuditFindings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SmbLateralMovementAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    SourceIp = table.Column<string>(type: "TEXT", nullable: false),
                    TargetIp = table.Column<string>(type: "TEXT", nullable: false),
                    DetectionReason = table.Column<string>(type: "TEXT", nullable: false),
                    PipeName = table.Column<string>(type: "TEXT", nullable: false),
                    ShareName = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SmbLateralMovementAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TlsCertAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Hostname = table.Column<string>(type: "TEXT", nullable: false),
                    Port = table.Column<int>(type: "INTEGER", nullable: false),
                    SubjectCn = table.Column<string>(type: "TEXT", nullable: false),
                    IssuerCn = table.Column<string>(type: "TEXT", nullable: false),
                    CertExpiresUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    IsSelfSigned = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsExpired = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsCnMismatch = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsUnknownCa = table.Column<bool>(type: "INTEGER", nullable: false),
                    ValidationError = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TlsCertAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UserAccountAuditFindings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    AccountName = table.Column<string>(type: "TEXT", nullable: false),
                    Issue = table.Column<string>(type: "TEXT", nullable: false),
                    IsAdmin = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasPassword = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    PasswordNeverExpires = table.Column<bool>(type: "INTEGER", nullable: false),
                    LastLogon = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Classification = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    AuditedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserAccountAuditFindings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "VssSnapshotEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    FolderPath = table.Column<string>(type: "TEXT", nullable: false),
                    SnapshotId = table.Column<string>(type: "TEXT", nullable: false),
                    SnapshotPath = table.Column<string>(type: "TEXT", nullable: false),
                    TriggerReason = table.Column<string>(type: "TEXT", nullable: false),
                    IsRestoreAction = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VssSnapshotEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "VulnerableSoftwareAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    SoftwareName = table.Column<string>(type: "TEXT", nullable: false),
                    SoftwareVersion = table.Column<string>(type: "TEXT", nullable: false),
                    CpeUri = table.Column<string>(type: "TEXT", nullable: false),
                    CveId = table.Column<string>(type: "TEXT", nullable: false),
                    CvssScore = table.Column<double>(type: "REAL", nullable: false),
                    CvssVector = table.Column<string>(type: "TEXT", nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VulnerableSoftwareAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "WebcamAccessEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    DevicePath = table.Column<string>(type: "TEXT", nullable: false),
                    AccessType = table.Column<string>(type: "TEXT", nullable: false),
                    WasBlocked = table.Column<bool>(type: "INTEGER", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebcamAccessEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "WpadAbuseAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    QueryType = table.Column<string>(type: "TEXT", nullable: false),
                    Hostname = table.Column<string>(type: "TEXT", nullable: false),
                    ResponderIp = table.Column<string>(type: "TEXT", nullable: false),
                    WpadDatContent = table.Column<string>(type: "TEXT", nullable: false),
                    DetectionReason = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WpadAbuseAlerts", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AutostartEntries_AuditedAtUtc",
                table: "AutostartEntries",
                column: "AuditedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_AutostartEntries_IsSuspicious",
                table: "AutostartEntries",
                column: "IsSuspicious");

            migrationBuilder.CreateIndex(
                name: "IX_BeaconingAnalyses_BeaconingScore",
                table: "BeaconingAnalyses",
                column: "BeaconingScore");

            migrationBuilder.CreateIndex(
                name: "IX_BeaconingAnalyses_DetectedAtUtc",
                table: "BeaconingAnalyses",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ClipboardHijackAlerts_DetectedAtUtc",
                table: "ClipboardHijackAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_MbrWriteAttemptAlerts_DetectedAtUtc",
                table: "MbrWriteAttemptAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_MbrWriteAttemptAlerts_Severity",
                table: "MbrWriteAttemptAlerts",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_MicrophoneAccessEvents_DetectedAtUtc",
                table: "MicrophoneAccessEvents",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_OpenPortInfos_LocalPort",
                table: "OpenPortInfos",
                column: "LocalPort");

            migrationBuilder.CreateIndex(
                name: "IX_OpenPortInfos_ScannedAtUtc",
                table: "OpenPortInfos",
                column: "ScannedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_PortScanAlerts_DetectedAtUtc",
                table: "PortScanAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_PortScanAlerts_Severity",
                table: "PortScanAlerts",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_ScreenCaptureAlerts_DetectedAtUtc",
                table: "ScreenCaptureAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ScreenLockerAlerts_DetectedAtUtc",
                table: "ScreenLockerAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityPostureIssues_CheckedAtUtc",
                table: "SecurityPostureIssues",
                column: "CheckedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityPostureIssues_Severity",
                table: "SecurityPostureIssues",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_SensitiveDataFindings_DataType",
                table: "SensitiveDataFindings",
                column: "DataType");

            migrationBuilder.CreateIndex(
                name: "IX_SensitiveDataFindings_FoundAtUtc",
                table: "SensitiveDataFindings",
                column: "FoundAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ServiceAuditFindings_AuditedAtUtc",
                table: "ServiceAuditFindings",
                column: "AuditedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_SmbLateralMovementAlerts_DetectedAtUtc",
                table: "SmbLateralMovementAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_SmbLateralMovementAlerts_Severity",
                table: "SmbLateralMovementAlerts",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_TlsCertAlerts_DetectedAtUtc",
                table: "TlsCertAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_TlsCertAlerts_Hostname",
                table: "TlsCertAlerts",
                column: "Hostname");

            migrationBuilder.CreateIndex(
                name: "IX_UserAccountAuditFindings_AuditedAtUtc",
                table: "UserAccountAuditFindings",
                column: "AuditedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_VssSnapshotEvents_CreatedAtUtc",
                table: "VssSnapshotEvents",
                column: "CreatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_VulnerableSoftwareAlerts_CvssScore",
                table: "VulnerableSoftwareAlerts",
                column: "CvssScore");

            migrationBuilder.CreateIndex(
                name: "IX_VulnerableSoftwareAlerts_DetectedAtUtc",
                table: "VulnerableSoftwareAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_WebcamAccessEvents_DetectedAtUtc",
                table: "WebcamAccessEvents",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_WpadAbuseAlerts_DetectedAtUtc",
                table: "WpadAbuseAlerts",
                column: "DetectedAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AutostartEntries");

            migrationBuilder.DropTable(
                name: "BeaconingAnalyses");

            migrationBuilder.DropTable(
                name: "ClipboardHijackAlerts");

            migrationBuilder.DropTable(
                name: "MbrWriteAttemptAlerts");

            migrationBuilder.DropTable(
                name: "MicrophoneAccessEvents");

            migrationBuilder.DropTable(
                name: "OpenPortInfos");

            migrationBuilder.DropTable(
                name: "PortScanAlerts");

            migrationBuilder.DropTable(
                name: "ScreenCaptureAlerts");

            migrationBuilder.DropTable(
                name: "ScreenLockerAlerts");

            migrationBuilder.DropTable(
                name: "SecurityPostureIssues");

            migrationBuilder.DropTable(
                name: "SensitiveDataFindings");

            migrationBuilder.DropTable(
                name: "ServiceAuditFindings");

            migrationBuilder.DropTable(
                name: "SmbLateralMovementAlerts");

            migrationBuilder.DropTable(
                name: "TlsCertAlerts");

            migrationBuilder.DropTable(
                name: "UserAccountAuditFindings");

            migrationBuilder.DropTable(
                name: "VssSnapshotEvents");

            migrationBuilder.DropTable(
                name: "VulnerableSoftwareAlerts");

            migrationBuilder.DropTable(
                name: "WebcamAccessEvents");

            migrationBuilder.DropTable(
                name: "WpadAbuseAlerts");
        }
    }
}
