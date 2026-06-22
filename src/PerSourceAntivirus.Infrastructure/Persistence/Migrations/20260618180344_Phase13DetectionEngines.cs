using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PerSourceAntivirus.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Phase13DetectionEngines : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AdsStreamInfos",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ScannedFileId = table.Column<Guid>(type: "TEXT", nullable: false),
                    StreamName = table.Column<string>(type: "TEXT", nullable: false),
                    StreamSize = table.Column<long>(type: "INTEGER", nullable: false),
                    IsSuspicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AdsStreamInfos", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AdsStreamInfos_ScannedFiles_ScannedFileId",
                        column: x => x.ScannedFileId,
                        principalTable: "ScannedFiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AmsiScanEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ContentName = table.Column<string>(type: "TEXT", nullable: false),
                    AmsiResult = table.Column<int>(type: "INTEGER", nullable: false),
                    WasBlocked = table.Column<bool>(type: "INTEGER", nullable: false),
                    ScannedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AmsiScanEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ArchiveEntryResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ArchiveScannedFileId = table.Column<Guid>(type: "TEXT", nullable: false),
                    EntryPath = table.Column<string>(type: "TEXT", nullable: false),
                    EntrySize = table.Column<long>(type: "INTEGER", nullable: false),
                    ScanDepth = table.Column<int>(type: "INTEGER", nullable: false),
                    IsSuspicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    DetectionReason = table.Column<string>(type: "TEXT", nullable: false),
                    Entropy = table.Column<double>(type: "REAL", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ArchiveEntryResults", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DgaAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Hostname = table.Column<string>(type: "TEXT", nullable: false),
                    EntropyScore = table.Column<double>(type: "REAL", nullable: false),
                    ConsonantVowelRatio = table.Column<double>(type: "REAL", nullable: false),
                    NxdomainStreak = table.Column<int>(type: "INTEGER", nullable: false),
                    Probability = table.Column<double>(type: "REAL", nullable: false),
                    IsDga = table.Column<bool>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DgaAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "EmailScanResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ScannedFileId = table.Column<Guid>(type: "TEXT", nullable: false),
                    AttachmentCount = table.Column<int>(type: "INTEGER", nullable: false),
                    SuspiciousAttachmentCount = table.Column<int>(type: "INTEGER", nullable: false),
                    PhishingLinkCount = table.Column<int>(type: "INTEGER", nullable: false),
                    SuspiciousAttachmentNames = table.Column<string>(type: "TEXT", nullable: false),
                    PhishingIndicators = table.Column<string>(type: "TEXT", nullable: false),
                    HasSpoofedSender = table.Column<bool>(type: "INTEGER", nullable: false),
                    RiskScore = table.Column<int>(type: "INTEGER", nullable: false),
                    ScannedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailScanResults", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EmailScanResults_ScannedFiles_ScannedFileId",
                        column: x => x.ScannedFileId,
                        principalTable: "ScannedFiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "EmulationResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    FilePath = table.Column<string>(type: "TEXT", nullable: false),
                    InstructionCount = table.Column<int>(type: "INTEGER", nullable: false),
                    ApiCallsIntercepted = table.Column<int>(type: "INTEGER", nullable: false),
                    IsSuspicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    DetectedPatterns = table.Column<string>(type: "TEXT", nullable: false),
                    EmulatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmulationResults", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "FilelessAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    TechniqueType = table.Column<string>(type: "TEXT", nullable: false),
                    Detail = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FilelessAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "LolBinAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    Arguments = table.Column<string>(type: "TEXT", nullable: false),
                    LolbinName = table.Column<string>(type: "TEXT", nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    MitreTechnique = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    AlertedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LolBinAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PdfScanResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ScannedFileId = table.Column<Guid>(type: "TEXT", nullable: false),
                    HasJavaScript = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasOpenAction = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasLaunchAction = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasRichMedia = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasXfa = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasEmbeddedFiles = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasObjStm = table.Column<bool>(type: "INTEGER", nullable: false),
                    MaliciousObjectTypes = table.Column<string>(type: "TEXT", nullable: false),
                    RiskScore = table.Column<int>(type: "INTEGER", nullable: false),
                    ScannedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PdfScanResults", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PdfScanResults_ScannedFiles_ScannedFileId",
                        column: x => x.ScannedFileId,
                        principalTable: "ScannedFiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SteganographyAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    FilePath = table.Column<string>(type: "TEXT", nullable: false),
                    ChiSquareScore = table.Column<double>(type: "REAL", nullable: false),
                    HistogramAnomalyScore = table.Column<double>(type: "REAL", nullable: false),
                    ChannelEntropy = table.Column<double>(type: "REAL", nullable: false),
                    IsSuspicious = table.Column<bool>(type: "INTEGER", nullable: false),
                    SuspicionReasons = table.Column<string>(type: "TEXT", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SteganographyAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UnpackingResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    FilePath = table.Column<string>(type: "TEXT", nullable: false),
                    DetectedPacker = table.Column<string>(type: "TEXT", nullable: false),
                    IsPacked = table.Column<bool>(type: "INTEGER", nullable: false),
                    WasUnpacked = table.Column<bool>(type: "INTEGER", nullable: false),
                    UnpackedFilePath = table.Column<string>(type: "TEXT", nullable: true),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UnpackingResults", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AdsStreamInfos_ScannedFileId",
                table: "AdsStreamInfos",
                column: "ScannedFileId");

            migrationBuilder.CreateIndex(
                name: "IX_AmsiScanEvents_ScannedAtUtc",
                table: "AmsiScanEvents",
                column: "ScannedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ArchiveEntryResults_ArchiveScannedFileId",
                table: "ArchiveEntryResults",
                column: "ArchiveScannedFileId");

            migrationBuilder.CreateIndex(
                name: "IX_DgaAlerts_DetectedAtUtc",
                table: "DgaAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_DgaAlerts_IsDga",
                table: "DgaAlerts",
                column: "IsDga");

            migrationBuilder.CreateIndex(
                name: "IX_EmailScanResults_ScannedFileId",
                table: "EmailScanResults",
                column: "ScannedFileId");

            migrationBuilder.CreateIndex(
                name: "IX_EmulationResults_EmulatedAtUtc",
                table: "EmulationResults",
                column: "EmulatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_FilelessAlerts_DetectedAtUtc",
                table: "FilelessAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_LolBinAlerts_AlertedAtUtc",
                table: "LolBinAlerts",
                column: "AlertedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_LolBinAlerts_Severity",
                table: "LolBinAlerts",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_PdfScanResults_ScannedFileId",
                table: "PdfScanResults",
                column: "ScannedFileId");

            migrationBuilder.CreateIndex(
                name: "IX_SteganographyAlerts_DetectedAtUtc",
                table: "SteganographyAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_SteganographyAlerts_IsSuspicious",
                table: "SteganographyAlerts",
                column: "IsSuspicious");

            migrationBuilder.CreateIndex(
                name: "IX_UnpackingResults_DetectedAtUtc",
                table: "UnpackingResults",
                column: "DetectedAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AdsStreamInfos");

            migrationBuilder.DropTable(
                name: "AmsiScanEvents");

            migrationBuilder.DropTable(
                name: "ArchiveEntryResults");

            migrationBuilder.DropTable(
                name: "DgaAlerts");

            migrationBuilder.DropTable(
                name: "EmailScanResults");

            migrationBuilder.DropTable(
                name: "EmulationResults");

            migrationBuilder.DropTable(
                name: "FilelessAlerts");

            migrationBuilder.DropTable(
                name: "LolBinAlerts");

            migrationBuilder.DropTable(
                name: "PdfScanResults");

            migrationBuilder.DropTable(
                name: "SteganographyAlerts");

            migrationBuilder.DropTable(
                name: "UnpackingResults");
        }
    }
}
