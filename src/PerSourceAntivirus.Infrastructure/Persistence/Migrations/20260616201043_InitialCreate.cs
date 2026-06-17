using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PerSourceAntivirus.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "NetworkConnectionEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CapturedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Protocol = table.Column<int>(type: "INTEGER", nullable: false),
                    SourceAddress = table.Column<string>(type: "TEXT", nullable: false),
                    SourcePort = table.Column<int>(type: "INTEGER", nullable: false),
                    DestinationAddress = table.Column<string>(type: "TEXT", nullable: false),
                    DestinationPort = table.Column<int>(type: "INTEGER", nullable: false),
                    PacketLength = table.Column<int>(type: "INTEGER", nullable: false),
                    IsBlocklisted = table.Column<bool>(type: "INTEGER", nullable: false),
                    BlocklistReason = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NetworkConnectionEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ScannedFiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    FilePath = table.Column<string>(type: "TEXT", nullable: false),
                    FileName = table.Column<string>(type: "TEXT", nullable: false),
                    SizeBytes = table.Column<long>(type: "INTEGER", nullable: false),
                    Sha256Hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Entropy = table.Column<double>(type: "REAL", nullable: false),
                    ScannedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ThreatStatus = table.Column<int>(type: "INTEGER", nullable: false),
                    IsQuarantined = table.Column<bool>(type: "INTEGER", nullable: false),
                    QuarantinedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    QuarantinePath = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScannedFiles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PeAnalysisResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ScannedFileId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Is64Bit = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsDll = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsDotNet = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsSigned = table.Column<bool>(type: "INTEGER", nullable: false),
                    SuspiciousImports = table.Column<string>(type: "TEXT", nullable: false),
                    Anomalies = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PeAnalysisResults", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PeAnalysisResults_ScannedFiles_ScannedFileId",
                        column: x => x.ScannedFileId,
                        principalTable: "ScannedFiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ScriptAnalysisResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ScannedFileId = table.Column<Guid>(type: "TEXT", nullable: false),
                    ScriptType = table.Column<int>(type: "INTEGER", nullable: false),
                    HasObfuscation = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasNetworkAccess = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasProcessExecution = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasFileSystemAccess = table.Column<bool>(type: "INTEGER", nullable: false),
                    SuspiciousPatterns = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScriptAnalysisResults", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ScriptAnalysisResults_ScannedFiles_ScannedFileId",
                        column: x => x.ScannedFileId,
                        principalTable: "ScannedFiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "YaraMatches",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ScannedFileId = table.Column<Guid>(type: "TEXT", nullable: false),
                    RuleIdentifier = table.Column<string>(type: "TEXT", nullable: false),
                    Tags = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_YaraMatches", x => x.Id);
                    table.ForeignKey(
                        name: "FK_YaraMatches_ScannedFiles_ScannedFileId",
                        column: x => x.ScannedFileId,
                        principalTable: "ScannedFiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "PeSections",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    PeAnalysisResultId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    SizeOfRawData = table.Column<uint>(type: "INTEGER", nullable: false),
                    Entropy = table.Column<double>(type: "REAL", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PeSections", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PeSections_PeAnalysisResults_PeAnalysisResultId",
                        column: x => x.PeAnalysisResultId,
                        principalTable: "PeAnalysisResults",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PeAnalysisResults_ScannedFileId",
                table: "PeAnalysisResults",
                column: "ScannedFileId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_PeSections_PeAnalysisResultId",
                table: "PeSections",
                column: "PeAnalysisResultId");

            migrationBuilder.CreateIndex(
                name: "IX_ScriptAnalysisResults_ScannedFileId",
                table: "ScriptAnalysisResults",
                column: "ScannedFileId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_YaraMatches_ScannedFileId",
                table: "YaraMatches",
                column: "ScannedFileId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "NetworkConnectionEvents");

            migrationBuilder.DropTable(
                name: "PeSections");

            migrationBuilder.DropTable(
                name: "ScriptAnalysisResults");

            migrationBuilder.DropTable(
                name: "YaraMatches");

            migrationBuilder.DropTable(
                name: "PeAnalysisResults");

            migrationBuilder.DropTable(
                name: "ScannedFiles");
        }
    }
}
