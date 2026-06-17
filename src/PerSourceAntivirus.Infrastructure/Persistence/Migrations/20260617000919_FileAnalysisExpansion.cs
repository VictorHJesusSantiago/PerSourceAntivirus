using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PerSourceAntivirus.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class FileAnalysisExpansion : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "FileMetadataResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ScannedFileId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Author = table.Column<string>(type: "TEXT", nullable: true),
                    Creator = table.Column<string>(type: "TEXT", nullable: true),
                    DocumentCreatedUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    DocumentModifiedUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    HasEmbeddedFiles = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasJavaScript = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsPolyglot = table.Column<bool>(type: "INTEGER", nullable: false),
                    Anomalies = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FileMetadataResults", x => x.Id);
                    table.ForeignKey(
                        name: "FK_FileMetadataResults_ScannedFiles_ScannedFileId",
                        column: x => x.ScannedFileId,
                        principalTable: "ScannedFiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "OfficeMacroResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ScannedFileId = table.Column<Guid>(type: "TEXT", nullable: false),
                    HasMacros = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasAutoExec = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasNetworkAccess = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasProcessExecution = table.Column<bool>(type: "INTEGER", nullable: false),
                    HasObfuscation = table.Column<bool>(type: "INTEGER", nullable: false),
                    SuspiciousPatterns = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OfficeMacroResults", x => x.Id);
                    table.ForeignKey(
                        name: "FK_OfficeMacroResults_ScannedFiles_ScannedFileId",
                        column: x => x.ScannedFileId,
                        principalTable: "ScannedFiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_FileMetadataResults_ScannedFileId",
                table: "FileMetadataResults",
                column: "ScannedFileId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OfficeMacroResults_ScannedFileId",
                table: "OfficeMacroResults",
                column: "ScannedFileId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "FileMetadataResults");

            migrationBuilder.DropTable(
                name: "OfficeMacroResults");
        }
    }
}
