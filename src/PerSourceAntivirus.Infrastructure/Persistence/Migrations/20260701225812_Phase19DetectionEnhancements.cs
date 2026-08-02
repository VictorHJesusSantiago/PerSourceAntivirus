using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PerSourceAntivirus.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Phase19DetectionEnhancements : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CertificateTrustAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    FilePath = table.Column<string>(type: "TEXT", nullable: false),
                    Thumbprint = table.Column<string>(type: "TEXT", nullable: false),
                    SubjectName = table.Column<string>(type: "TEXT", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateTrustAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CertificateTrustEntries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Thumbprint = table.Column<string>(type: "TEXT", nullable: false),
                    SubjectName = table.Column<string>(type: "TEXT", nullable: false),
                    TrustLevel = table.Column<string>(type: "TEXT", nullable: false),
                    Note = table.Column<string>(type: "TEXT", nullable: true),
                    AddedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateTrustEntries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CryptojackingAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    CpuPercent = table.Column<double>(type: "REAL", nullable: false),
                    RemoteAddress = table.Column<string>(type: "TEXT", nullable: true),
                    RemotePort = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectionReason = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CryptojackingAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CustomSignatureMatches",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    FilePath = table.Column<string>(type: "TEXT", nullable: false),
                    FileHashSha256 = table.Column<string>(type: "TEXT", nullable: false),
                    SignatureName = table.Column<string>(type: "TEXT", nullable: false),
                    MatchType = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CustomSignatureMatches", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DllHijackAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    DllName = table.Column<string>(type: "TEXT", nullable: false),
                    LoadedDllPath = table.Column<string>(type: "TEXT", nullable: false),
                    ExpectedSystemDllPath = table.Column<string>(type: "TEXT", nullable: true),
                    HijackType = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DllHijackAlerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UnsignedBinaryAlerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", nullable: false),
                    ProcessId = table.Column<int>(type: "INTEGER", nullable: false),
                    FilePath = table.Column<string>(type: "TEXT", nullable: false),
                    IsSigned = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsTrusted = table.Column<bool>(type: "INTEGER", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UnsignedBinaryAlerts", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTrustAlerts_DetectedAtUtc",
                table: "CertificateTrustAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTrustEntries_Thumbprint",
                table: "CertificateTrustEntries",
                column: "Thumbprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CryptojackingAlerts_DetectedAtUtc",
                table: "CryptojackingAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_CustomSignatureMatches_DetectedAtUtc",
                table: "CustomSignatureMatches",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_CustomSignatureMatches_FileHashSha256",
                table: "CustomSignatureMatches",
                column: "FileHashSha256");

            migrationBuilder.CreateIndex(
                name: "IX_DllHijackAlerts_DetectedAtUtc",
                table: "DllHijackAlerts",
                column: "DetectedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_UnsignedBinaryAlerts_DetectedAtUtc",
                table: "UnsignedBinaryAlerts",
                column: "DetectedAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CertificateTrustAlerts");

            migrationBuilder.DropTable(
                name: "CertificateTrustEntries");

            migrationBuilder.DropTable(
                name: "CryptojackingAlerts");

            migrationBuilder.DropTable(
                name: "CustomSignatureMatches");

            migrationBuilder.DropTable(
                name: "DllHijackAlerts");

            migrationBuilder.DropTable(
                name: "UnsignedBinaryAlerts");
        }
    }
}
