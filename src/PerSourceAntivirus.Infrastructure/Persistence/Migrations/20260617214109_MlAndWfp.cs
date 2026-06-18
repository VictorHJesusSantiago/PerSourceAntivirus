using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PerSourceAntivirus.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class MlAndWfp : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PeMlPredictions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    FilePath = table.Column<string>(type: "TEXT", nullable: false),
                    MaliciousProbability = table.Column<float>(type: "REAL", nullable: false),
                    Classification = table.Column<string>(type: "TEXT", nullable: false),
                    ModelVersion = table.Column<string>(type: "TEXT", nullable: false),
                    PredictedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    FeaturesJson = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PeMlPredictions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "WfpBlocks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    IpAddress = table.Column<string>(type: "TEXT", nullable: false),
                    FilterIdOutboundV4 = table.Column<ulong>(type: "INTEGER", nullable: false),
                    FilterIdInboundV4 = table.Column<ulong>(type: "INTEGER", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", nullable: false),
                    AddedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WfpBlocks", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PeMlPredictions_Classification",
                table: "PeMlPredictions",
                column: "Classification");

            migrationBuilder.CreateIndex(
                name: "IX_WfpBlocks_IpAddress_IsActive",
                table: "WfpBlocks",
                columns: new[] { "IpAddress", "IsActive" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PeMlPredictions");

            migrationBuilder.DropTable(
                name: "WfpBlocks");
        }
    }
}
