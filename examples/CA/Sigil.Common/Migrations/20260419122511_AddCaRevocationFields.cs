using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sigil.Common.Migrations
{
    /// <inheritdoc />
    public partial class AddCaRevocationFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsRevoked",
                schema: "sigil",
                table: "CaCertificates",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "RevocationReason",
                schema: "sigil",
                table: "CaCertificates",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "RevokedAt",
                schema: "sigil",
                table: "CaCertificates",
                type: "timestamp with time zone",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsRevoked",
                schema: "sigil",
                table: "CaCertificates");

            migrationBuilder.DropColumn(
                name: "RevocationReason",
                schema: "sigil",
                table: "CaCertificates");

            migrationBuilder.DropColumn(
                name: "RevokedAt",
                schema: "sigil",
                table: "CaCertificates");
        }
    }
}
