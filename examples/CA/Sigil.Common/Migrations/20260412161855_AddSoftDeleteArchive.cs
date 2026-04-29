using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sigil.Common.Migrations
{
    /// <inheritdoc />
    public partial class AddSoftDeleteArchive : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "ArchivedAt",
                schema: "sigil",
                table: "IssuedCertificates",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsArchived",
                schema: "sigil",
                table: "IssuedCertificates",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTime>(
                name: "ArchivedAt",
                schema: "sigil",
                table: "Crls",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsArchived",
                schema: "sigil",
                table: "Crls",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTime>(
                name: "ArchivedAt",
                schema: "sigil",
                table: "CaCertificates",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsArchived",
                schema: "sigil",
                table: "CaCertificates",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ArchivedAt",
                schema: "sigil",
                table: "IssuedCertificates");

            migrationBuilder.DropColumn(
                name: "IsArchived",
                schema: "sigil",
                table: "IssuedCertificates");

            migrationBuilder.DropColumn(
                name: "ArchivedAt",
                schema: "sigil",
                table: "Crls");

            migrationBuilder.DropColumn(
                name: "IsArchived",
                schema: "sigil",
                table: "Crls");

            migrationBuilder.DropColumn(
                name: "ArchivedAt",
                schema: "sigil",
                table: "CaCertificates");

            migrationBuilder.DropColumn(
                name: "IsArchived",
                schema: "sigil",
                table: "CaCertificates");
        }
    }
}
