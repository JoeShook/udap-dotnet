using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Sigil.Common.Migrations
{
    /// <inheritdoc />
    public partial class AddCrlEntity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CertificateRevocations_CaCertificates_CaCertificateId",
                schema: "sigil",
                table: "CertificateRevocations");

            migrationBuilder.RenameColumn(
                name: "CaCertificateId",
                schema: "sigil",
                table: "CertificateRevocations",
                newName: "CrlId");

            migrationBuilder.RenameIndex(
                name: "IX_CertificateRevocations_CaCertificateId",
                schema: "sigil",
                table: "CertificateRevocations",
                newName: "IX_CertificateRevocations_CrlId");

            migrationBuilder.CreateTable(
                name: "Crls",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    CaCertificateId = table.Column<int>(type: "integer", nullable: false),
                    CrlNumber = table.Column<long>(type: "bigint", nullable: false),
                    ThisUpdate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    NextUpdate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    SignatureAlgorithm = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    RawBytes = table.Column<byte[]>(type: "bytea", nullable: false),
                    FileName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    SignatureValid = table.Column<bool>(type: "boolean", nullable: false),
                    ImportedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Crls", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Crls_CaCertificates_CaCertificateId",
                        column: x => x.CaCertificateId,
                        principalSchema: "sigil",
                        principalTable: "CaCertificates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Crls_CaCertificateId",
                schema: "sigil",
                table: "Crls",
                column: "CaCertificateId");

            migrationBuilder.AddForeignKey(
                name: "FK_CertificateRevocations_Crls_CrlId",
                schema: "sigil",
                table: "CertificateRevocations",
                column: "CrlId",
                principalSchema: "sigil",
                principalTable: "Crls",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CertificateRevocations_Crls_CrlId",
                schema: "sigil",
                table: "CertificateRevocations");

            migrationBuilder.DropTable(
                name: "Crls",
                schema: "sigil");

            migrationBuilder.RenameColumn(
                name: "CrlId",
                schema: "sigil",
                table: "CertificateRevocations",
                newName: "CaCertificateId");

            migrationBuilder.RenameIndex(
                name: "IX_CertificateRevocations_CrlId",
                schema: "sigil",
                table: "CertificateRevocations",
                newName: "IX_CertificateRevocations_CaCertificateId");

            migrationBuilder.AddForeignKey(
                name: "FK_CertificateRevocations_CaCertificates_CaCertificateId",
                schema: "sigil",
                table: "CertificateRevocations",
                column: "CaCertificateId",
                principalSchema: "sigil",
                principalTable: "CaCertificates",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
