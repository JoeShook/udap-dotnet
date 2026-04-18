using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sigil.Common.Migrations
{
    /// <inheritdoc />
    public partial class AddIssuedCertStoreProviderHint : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte>(
                name: "CertSecurityLevel",
                schema: "sigil",
                table: "IssuedCertificates",
                type: "smallint",
                nullable: false,
                defaultValue: (byte)0);

            migrationBuilder.AddColumn<string>(
                name: "StoreProviderHint",
                schema: "sigil",
                table: "IssuedCertificates",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CertSecurityLevel",
                schema: "sigil",
                table: "IssuedCertificates");

            migrationBuilder.DropColumn(
                name: "StoreProviderHint",
                schema: "sigil",
                table: "IssuedCertificates");
        }
    }
}
