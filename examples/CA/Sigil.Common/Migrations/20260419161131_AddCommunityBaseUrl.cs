using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sigil.Common.Migrations
{
    /// <inheritdoc />
    public partial class AddCommunityBaseUrl : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "BaseUrl",
                schema: "sigil",
                table: "Communities",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "BaseUrl",
                schema: "sigil",
                table: "Communities");
        }
    }
}
