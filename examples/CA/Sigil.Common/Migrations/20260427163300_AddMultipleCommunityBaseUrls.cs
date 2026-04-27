using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Sigil.Common.Migrations
{
    /// <inheritdoc />
    public partial class AddMultipleCommunityBaseUrls : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CommunityBaseUrls",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    CommunityId = table.Column<int>(type: "integer", nullable: false),
                    Url = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    SortOrder = table.Column<int>(type: "integer", nullable: false),
                    PublishingBasePath = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CommunityBaseUrls", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CommunityBaseUrls_Communities_CommunityId",
                        column: x => x.CommunityId,
                        principalSchema: "sigil",
                        principalTable: "Communities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CommunityBaseUrls_CommunityId_SortOrder",
                schema: "sigil",
                table: "CommunityBaseUrls",
                columns: new[] { "CommunityId", "SortOrder" });

            // Migrate existing BaseUrl data to the new table
            migrationBuilder.Sql("""
                INSERT INTO sigil."CommunityBaseUrls" ("CommunityId", "Url", "SortOrder")
                SELECT "Id", "BaseUrl", 0
                FROM sigil."Communities"
                WHERE "BaseUrl" IS NOT NULL AND "BaseUrl" <> ''
                """);

            migrationBuilder.DropColumn(
                name: "BaseUrl",
                schema: "sigil",
                table: "Communities");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "BaseUrl",
                schema: "sigil",
                table: "Communities",
                type: "text",
                nullable: true);

            // Restore first base URL back to the BaseUrl column
            migrationBuilder.Sql("""
                UPDATE sigil."Communities" c
                SET "BaseUrl" = bu."Url"
                FROM sigil."CommunityBaseUrls" bu
                WHERE bu."CommunityId" = c."Id" AND bu."SortOrder" = 0
                """);

            migrationBuilder.DropTable(
                name: "CommunityBaseUrls",
                schema: "sigil");
        }
    }
}
