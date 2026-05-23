using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Sigil.Common.Migrations
{
    /// <inheritdoc />
    public partial class AddDidAndVcEntities : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CredentialSchemas",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    TypeUri = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Format = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ClaimsSchemaJson = table.Column<string>(type: "text", nullable: false),
                    DefaultValidityDays = table.Column<int>(type: "integer", nullable: true),
                    IsPreset = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CredentialSchemas", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DidTemplates",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    Method = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    KeyAlgorithm = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    EcdsaCurve = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    DefaultPurposes = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    IsPreset = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DidTemplates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DidDocuments",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    TrustDomainId = table.Column<int>(type: "integer", nullable: false),
                    DidTemplateId = table.Column<int>(type: "integer", nullable: true),
                    Did = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    Method = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Deactivated = table.Column<bool>(type: "boolean", nullable: false),
                    DeactivatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DidDocuments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DidDocuments_DidTemplates_DidTemplateId",
                        column: x => x.DidTemplateId,
                        principalSchema: "sigil",
                        principalTable: "DidTemplates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_DidDocuments_TrustDomains_TrustDomainId",
                        column: x => x.TrustDomainId,
                        principalSchema: "sigil",
                        principalTable: "TrustDomains",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "IssuedCredentials",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    TrustDomainId = table.Column<int>(type: "integer", nullable: false),
                    CredentialSchemaId = table.Column<int>(type: "integer", nullable: false),
                    IssuerDidDocumentId = table.Column<int>(type: "integer", nullable: false),
                    SubjectDid = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    ClaimsJson = table.Column<string>(type: "text", nullable: false),
                    Format = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    SignedCredential = table.Column<string>(type: "text", nullable: false),
                    CredentialId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    IssuedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ValidUntil = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Revoked = table.Column<bool>(type: "boolean", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IssuedCredentials", x => x.Id);
                    table.ForeignKey(
                        name: "FK_IssuedCredentials_CredentialSchemas_CredentialSchemaId",
                        column: x => x.CredentialSchemaId,
                        principalSchema: "sigil",
                        principalTable: "CredentialSchemas",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_IssuedCredentials_DidDocuments_IssuerDidDocumentId",
                        column: x => x.IssuerDidDocumentId,
                        principalSchema: "sigil",
                        principalTable: "DidDocuments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_IssuedCredentials_TrustDomains_TrustDomainId",
                        column: x => x.TrustDomainId,
                        principalSchema: "sigil",
                        principalTable: "TrustDomains",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "VerificationMethods",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    DidDocumentId = table.Column<int>(type: "integer", nullable: false),
                    MethodId = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    KeyAlgorithm = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    Provider = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    KeyIdentifier = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    KeySize = table.Column<int>(type: "integer", nullable: false),
                    PublicKeyMultibase = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    Purposes = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VerificationMethods", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VerificationMethods_DidDocuments_DidDocumentId",
                        column: x => x.DidDocumentId,
                        principalSchema: "sigil",
                        principalTable: "DidDocuments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CredentialSchemas_Name",
                schema: "sigil",
                table: "CredentialSchemas",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DidDocuments_Did",
                schema: "sigil",
                table: "DidDocuments",
                column: "Did",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DidDocuments_DidTemplateId",
                schema: "sigil",
                table: "DidDocuments",
                column: "DidTemplateId");

            migrationBuilder.CreateIndex(
                name: "IX_DidDocuments_TrustDomainId",
                schema: "sigil",
                table: "DidDocuments",
                column: "TrustDomainId");

            migrationBuilder.CreateIndex(
                name: "IX_DidTemplates_Name",
                schema: "sigil",
                table: "DidTemplates",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_IssuedCredentials_CredentialId",
                schema: "sigil",
                table: "IssuedCredentials",
                column: "CredentialId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_IssuedCredentials_CredentialSchemaId",
                schema: "sigil",
                table: "IssuedCredentials",
                column: "CredentialSchemaId");

            migrationBuilder.CreateIndex(
                name: "IX_IssuedCredentials_IssuerDidDocumentId",
                schema: "sigil",
                table: "IssuedCredentials",
                column: "IssuerDidDocumentId");

            migrationBuilder.CreateIndex(
                name: "IX_IssuedCredentials_TrustDomainId",
                schema: "sigil",
                table: "IssuedCredentials",
                column: "TrustDomainId");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationMethods_DidDocumentId",
                schema: "sigil",
                table: "VerificationMethods",
                column: "DidDocumentId");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationMethods_MethodId",
                schema: "sigil",
                table: "VerificationMethods",
                column: "MethodId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "IssuedCredentials",
                schema: "sigil");

            migrationBuilder.DropTable(
                name: "VerificationMethods",
                schema: "sigil");

            migrationBuilder.DropTable(
                name: "CredentialSchemas",
                schema: "sigil");

            migrationBuilder.DropTable(
                name: "DidDocuments",
                schema: "sigil");

            migrationBuilder.DropTable(
                name: "DidTemplates",
                schema: "sigil");
        }
    }
}
