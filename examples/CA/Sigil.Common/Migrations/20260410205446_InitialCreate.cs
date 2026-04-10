using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Sigil.Common.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "sigil");

            migrationBuilder.CreateTable(
                name: "CertificateTemplates",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    CertificateType = table.Column<byte>(type: "smallint", nullable: false),
                    KeyAlgorithm = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    KeySize = table.Column<int>(type: "integer", nullable: false),
                    ValidityDays = table.Column<int>(type: "integer", nullable: false),
                    KeyUsageFlags = table.Column<int>(type: "integer", nullable: false),
                    IsKeyUsageCritical = table.Column<bool>(type: "boolean", nullable: false),
                    ExtendedKeyUsageOids = table.Column<string>(type: "text", nullable: true),
                    IsBasicConstraintsCa = table.Column<bool>(type: "boolean", nullable: false),
                    SubjectTemplate = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    IncludeCdp = table.Column<bool>(type: "boolean", nullable: false),
                    IncludeAia = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateTemplates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Communities",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Communities", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Jobs",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    JobType = table.Column<byte>(type: "smallint", nullable: false),
                    CronExpression = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    TargetCertificateId = table.Column<int>(type: "integer", nullable: true),
                    TargetEntityType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    LastRunAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    NextRunAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Configuration = table.Column<string>(type: "text", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Jobs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CaCertificates",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    CommunityId = table.Column<int>(type: "integer", nullable: false),
                    ParentId = table.Column<int>(type: "integer", nullable: true),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Subject = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    X509CertificatePem = table.Column<string>(type: "text", nullable: false),
                    EncryptedPfxBytes = table.Column<byte[]>(type: "bytea", nullable: true),
                    PfxPassword = table.Column<string>(type: "text", nullable: true),
                    Thumbprint = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    SerialNumber = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    KeyAlgorithm = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    KeySize = table.Column<int>(type: "integer", nullable: false),
                    NotBefore = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    NotAfter = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CrlDistributionPoint = table.Column<string>(type: "text", nullable: true),
                    AuthorityInfoAccessUri = table.Column<string>(type: "text", nullable: true),
                    CertSecurityLevel = table.Column<byte>(type: "smallint", nullable: false),
                    StoreProviderHint = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaCertificates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CaCertificates_CaCertificates_ParentId",
                        column: x => x.ParentId,
                        principalSchema: "sigil",
                        principalTable: "CaCertificates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_CaCertificates_Communities_CommunityId",
                        column: x => x.CommunityId,
                        principalSchema: "sigil",
                        principalTable: "Communities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "JobExecutions",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    JobId = table.Column<int>(type: "integer", nullable: false),
                    StartedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CompletedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Status = table.Column<byte>(type: "smallint", nullable: false),
                    ResultMessage = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_JobExecutions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_JobExecutions_Jobs_JobId",
                        column: x => x.JobId,
                        principalSchema: "sigil",
                        principalTable: "Jobs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

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

            migrationBuilder.CreateTable(
                name: "IssuedCertificates",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    IssuingCaCertificateId = table.Column<int>(type: "integer", nullable: false),
                    TemplateId = table.Column<int>(type: "integer", nullable: true),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Subject = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    SubjectAltNames = table.Column<string>(type: "text", nullable: true),
                    X509CertificatePem = table.Column<string>(type: "text", nullable: false),
                    EncryptedPfxBytes = table.Column<byte[]>(type: "bytea", nullable: true),
                    PfxPassword = table.Column<string>(type: "text", nullable: true),
                    Thumbprint = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    SerialNumber = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    KeyAlgorithm = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    KeySize = table.Column<int>(type: "integer", nullable: false),
                    NotBefore = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    NotAfter = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    IsRevoked = table.Column<bool>(type: "boolean", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IssuedCertificates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_IssuedCertificates_CaCertificates_IssuingCaCertificateId",
                        column: x => x.IssuingCaCertificateId,
                        principalSchema: "sigil",
                        principalTable: "CaCertificates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_IssuedCertificates_CertificateTemplates_TemplateId",
                        column: x => x.TemplateId,
                        principalSchema: "sigil",
                        principalTable: "CertificateTemplates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "CertificateRevocations",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    CrlId = table.Column<int>(type: "integer", nullable: false),
                    RevokedCertSerialNumber = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    RevokedCertThumbprint = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    RevocationDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RevocationReason = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateRevocations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertificateRevocations_Crls_CrlId",
                        column: x => x.CrlId,
                        principalSchema: "sigil",
                        principalTable: "Crls",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CaCertificates_CommunityId",
                schema: "sigil",
                table: "CaCertificates",
                column: "CommunityId");

            migrationBuilder.CreateIndex(
                name: "IX_CaCertificates_ParentId",
                schema: "sigil",
                table: "CaCertificates",
                column: "ParentId");

            migrationBuilder.CreateIndex(
                name: "IX_CaCertificates_Thumbprint",
                schema: "sigil",
                table: "CaCertificates",
                column: "Thumbprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRevocations_CrlId",
                schema: "sigil",
                table: "CertificateRevocations",
                column: "CrlId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTemplates_Name",
                schema: "sigil",
                table: "CertificateTemplates",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Communities_Name",
                schema: "sigil",
                table: "Communities",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Crls_CaCertificateId",
                schema: "sigil",
                table: "Crls",
                column: "CaCertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_IssuedCertificates_IssuingCaCertificateId",
                schema: "sigil",
                table: "IssuedCertificates",
                column: "IssuingCaCertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_IssuedCertificates_TemplateId",
                schema: "sigil",
                table: "IssuedCertificates",
                column: "TemplateId");

            migrationBuilder.CreateIndex(
                name: "IX_IssuedCertificates_Thumbprint",
                schema: "sigil",
                table: "IssuedCertificates",
                column: "Thumbprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_JobExecutions_JobId",
                schema: "sigil",
                table: "JobExecutions",
                column: "JobId");

            migrationBuilder.CreateIndex(
                name: "IX_Jobs_NextRunAt",
                schema: "sigil",
                table: "Jobs",
                column: "NextRunAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CertificateRevocations",
                schema: "sigil");

            migrationBuilder.DropTable(
                name: "IssuedCertificates",
                schema: "sigil");

            migrationBuilder.DropTable(
                name: "JobExecutions",
                schema: "sigil");

            migrationBuilder.DropTable(
                name: "Crls",
                schema: "sigil");

            migrationBuilder.DropTable(
                name: "CertificateTemplates",
                schema: "sigil");

            migrationBuilder.DropTable(
                name: "Jobs",
                schema: "sigil");

            migrationBuilder.DropTable(
                name: "CaCertificates",
                schema: "sigil");

            migrationBuilder.DropTable(
                name: "Communities",
                schema: "sigil");
        }
    }
}
