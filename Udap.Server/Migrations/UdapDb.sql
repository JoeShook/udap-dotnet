CREATE TABLE IF NOT EXISTS "__EFMigrationsHistory" (
    "MigrationId" character varying(150) NOT NULL,
    "ProductVersion" character varying(32) NOT NULL,
    CONSTRAINT "PK___EFMigrationsHistory" PRIMARY KEY ("MigrationId")
);

START TRANSACTION;

CREATE TABLE "UdapCommunities" (
    "Id" integer GENERATED ALWAYS AS IDENTITY,
    "Name" character varying(200) NOT NULL,
    "Enabled" integer NOT NULL,
    "Default" integer NOT NULL,
    CONSTRAINT "PK_UdapCommunities" PRIMARY KEY ("Id")
);

CREATE TABLE "UdapRootCertificates" (
    "Id" integer GENERATED ALWAYS AS IDENTITY,
    "Enabled" boolean NOT NULL,
    "Name" text NOT NULL,
    "X509Certificate" text NOT NULL,
    "Thumbprint" text NOT NULL,
    "BeginDate" timestamp with time zone NOT NULL,
    "EndDate" timestamp with time zone NOT NULL,
    CONSTRAINT "PK_UdapRootCertificates" PRIMARY KEY ("Id")
);

CREATE TABLE "UdapAnchors" (
    "Id" integer GENERATED ALWAYS AS IDENTITY,
    "Enabled" boolean NOT NULL,
    "Name" text NOT NULL,
    "X509Certificate" text NOT NULL,
    "Thumbprint" text NOT NULL,
    "BeginDate" timestamp with time zone NOT NULL,
    "EndDate" timestamp with time zone NOT NULL,
    "CommunityId" integer NOT NULL,
    CONSTRAINT "PK_UdapAnchors" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_Anchor_Communities" FOREIGN KEY ("CommunityId") REFERENCES "UdapCommunities" ("Id") ON DELETE CASCADE
);

CREATE TABLE "UdapCertifications" (
    "Id" integer GENERATED ALWAYS AS IDENTITY,
    "Name" character varying(200) NOT NULL,
    "CommunityId" integer NULL,
    CONSTRAINT "PK_UdapCertifications" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_UdapCertifications_UdapCommunities_CommunityId" FOREIGN KEY ("CommunityId") REFERENCES "UdapCommunities" ("Id")
);

CREATE TABLE "UdapAnchorCertification" (
    "AnchorId" integer NOT NULL,
    "CertificationId" integer NOT NULL,
    CONSTRAINT "PK_UdapAnchorCertification" PRIMARY KEY ("AnchorId", "CertificationId"),
    CONSTRAINT "FK_AnchorCertification_Anchor" FOREIGN KEY ("AnchorId") REFERENCES "UdapAnchors" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_AnchorCertification_Certification" FOREIGN KEY ("CertificationId") REFERENCES "UdapCertifications" ("Id") ON DELETE CASCADE
);

CREATE TABLE "UdapCommunityCertification" (
    "CommunityId" integer NOT NULL,
    "CertificationId" integer NOT NULL,
    CONSTRAINT "PK_UdapCommunityCertification" PRIMARY KEY ("CommunityId", "CertificationId"),
    CONSTRAINT "FK_CommunityCertification_Certification" FOREIGN KEY ("CertificationId") REFERENCES "UdapCertifications" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_CommunityCertification_Community" FOREIGN KEY ("CommunityId") REFERENCES "UdapCommunities" ("Id")
);

CREATE INDEX "IX_UdapAnchorCertification_CertificationId" ON "UdapAnchorCertification" ("CertificationId");

CREATE INDEX "IX_UdapAnchors_CommunityId" ON "UdapAnchors" ("CommunityId");

CREATE INDEX "IX_UdapCertifications_CommunityId" ON "UdapCertifications" ("CommunityId");

CREATE INDEX "IX_UdapCommunityCertification_CertificationId" ON "UdapCommunityCertification" ("CertificationId");

INSERT INTO "__EFMigrationsHistory" ("MigrationId", "ProductVersion")
VALUES ('20221223020511_InitialUdap', '7.0.1');

COMMIT;

