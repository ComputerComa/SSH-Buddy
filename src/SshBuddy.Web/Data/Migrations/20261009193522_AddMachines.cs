using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SshBuddy.Web.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddMachines : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Machines",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Fqdn = table.Column<string>(type: "TEXT", maxLength: 253, nullable: false),
                    CredentialHash = table.Column<string>(type: "TEXT", nullable: true),
                    EnrollmentNonceHash = table.Column<string>(type: "TEXT", nullable: true),
                    TemplateCredentialId = table.Column<Guid>(type: "TEXT", nullable: true),
                    FirstRegisteredUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CredentialIssuedUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ConfirmedUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastContactUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastSuccessUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastIp = table.Column<string>(type: "TEXT", nullable: true),
                    AgentVersion = table.Column<string>(type: "TEXT", nullable: true),
                    AppliedEtag = table.Column<string>(type: "TEXT", nullable: true),
                    LastResult = table.Column<string>(type: "TEXT", nullable: true),
                    LastError = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    RevokedUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ReenrollPermittedUntilUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastRefusedEnrollUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastRefusedEnrollIp = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Machines", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TemplateCredentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    TokenHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastUsedUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    RevokedUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TemplateCredentials", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Machines_CredentialHash",
                table: "Machines",
                column: "CredentialHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Machines_Fqdn",
                table: "Machines",
                column: "Fqdn",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TemplateCredentials_TokenHash",
                table: "TemplateCredentials",
                column: "TokenHash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Machines");

            migrationBuilder.DropTable(
                name: "TemplateCredentials");
        }
    }
}
