using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace SshBuddy.Web.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : IdentityDbContext<IdentityUser>(options)
{
    public DbSet<SshKey> Keys => Set<SshKey>();
    public DbSet<EnrollmentToken> EnrollmentTokens => Set<EnrollmentToken>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<TemplateCredential> TemplateCredentials => Set<TemplateCredential>();
    public DbSet<Machine> Machines => Set<Machine>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);

        b.Entity<SshKey>(e =>
        {
            e.HasIndex(k => k.KeyMaterial).IsUnique();
            e.Property(k => k.Label).HasMaxLength(64);
            e.Property(k => k.Algorithm).HasMaxLength(64);
            e.Ignore(k => k.IsActive);
        });

        b.Entity<EnrollmentToken>(e =>
        {
            e.HasIndex(t => t.TokenHash).IsUnique();
            e.Property(t => t.TokenHash).HasMaxLength(64);
        });

        b.Entity<AuditEvent>(e => e.HasIndex(a => a.TimestampUtc));

        b.Entity<TemplateCredential>(e =>
        {
            e.HasIndex(t => t.TokenHash).IsUnique();
            e.Property(t => t.TokenHash).HasMaxLength(64);
            e.Property(t => t.Name).HasMaxLength(64);
        });

        b.Entity<Machine>(e =>
        {
            e.HasIndex(m => m.Fqdn).IsUnique();
            e.HasIndex(m => m.CredentialHash).IsUnique(); // nulls (revoked) do not collide in SQLite
            e.Property(m => m.Fqdn).HasMaxLength(253);
            e.Property(m => m.LastError).HasMaxLength(500);
        });
    }
}
