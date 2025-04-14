using System;
using System.Collections.Generic;
using Asomameco.Infraestructure.Models;
using Microsoft.EntityFrameworkCore;

namespace Asomameco.Infraestructure.Data;

public partial class AsomamecoContext : DbContext
{
    public AsomamecoContext(DbContextOptions<AsomamecoContext> options)
        : base(options)
    {
    }

    public virtual DbSet<Asamblea> Asamblea { get; set; }

    public virtual DbSet<Asistencia> Asistencia { get; set; }

    public virtual DbSet<Confirmacion> Confirmacion { get; set; }

    public virtual DbSet<Estado1Usuario> Estado1Usuario { get; set; }

    public virtual DbSet<Estado2Usuario> Estado2Usuario { get; set; }

    public virtual DbSet<EstadoAsamblea> EstadoAsamblea { get; set; }

    public virtual DbSet<MetodoConfirmacion> MetodoConfirmacion { get; set; }

    public virtual DbSet<TipoUsuario> TipoUsuario { get; set; }

    public virtual DbSet<Usuario> Usuario { get; set; }

    public virtual DbSet<Lugar> Lugar { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Asamblea>(entity =>
        {
            entity.Property(e => e.Id).ValueGeneratedNever();
            entity.Property(e => e.Fecha).HasColumnType("datetime");

            entity.HasOne(d => d.EstadoNavigation).WithMany(p => p.Asamblea)
                .HasForeignKey(d => d.Estado)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_Asamblea_EstadoAsamblea");

            entity.HasOne(d => d.LugarNavigation).WithMany(p => p.Asamblea)
               .HasForeignKey(d => d.Lugar)
               .OnDelete(DeleteBehavior.ClientSetNull)
               .HasConstraintName("FK_Asamblea_Lugar");
        });

        modelBuilder.Entity<Asistencia>(entity =>
        {
            entity.Property(e => e.Id).ValueGeneratedNever();
            entity.Property(e => e.FechaHoraLlegada).HasColumnType("datetime");

            entity.HasOne(d => d.IdAsambleaNavigation).WithMany(p => p.Asistencia)
                .HasForeignKey(d => d.IdAsamblea)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_Asistencia_Asamblea");

            entity.HasOne(d => d.IdMiembroNavigation).WithMany(p => p.Asistencia)
                .HasForeignKey(d => d.IdMiembro)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_Asistencia_Usuario");
        });

        modelBuilder.Entity<Confirmacion>(entity =>
        {
            entity.Property(e => e.Id).ValueGeneratedNever();
            entity.Property(e => e.FechaConfirmacion).HasColumnType("datetime");

            entity.HasOne(d => d.IdMiembroNavigation).WithMany(p => p.Confirmacion)
                .HasForeignKey(d => d.IdMiembro)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_Confirmacion_Usuario");
        });

        modelBuilder.Entity<Estado1Usuario>(entity =>
        {
            entity.Property(e => e.Id).ValueGeneratedNever();
        });

        modelBuilder.Entity<Estado2Usuario>(entity =>
        {
            entity.Property(e => e.Id).ValueGeneratedNever();
        });

        modelBuilder.Entity<EstadoAsamblea>(entity =>
        {
            entity.Property(e => e.Id).ValueGeneratedNever();
        });

        modelBuilder.Entity<MetodoConfirmacion>(entity =>
        {
            entity.HasNoKey();

            entity.HasOne(d => d.IdNavigation).WithMany()
                .HasForeignKey(d => d.Id)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_MetodoConfirmacion_Confirmacion");
        });

        modelBuilder.Entity<TipoUsuario>(entity =>
        {
            entity.Property(e => e.Id).ValueGeneratedNever();
        });

        modelBuilder.Entity<Usuario>(entity =>
        {
            entity.Property(e => e.Id).ValueGeneratedNever();

            entity.HasOne(d => d.Estado1Navigation).WithMany(p => p.Usuario)
                .HasForeignKey(d => d.Estado1)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_Usuario_Estado1Usuario");

            entity.HasOne(d => d.Estado2Navigation).WithMany(p => p.Usuario)
                .HasForeignKey(d => d.Estado2)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_Usuario_Estado2Usuario");

            entity.HasOne(d => d.TipoNavigation).WithMany(p => p.Usuario)
                .HasForeignKey(d => d.Tipo)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_Usuario_TipoUsuario");
        });
        modelBuilder.Entity<Lugar>(entity =>
        {
            entity.Property(e => e.Id).ValueGeneratedNever();
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
