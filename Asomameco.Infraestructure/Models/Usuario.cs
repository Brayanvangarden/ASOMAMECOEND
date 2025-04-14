using System;
using System.Collections.Generic;

namespace Asomameco.Infraestructure.Models;

public partial class Usuario
{
    public int Id { get; set; }

    public string Nombre { get; set; } = null!;

    public string Apellidos { get; set; } = null!;

    public string Cedula { get; set; } = null!;

    public int Estado1 { get; set; }

    public int Estado2 { get; set; }

    public string Correo { get; set; } = null!;

    public int Telefono { get; set; }

    public int Tipo { get; set; }

    public string? Contraseña { get; set; }

    public virtual ICollection<Asistencia> Asistencia { get; set; } = new List<Asistencia>();

    public virtual ICollection<Confirmacion> Confirmacion { get; set; } = new List<Confirmacion>();

    public virtual Estado1Usuario Estado1Navigation { get; set; } = null!;

    public virtual Estado2Usuario Estado2Navigation { get; set; } = null!;

    public virtual TipoUsuario TipoNavigation { get; set; } = null!;
}
