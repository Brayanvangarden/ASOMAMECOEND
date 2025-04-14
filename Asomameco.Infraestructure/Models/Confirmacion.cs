using System;
using System.Collections.Generic;

namespace Asomameco.Infraestructure.Models;

public partial class Confirmacion
{
    public int Id { get; set; }

    public int IdMiembro { get; set; }

    public int IdAsamblea { get; set; }

    public DateTime FechaConfirmacion { get; set; }

    public int Metodo { get; set; }

    public virtual Usuario IdMiembroNavigation { get; set; } = null!;
}
