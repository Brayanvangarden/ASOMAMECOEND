using System;
using System.Collections.Generic;

namespace Asomameco.Infraestructure.Models;

public partial class Asistencia
{
    public int Id { get; set; }

    public int IdMiembro { get; set; }

    public int IdAsamblea { get; set; }

    public DateTime FechaHoraLlegada { get; set; }

    public virtual Asamblea IdAsambleaNavigation { get; set; } = null!;

    public virtual Usuario IdMiembroNavigation { get; set; } = null!;
}
