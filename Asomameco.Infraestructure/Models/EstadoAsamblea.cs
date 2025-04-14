using System;
using System.Collections.Generic;

namespace Asomameco.Infraestructure.Models;

public partial class EstadoAsamblea
{
    public int Id { get; set; }

    public string Descripcion { get; set; } = null!;

    public virtual ICollection<Asamblea> Asamblea { get; set; } = new List<Asamblea>();
}
