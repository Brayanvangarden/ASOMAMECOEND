using System;
using System.Collections.Generic;

namespace Asomameco.Infraestructure.Models;

public partial class Estado2Usuario
{
    public int Id { get; set; }

    public string Descripcion { get; set; } = null!;

    public virtual ICollection<Usuario> Usuario { get; set; } = new List<Usuario>();
}
