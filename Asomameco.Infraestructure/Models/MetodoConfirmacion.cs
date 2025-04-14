using System;
using System.Collections.Generic;

namespace Asomameco.Infraestructure.Models;

public partial class MetodoConfirmacion
{
    public int Id { get; set; }

    public string Descripcion { get; set; } = null!;

    public virtual Confirmacion IdNavigation { get; set; } = null!;
}
