using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Infraestructure.Models
{
    public partial class Lugar
    {
        public int Id { get; set; }

        public string NombreLugar { get; set; } = null!;

        public string DireccionExacta { get; set; } = null!;

        public bool Estado { get; set; }
        public virtual ICollection<Asamblea> Asamblea { get; set; } = new List<Asamblea>();
    }
}
