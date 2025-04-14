using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.DTOs
{
    public record class LugarDTO
    {
        public int Id { get; set; }

        [Display(Name = "Nombre")]
        public string NombreLugar { get; set; } = null!;

        [Display(Name = "Dirección")]
        public string DireccionExacta { get; set; } = null!;

        [Display(Name = "Estado")]
        public bool Estado { get; set; }

        [ValidateNever]
        public string EstadoDescripcion 
        {
            get
            {
                return Estado  ? "Activo" : "Inactivo";
            }
        }

    }
}
