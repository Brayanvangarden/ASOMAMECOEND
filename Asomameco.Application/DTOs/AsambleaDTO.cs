using Asomameco.Infraestructure.Models;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.DTOs
{
    public record AsambleaDTO
    {
        public int Id { get; set; }

        public DateTime Fecha { get; set; }

        public int Estado { get; set; }

        public string EstadoDescripcion
        {
            get
            {
                return Estado switch
                {
                    1 => "Registrado",
                    2 => "En Proceso",
                    3 => "Concluida",
                    _ => "Desconocido"
                };
            }
        }

        [ValidateNever]
        [Display(Name = "Descripcion (Opcional)")]
        public string Descripcion { get; set; } = null!;

        public int Lugar { get; set; }

        [ValidateNever]
        public virtual ICollection<Asistencia> Asistencia { get; set; } = new List<Asistencia>();
        [ValidateNever]
        public virtual EstadoAsambleaDTO EstadoNavigation { get; set; } = null!;
        [ValidateNever]
        public virtual LugarDTO LugarNavigation { get; set; } = null!;




    }
}
