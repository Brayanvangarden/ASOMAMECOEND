using Asomameco.Infraestructure.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.DTOs
{
    public record AsistenciaDTO
    {
        [ValidateNever]
        public int Id { get; set; }

        public int IdMiembro { get; set; }

        public int IdAsamblea { get; set; }

        public DateTime FechaHoraLlegada { get; set; }

        [ValidateNever]
        public virtual Asamblea IdAsambleaNavigation { get; set; } = null!;

        [ValidateNever]
        public virtual Usuario IdMiembroNavigation { get; set; } = null!;
    }
}
