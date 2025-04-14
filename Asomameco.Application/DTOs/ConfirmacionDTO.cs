using Asomameco.Infraestructure.Models;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.DTOs
{
    public record ConfirmacionDTO
    {
        [ValidateNever]
        public int Id { get; set; }

        public int IdMiembro { get; set; }

        public int IdAsamblea { get; set; }

        public DateTime FechaConfirmacion { get; set; }

        [ValidateNever]
        public int Metodo { get; set; }

        [ValidateNever]
        public virtual Usuario IdMiembroNavigation { get; set; } = null!;
    }
}
