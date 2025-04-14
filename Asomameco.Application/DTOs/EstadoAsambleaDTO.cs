using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.DTOs
{
    public record EstadoAsambleaDTO
    {
        //ID Estado Asamblea
        [Display(Name = "Código")]
        [ValidateNever]
        public int Id { get; set; }



        //Descripción Estado Asamblea
        [Display(Name = "Descripción")]
        [ValidateNever]
        public string Descripcion { get; set; } = null!;
    }
}
