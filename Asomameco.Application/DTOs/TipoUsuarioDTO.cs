using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.DTOs
{
    public record TipoUsuarioDTO
    {
        //ID TipoUsuario
        [Display(Name = "Código")]
        [ValidateNever]
        public int Id { get; set; }



        //Descripción TipoUsuario
        [Display(Name = "Descripción")]
        [ValidateNever]
        public string Descripcion { get; set; } = null!;


    }
}
