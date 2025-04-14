﻿using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.DTOs
{
    public record Estado1UsuarioDTO
    {
        //ID Estado1 Usuario
        [Display(Name = "Código")]
        [ValidateNever]
        public int Id { get; set; }



        //Descripción Estado1 Usuario
        [Display(Name = "Descripción")]
        [ValidateNever]
        public string Descripcion { get; set; } = null!;
    }
}
