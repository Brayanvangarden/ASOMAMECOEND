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
    public record UsuarioDTO
    {
        //Codigo Usuario
        [Display(Name = "Codigo")]
        [Required(ErrorMessage = "{0} es un dato requerido")]
        public int Id { get; set; }

        //Nombre Usuario
        [Display(Name = "Nombre")]
        [Required(ErrorMessage = "{0} es un dato requerido")]
        public string Nombre { get; set; } = null!;

        //Apellidos Usuario
        [Display(Name = "Apellidos")]
        [Required(ErrorMessage = "{0} es un dato requerido")]
        public string Apellidos { get; set; } = null!;
        //ID Usuario
        [Display(Name = "Cédula")]
        [Required(ErrorMessage = "{0} es un dato requerido")]
        public string Cedula { get; set; } = null!;

  
        //Estado del Combo: 1 Activo | 2 Inactivo 
        [Display(Name = "Estado")]
        [ValidateNever]
        public int Estado1 { get; set; }
        public string Estado1Descripcion
        {
            get
            {
                return Estado1 == 1 ? "Activo" : "Inactivo";
            }
        }

        [ValidateNever]
        public int Estado2 { get; set; }
        public string Estado2Descripcion
        {
            get
            {
                return Estado1 == 1 ? "Confirmado" : "No Confirmado";
            }
        }

        //Correo Usuario
        [Display(Name = "Correo")]
        [Required(ErrorMessage = "{0} es un dato requerido")]
        public string Correo { get; set; } = null!;


        //Correo Usuario
        [Display(Name = "Telefono")]
        [Required(ErrorMessage = "{0} es un dato requerido")]
        public int Telefono { get; set; }

        public int Tipo { get; set; }

        //Contraseña Usuario
        [Display(Name = "Contraseña")]
        [Required(ErrorMessage = "{0} es un dato requerido")]
        public string Contraseña { get; set; }= null!;

        [ValidateNever]
        public virtual ICollection<Asistencia> Asistencia { get; set; } = new List<Asistencia>();

        [ValidateNever]
        public virtual ICollection<Confirmacion> Confirmacion { get; set; } = new List<Confirmacion>();

        [ValidateNever]
        public virtual Estado1Usuario Estado1Navigation { get; set; } = null!;

        [ValidateNever]
        public virtual Estado2Usuario Estado2Navigation { get; set; } = null!;

        //Rol Usuario
        [Display(Name = "Rol")]
        [ValidateNever]
        public virtual TipoUsuario TipoNavigation { get; set; } = null!;
    }
}
