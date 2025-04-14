 
using Asomameco.Application.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.Services.Interfaces
{
    public interface IServiceEstado2Usuario
    {
        Task<ICollection<Estado2UsuarioDTO>> ListAsync();
        Task<Estado2UsuarioDTO> FindByIdAsync(int id);
    }
}
