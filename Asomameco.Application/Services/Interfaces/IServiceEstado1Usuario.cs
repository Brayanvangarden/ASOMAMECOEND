 
using Asomameco.Application.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.Services.Interfaces
{
    public interface IServiceEstado1Usuario
    {
        Task<ICollection<Estado1UsuarioDTO>> ListAsync();
        Task<Estado1UsuarioDTO> FindByIdAsync(int id);
    }
}
