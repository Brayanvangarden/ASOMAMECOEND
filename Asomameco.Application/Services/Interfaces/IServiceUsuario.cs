using Asomameco.Application.DTOs;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.Services.Interfaces
{
    public interface IServiceUsuario
    {
        Task<ICollection<UsuarioDTO>> ListAsync();
        Task<UsuarioDTO> FindByIdAsync(int id);
        Task<int> AddAsync(UsuarioDTO dto);
        Task UpdateAsync(int id, UsuarioDTO dto);
        Task<UsuarioDTO> AuthenticateAsync(int username, string password);
        Task DeleteAsync(int id, UsuarioDTO dto);

    }
}
