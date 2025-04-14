using Asomameco.Infraestructure.Models; 
using Asomameco.Application.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.Services.Interfaces
{
    public interface IServiceMetodoConfirmacion
    {
        Task<ICollection<MetodoConfirmacionDTO>> ListAsync();
        Task<MetodoConfirmacionDTO> FindByIdAsync(int id);
    }
}
