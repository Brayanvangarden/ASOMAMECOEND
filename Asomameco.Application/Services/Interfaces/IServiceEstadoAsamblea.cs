 
using Asomameco.Application.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.Services.Interfaces
{
    public interface IServiceEstadoAsamblea
    {
        Task<ICollection<EstadoAsambleaDTO>> ListAsync();
        Task<EstadoAsambleaDTO> FindByIdAsync(int id);
    }
}
