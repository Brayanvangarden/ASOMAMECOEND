using Asomameco.Application.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.Services.Interfaces
{
    public interface IServiceLugar
    {
        Task<ICollection<LugarDTO>> ListAsync();
        Task<LugarDTO> FindByIdAsync(int id);
        Task<int> AddAsync(LugarDTO dto);
        Task UpdateAsync(int id, LugarDTO dto);
        Task DeleteAsync(int id, LugarDTO dto);
    }
}
