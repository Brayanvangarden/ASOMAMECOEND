using Microsoft.AspNetCore.Mvc;
using Asomameco.Application.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.Services.Interfaces
{
    public interface IServiceAsamblea
    {
       Task<ICollection<AsambleaDTO>> ListAsync();
        Task<AsambleaDTO> FindByIdAsync(int id); 
     

        Task<int> ConfirmAttendance(AsistenciaDTO confirmacion);
        Task<int> Confirmation(ConfirmacionDTO confirmacion);

        Task<bool> VerificarAsistencia(int idMiembro, int idAsamblea);

        Task<int> AddAsync(AsambleaDTO dto);
        Task UpdateAsync(int id, AsambleaDTO dto);
        Task DeleteAsync(int id, AsambleaDTO dto);
    }
}
