 
using Asomameco.Infraestructure.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Infraestructure.Repository.Interfaces
{
    public interface IRepositoryAsamblea
    {
        Task<ICollection<Asamblea>> ListAsync();
        Task<Asamblea> FindByIdAsync(int id);

        Task<int> ConfirmAttendance(Asistencia confirmacion);

        Task<int> Confirmation(Confirmacion confirmacion);

        Task<int> AddAsync(Asamblea entity);
        Task UpdateAsync(int id, Asamblea dto);

        Task DeleteAsync(int id, Asamblea dto);
    }
}
