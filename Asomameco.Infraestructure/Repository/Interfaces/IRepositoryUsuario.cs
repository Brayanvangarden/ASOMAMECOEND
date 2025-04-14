 
using Asomameco.Infraestructure.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Infraestructure.Repository.Interfaces
{
    public interface IRepositoryUsuario
    {
        Task<ICollection<Usuario>> ListAsync();
        Task<Usuario> FindByIdAsync(int id);
        Task<Usuario> LoginAsync(int id, string password);
        Task<int> AddAsync(Usuario entity);
        Task UpdateAsync(int id, Usuario dto);

        Task DeleteAsync(int id, Usuario dto);
    }
}
