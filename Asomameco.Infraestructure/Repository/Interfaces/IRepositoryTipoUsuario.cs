 
using Asomameco.Infraestructure.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Infraestructure.Repository.Interfaces
{
    public interface IRepositoryTipoUsuario
    {
        Task<ICollection<TipoUsuario>> ListAsync();
        Task<TipoUsuario> FindByIdAsync(int id);
    }
}
