 
using Asomameco.Infraestructure.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Infraestructure.Repository.Interfaces
{
    public interface IRepositoryEstado1Usuario
    {
        Task<ICollection<Estado1Usuario>> ListAsync();
        Task<Estado1Usuario> FindByIdAsync(int id);
    }
}
