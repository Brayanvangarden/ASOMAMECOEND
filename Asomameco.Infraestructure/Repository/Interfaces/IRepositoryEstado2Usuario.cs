 
using Asomameco.Infraestructure.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Infraestructure.Repository.Interfaces
{
    public interface IRepositoryEstado2Usuario
    {
        Task<ICollection<Estado2Usuario>> ListAsync();
        Task<Estado2Usuario> FindByIdAsync(int id);
    }
}
