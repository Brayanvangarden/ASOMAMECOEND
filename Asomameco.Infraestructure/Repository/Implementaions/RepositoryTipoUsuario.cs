using Asomameco.Infraestructure.Data;
using Asomameco.Infraestructure.Models;
using Asomameco.Infraestructure.Repository.Interfaces;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Infraestructure.Repository.Implementations
{
    public class RepositoryTipoUsuario:IRepositoryTipoUsuario
    {
        private readonly AsomamecoContext _context;
        public RepositoryTipoUsuario(AsomamecoContext context) {
            _context=context;
        }

        public async Task<TipoUsuario> FindByIdAsync(int id)
        {

            var @object = await _context.Set<TipoUsuario>().FindAsync(id);

            return @object!;
        }

        public async Task<ICollection<TipoUsuario>> ListAsync()
        {
            var collection = await _context.Set<TipoUsuario>().ToListAsync();
            return collection;
        }
    }
}
