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
    public class RepositoryEstado2Usuario : IRepositoryEstado2Usuario
    {
        private readonly AsomamecoContext _context;
        public RepositoryEstado2Usuario(AsomamecoContext context) {
            _context=context;
        }

        public async Task<Estado2Usuario> FindByIdAsync(int id)
        {

            var @object = await _context.Set<Estado2Usuario>().FindAsync(id);

            return @object!;
        }

        public async Task<ICollection<Estado2Usuario>> ListAsync()
        {
            var collection = await _context.Set<Estado2Usuario>().ToListAsync();
            return collection;
        }
    }
}
