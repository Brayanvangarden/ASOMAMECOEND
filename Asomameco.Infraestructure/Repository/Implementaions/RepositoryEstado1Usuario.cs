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
    public class RepositoryEstado1Usuario : IRepositoryEstado1Usuario
    {
        private readonly AsomamecoContext _context;
        public RepositoryEstado1Usuario(AsomamecoContext context) {
            _context=context;
        }

        public async Task<Estado1Usuario> FindByIdAsync(int id)
        {

            var @object = await _context.Set<Estado1Usuario>().FindAsync(id);

            return @object!;
        }

        public async Task<ICollection<Estado1Usuario>> ListAsync()
        {
            var collection = await _context.Set<Estado1Usuario>().ToListAsync();
            return collection;
        }
    }
}
