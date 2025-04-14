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
    public class RepositoryEstadoAsamblea : IRepositoryEstadoAsamblea
    {
        private readonly AsomamecoContext _context;
        public RepositoryEstadoAsamblea(AsomamecoContext context) {
            _context=context;
        }

        public async Task<EstadoAsamblea> FindByIdAsync(int id)
        {

            var @object = await _context.Set<EstadoAsamblea>().FindAsync(id);

            return @object!;
        }

        public async Task<ICollection<EstadoAsamblea>> ListAsync()
        {
            var collection = await _context.Set<EstadoAsamblea>().ToListAsync();
            return collection;
        }
    }
}
