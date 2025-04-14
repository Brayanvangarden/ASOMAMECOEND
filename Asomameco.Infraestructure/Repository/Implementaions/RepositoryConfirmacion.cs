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
    public class RepositoryConfirmacion : IRepositoryConfirmacion
    {
        private readonly AsomamecoContext _context;
        public RepositoryConfirmacion(AsomamecoContext context) {
            _context=context;
        }

        public async Task<Confirmacion> FindByIdAsync(int id)
        {

            var @object = await _context.Set<Confirmacion>().FindAsync(id);

            return @object!;
        }

        public async Task<ICollection<Confirmacion>> ListAsync()
        {
            var collection = await _context.Set<Confirmacion>().ToListAsync();
            return collection;
        }
    }
}
