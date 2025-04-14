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
    public class RepositoryMetodoConfirmacion : IRepositoryMetodoConfirmacion
    {
        private readonly AsomamecoContext _context;
        public RepositoryMetodoConfirmacion(AsomamecoContext context) {
            _context=context;
        }

        public async Task<MetodoConfirmacion> FindByIdAsync(int id)
        {

            var @object = await _context.Set<MetodoConfirmacion>().FindAsync(id);

            return @object!;
        }

        public async Task<ICollection<MetodoConfirmacion>> ListAsync()
        {
            var collection = await _context.Set<MetodoConfirmacion>().ToListAsync();
            return collection;
        }
    }
}
