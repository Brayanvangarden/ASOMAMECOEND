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
    public class RepositoryAsistencia : IRepositoryAsistencia
    {
        private readonly AsomamecoContext _context;
        public RepositoryAsistencia(AsomamecoContext context) {
            _context=context;
        }

        public async Task<Asistencia> FindByIdAsync(int id)
        {

            var @object = await _context.Set<Asistencia>().FindAsync(id);

            return @object!;
        }

        public async Task<ICollection<Asistencia>> ListAsync()
        {
            var collection = await _context.Set<Asistencia>().ToListAsync();
            return collection;
        }
    }
}
