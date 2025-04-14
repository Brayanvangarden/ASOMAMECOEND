using Asomameco.Infraestructure.Data;
using Asomameco.Infraestructure.Models;
using Asomameco.Infraestructure.Repository.Interfaces;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Infraestructure.Repository.Implementaions
{
    public class RepositoryLugar: IRepositoryLugar
    {

        private readonly AsomamecoContext _context;
        public RepositoryLugar(AsomamecoContext context)
        {
            _context = context;
        }

        public async Task<Lugar> FindByIdAsync(int id)
        {

            var @object = await _context.Set<Lugar>().FindAsync(id);

            return @object!;
        }

        public async Task<ICollection<Lugar>> ListAsync()
        {
            var collection = await _context.Set<Lugar>().ToListAsync();
            return collection;
        }

        public async Task<int> AddAsync(Lugar entity)
        {

            // Insertar el nuevo Lugar en la tabla Lugar usando SQL
            var sqlLugar = @"
                    INSERT INTO Lugar (NombreLugar, DireccionExacta,Estado) 
                    VALUES (@NombreLugar, @DireccionExacta, @Estado);";

            // Parámetros para la consulta SQL del Lugar
            var parametersLugar = new[]
            {
 
                   new SqlParameter("@NombreLugar", entity.NombreLugar),
                   new SqlParameter("@DireccionExacta", entity.DireccionExacta),
                   new SqlParameter("@Estado", entity.Estado)

              };

            // Ejecutar la consulta y obtener el Id del Lugar recién insertado
            var LugarID = await _context.Database.ExecuteSqlRawAsync(sqlLugar, parametersLugar);

            return LugarID; // Retornamos el Id del Lugar creado
        }

        public async Task UpdateAsync(int id, Lugar entity)
        {

            var sqlLugar = @"
           UPDATE Lugar 
           SET 
           NombreLugar = @NombreLugar, 
           DireccionExacta = @DireccionExacta,
           Estado = @Estado
 
     
        WHERE Id = @Id;";



            var parametersLugar = new[]
            {
                   new SqlParameter("@Id", entity.Id),
                   new SqlParameter("@NombreLugar", entity.NombreLugar),
                   new SqlParameter("@DireccionExacta", entity.DireccionExacta),
                   new SqlParameter("@Estado", entity.Estado)

    };

      
            await _context.Database.ExecuteSqlRawAsync(sqlLugar, parametersLugar);
  
        }



        public async Task DeleteAsync(int Id, Lugar entity)
        {

            var id = entity.Id; // ID del Lugar

      
            var sql = "DELETE FROM Lugar WHERE Id = @Id";

            // Usando SqlParameter para evitar el error de declaración de variable
            var parameters = new[]
            {

        new SqlParameter("@Id", id)
                         };

       
            await _context.Database.ExecuteSqlRawAsync(sql, parameters);
        }

    }
}
