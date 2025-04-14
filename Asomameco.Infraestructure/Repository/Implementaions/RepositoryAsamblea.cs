using Asomameco.Infraestructure.Data;
using Asomameco.Infraestructure.Models;
using Asomameco.Infraestructure.Repository.Interfaces;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Crypto.Generators;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
 


namespace Asomameco.Infraestructure.Repository.Implementations
{
    public class RepositoryAsamblea:IRepositoryAsamblea
    {
        private readonly AsomamecoContext _context;
        public RepositoryAsamblea(AsomamecoContext context) {
            _context=context;
        }

        public async Task<Asamblea> FindByIdAsync(int id)
        {

            var @object = await _context.Set<Asamblea>()
             .Include(p => p.EstadoNavigation)// Incluye el tipo de Asamblea  
             .Include(p => p.LugarNavigation)// Incluye el Lugar   
            .Where(p => p.Id == id)
            .FirstOrDefaultAsync();

            return @object!;
        }

        public async Task<ICollection<Asamblea>> ListAsync()
        {
            var collection = await _context.Set<Asamblea>()
                .Include(p => p.EstadoNavigation) // Incluye el tipo de Asamblea
                .Include(p => p.LugarNavigation)// Incluye el Lugar   
                .ToListAsync();
            return collection;
        }

    
 

        public async Task<int> AddAsync(Asamblea entity)
        {


          

            // Insertar el nuevo Asamblea en la tabla Asamblea usando SQL
            var sqlAsamblea = @"
                    INSERT INTO Asamblea (Id, Fecha,Estado, Descripcion, Lugar) 
                    VALUES (@Id, @Fecha, @Estado, @Descripcion, @Lugar);";

            // Parámetros para la consulta SQL del Asamblea
            var parametersAsamblea = new[]
            {
        new SqlParameter("@Id", entity.Id),
        new SqlParameter("@Fecha", entity.Fecha),
        new SqlParameter("@Estado", entity.Estado),
       // Manejo explícito de Descripcion para permitir valores nulos
        entity.Descripcion == null
            ? new SqlParameter("@Descripcion", "")
            : new SqlParameter("@Descripcion", entity.Descripcion),
        new SqlParameter("@Lugar", entity.Lugar)

    };

            // Ejecutar la consulta y obtener el Id del Asamblea recién insertado
            var AsambleaID = await _context.Database.ExecuteSqlRawAsync(sqlAsamblea, parametersAsamblea);

            return AsambleaID; // Retornamos el Id del Asamblea creado
        }


        //Confirmando asistencia EN EL Lugar y Dia y hora del EVENTO
        public async Task<int> ConfirmAttendance(Asistencia entity)
        {


            // Obtener el máximo Id actual en la tabla Asamblea y sumarle 1
            var maxId = await _context.Asistencia.MaxAsync(a => (int?)a.Id) ?? 0;
            var newId = maxId + 1;


            // Insertar la nueva confirmacion en la tabla Asamblea usando SQL
            var sqlConfirmacion = @"
        INSERT INTO Asistencia (Id, FechaHoraLlegada,IdMiembro,IdAsamblea) 
        VALUES (@Id, @FechaHoraLlegada,@IdMiembro,@IdAsamblea);";

            // Parámetros para la consulta SQL del Asamblea
            var parametersConfirmacion = new[]
            {
        new SqlParameter("@Id", newId),
        new SqlParameter("@FechaHoraLlegada", entity.FechaHoraLlegada),
            new SqlParameter("@IdMiembro", entity.IdMiembro),
        new SqlParameter("@IdAsamblea", entity.IdAsamblea)

    };

            // Ejecutar la consulta y obtener el Id del Asamblea recién insertado
            var ConfirmacionID = await _context.Database.ExecuteSqlRawAsync(sqlConfirmacion, parametersConfirmacion);

            return ConfirmacionID; // Retornamos el Id del Asamblea creado
        }

        //--------------------------------------------------
        //Confirmando asistencia EN A TRAVES del Correo
        public async Task<int> Confirmation(Confirmacion entity)
        {


            // Obtener el máximo Id actual en la tabla Asamblea y sumarle 1
            var maxId = await _context.Confirmacion.MaxAsync(a => (int?)a.Id) ?? 0;
            var newId = maxId + 1;


            // Insertar la nueva confirmacion en la tabla Asamblea usando SQL
            var sqlConfirmacion = @"
        INSERT INTO Confirmacion (Id, FechaConfirmacion,IdMiembro,Metodo,IdAsamblea) 
        VALUES (@Id, @FechaConfirmacion,@IdMiembro,@Metodo,@IdAsamblea);";

            // Parámetros para la consulta SQL del Asamblea
            var parametersConfirmacion = new[]
            {
            new SqlParameter("@Id", newId),
            new SqlParameter("@FechaConfirmacion", entity.FechaConfirmacion),
            new SqlParameter("@IdMiembro", entity.IdMiembro),
            new SqlParameter("@Metodo", entity.Metodo),
            new SqlParameter("@IdAsamblea", entity.IdAsamblea)

    };



            // Ejecutar la consulta y obtener el Id del Asamblea recién insertado
            var ConfirmacionID = await _context.Database.ExecuteSqlRawAsync(sqlConfirmacion, parametersConfirmacion);

            return ConfirmacionID; // Retornamos el Id del Asamblea creado
        }

        public async Task UpdateAsync(int id, Asamblea entity)
        {
        
            var sqlAsamblea = @"
        UPDATE Asamblea 
        SET 
            Fecha = @Fecha, 
            Estado = @Estado,
            Descripcion = @Descripcion,
            Lugar = @Lugar
     
        WHERE Id = @Id;";

          

            var parametersAsamblea = new[]
            {
        new SqlParameter("@Id", entity.Id),
        new SqlParameter("@Fecha", entity.Fecha),
        new SqlParameter("@Estado", entity.Estado),
         // Manejo explícito de Descripcion para permitir valores nulos
        entity.Descripcion == null
            ? new SqlParameter("@Descripcion", "")
            : new SqlParameter("@Descripcion", entity.Descripcion),
        new SqlParameter("@Lugar", entity.Lugar)

    };

            var sql2 = "DELETE FROM Confirmacion WHERE IdAsamblea = @Id";
            var parameters = new[]
    {

        new SqlParameter("@Id", entity.Id)
                         };

            await _context.Database.ExecuteSqlRawAsync(sqlAsamblea, parametersAsamblea);
            await _context.Database.ExecuteSqlRawAsync(sql2, parameters);
        }



        public async Task DeleteAsync(int Id, Asamblea entity)
        {
  
            var id = entity.Id; // ID del Asamblea

            var sql1 = "DELETE FROM Asistencia WHERE IdAsamblea = @Id";
            var sql2 = "DELETE FROM Confirmacion WHERE IdAsamblea = @Id";
            var sql = "DELETE FROM Asamblea WHERE Id = @Id";

            // Usando SqlParameter para evitar el error de declaración de variable
            var parameters = new[]
            {
 
        new SqlParameter("@Id", id)
                         };

            await _context.Database.ExecuteSqlRawAsync(sql1, parameters);
            await _context.Database.ExecuteSqlRawAsync(sql2, parameters);
            await _context.Database.ExecuteSqlRawAsync(sql, parameters);
        }

    }
}
