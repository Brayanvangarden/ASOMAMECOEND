using Asomameco.Infraestructure.Data;
using Asomameco.Infraestructure.Models;
using Asomameco.Infraestructure.Repository.Interfaces;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Crypto.Generators;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
 


namespace Asomameco.Infraestructure.Repository.Implementations
{
    public class RepositoryUsuario:IRepositoryUsuario
    {
        private readonly AsomamecoContext _context;
        public RepositoryUsuario(AsomamecoContext context) {
            _context=context;
        }

        public async Task<Usuario> FindByIdAsync(int id)
        {

            var @object = await _context.Set<Usuario>()
             .Include(p => p.TipoNavigation) // Incluye el tipo de usuario   
            .Where(p => p.Id == id)
            .FirstOrDefaultAsync();

            return @object!;
        }

        public async Task<ICollection<Usuario>> ListAsync()
        {
            var collection = await _context.Set<Usuario>()
                .Include(p => p.TipoNavigation) // Incluye el tipo de usuario
                .ToListAsync();
            return collection;
        }

    

        public async Task<Usuario> LoginAsync(int id, string password)
        {
            var user = await _context.Set<Usuario>()
                                     .Include(b => b.TipoNavigation)
                                     .Where(p => p.Id == id && p.Contraseña == password)
                                     .FirstOrDefaultAsync();

            // Verificar si el usuario existe y comparar la contraseña ingresada con la almacenada
            if (user != null)
            {
                return user;
            }

            return null!;
        }


        public async Task<int> AddAsync(Usuario entity)
        {
            entity.Estado1 = 1;
            entity.Estado2 = 0;
            // Hashear la contraseña antes de insertarla en la base de datos
            //string hashedPassword = BCrypt.Net.BCrypt.HashPassword(entity.Contraseña);

            // Insertar el nuevo usuario en la tabla Usuario usando SQL
            var sqlUsuario = @"
        INSERT INTO Usuario (Id, Nombre, Apellidos, Correo, Contraseña, Tipo, Estado1, Estado2, Telefono, Cedula) 
        VALUES (@Id, @Nombre, @Apellidos, @Correo, @Contraseña, @Tipo, @Estado1, @Estado2, @Telefono, @Cedula);";

            // Parámetros para la consulta SQL del usuario
            var parametersUsuario = new[]
            {
        new SqlParameter("@Id", entity.Id),
        new SqlParameter("@Cedula", entity.Cedula),
        new SqlParameter("@Nombre", entity.Nombre),
        new SqlParameter("@Apellidos", entity.Apellidos),
        new SqlParameter("@Correo", entity.Correo),
        new SqlParameter("@Contraseña", entity.Contraseña), // Guardamos la contraseña
        new SqlParameter("@Telefono", entity.Telefono),
        new SqlParameter("@Tipo", entity.Tipo),
        new SqlParameter("@Estado1", entity.Estado1),
         new SqlParameter("@Estado2", entity.Estado2)
    };

            // Ejecutar la consulta y obtener el Id del usuario recién insertado
            var UsuarioID = await _context.Database.ExecuteSqlRawAsync(sqlUsuario, parametersUsuario);

            return UsuarioID; // Retornamos el Id del usuario creado
        }


        public async Task UpdateAsync(int id, Usuario entity)
        {
        
            var sqlUsuario = @"
        UPDATE Usuario 
        SET 
            Nombre = @Nombre, 
            Apellidos = @Apellidos, 
Cedula = @Cedula,
Estado1 = @Estado1,
Estado2 = @Estado2,
            Correo = @Correo, 
Telefono = @Telefono, 
            Contraseña = @Contraseña, 
            Tipo = @Tipo
     
        WHERE Id = @Id;";

            var parametersUsuario = new[]
            {
        new SqlParameter("@Id", entity.Id),
        new SqlParameter("@Cedula", entity.Cedula),
        new SqlParameter("@Nombre", entity.Nombre),
        new SqlParameter("@Apellidos", entity.Apellidos),
        new SqlParameter("@Correo", entity.Correo),
        new SqlParameter("@Contraseña", entity.Contraseña), // Guardamos la contraseña
        new SqlParameter("@Telefono", entity.Telefono),
        new SqlParameter("@Tipo", entity.Tipo),
        new SqlParameter("@Estado1", entity.Estado1),
        new SqlParameter("@Estado2", entity.Estado2)
    };

            await _context.Database.ExecuteSqlRawAsync(sqlUsuario, parametersUsuario);
        }



        public async Task DeleteAsync(int Id, Usuario entity)
        {
  
            var id = entity.Id; // ID del Usuario

            var sql = "DELETE FROM Usuario WHERE Id = @Id";

            // Usando SqlParameter para evitar el error de declaración de variable
            var parameters = new[]
            {
 
        new SqlParameter("@Id", id)
                         };

            await _context.Database.ExecuteSqlRawAsync(sql, parameters);
        }


    }
}
