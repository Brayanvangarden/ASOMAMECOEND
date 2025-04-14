using Moq;
using Asomameco.Application.Services.Implementations;
using Asomameco.Application.DTOs;
using Asomameco.Infraestructure.Repository.Interfaces;
using AutoMapper;

namespace ASOMAMECOUsuarioExistente
{
    public class UsuarioExistenteTest
    {
        private readonly Mock<IRepositoryUsuario> _usuarioRepositoryMock;
        private readonly Mock<IMapper> _mapperMock; // Agregar Mock de AutoMapper
        private readonly ServiceUsuario _usuarioService;

        public UsuarioExistenteTest()
        {
            // Crear el Mock del repository
            _usuarioRepositoryMock = new Mock<IRepositoryUsuario>();
            _mapperMock = new Mock<IMapper>();
            // Inyectamos el Mock en el servicio
            _usuarioService = new ServiceUsuario(_usuarioRepositoryMock.Object, _mapperMock.Object);
        }


        [Fact]
        public async Task usuarioExistente()
        {

            // Arrange
            int id = 140;
            //string nombre = "David Soto";
            var usuario = new Asomameco.Infraestructure.Models.Usuario
            {
                Id = 140,
                Nombre = "David",
                Apellidos = "Soto",
                Estado1 = 1, // Estado activo
                Tipo = 1
            };

            var usuarioDTO = new UsuarioDTO
            {
                Id = 140,
                Nombre = "David",
                Apellidos = "Soto",
                Estado1 = 1, // Estado activo
                Tipo = 1
            };

            _usuarioRepositoryMock.Setup(repo => repo.FindByIdAsync(id)).ReturnsAsync(usuario);
            _mapperMock.Setup(mapper => mapper.Map<UsuarioDTO>(usuario)).Returns(usuarioDTO);

            // Act
            var result = await _usuarioService.FindByIdAsync(id);

            // Assert
            Assert.NotNull(result);
            Assert.Equal("David", result.Nombre);
            Assert.Equal("Soto", result.Apellidos);
            Assert.Equal(1, result.Estado1);
        }

        [Fact]
        public async Task usuarioInexistente()
        {
            // Arrange
            int id = 999; // ID de usuario inexistente
            _usuarioRepositoryMock.Setup(repo => repo.FindByIdAsync(id)).ReturnsAsync((Asomameco.Infraestructure.Models.Usuario)null);

            // Act
            var result = await _usuarioService.FindByIdAsync(id);

            // Assert
            Assert.Null(result); // Debería retornar null si el usuario no existe
        }

    }
}


