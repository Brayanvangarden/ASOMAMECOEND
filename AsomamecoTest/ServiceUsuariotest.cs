using System;
using System.Threading.Tasks;
using Xunit;
using Moq;
using Asomameco.Application.Services.Interfaces;
using Asomameco.Application.DTOs;

namespace PruebaUsuarioASOMAMECO
{
    public class ServicioUsuarioPruebas
    {
        private readonly Mock<IServiceUsuario> _mockServicio;
        private readonly IServiceUsuario _servicioUsuario;
        //Prueba
        public ServicioUsuarioPruebas()
        {
            _mockServicio = new Mock<IServiceUsuario>();
            _servicioUsuario = _mockServicio.Object;
        }


        [Fact]
        public async Task AuthenticateAsync_Deberia_DevolverUsuarioDTO_Cuando_CredencialesSonValidas()
        {
            // Arrange DD
            var usuarioEsperado = new UsuarioDTO { Id = 1, Nombre = "UsuarioValido" };
            _mockServicio.Setup(s => s.AuthenticateAsync(1, "password123")).ReturnsAsync(usuarioEsperado);

            // Act
            var resultado = await _servicioUsuario.AuthenticateAsync(1, "password123");

            // Assert d
            Assert.NotNull(resultado);
            Assert.Equal(usuarioEsperado.Id, resultado.Id);
            Assert.Equal(usuarioEsperado.Nombre, resultado.Nombre);
        }

        [Fact]
        public async Task AuthenticateAsync_Deberia_DevolverNulo_Cuando_CredencialesSonInvalidas()
        {
            // Arrange
            _mockServicio.Setup(s => s.AuthenticateAsync(1, "wrongpassword")).ReturnsAsync((UsuarioDTO)null);

            // Act
            var resultado = await _servicioUsuario.AuthenticateAsync(1, "wrongpassword");

            // Assert
            Assert.Null(resultado);
        }

        [Fact]
        public async Task AuthenticateAsync_Deberia_DevolverNulo_Cuando_UsuarioNoExiste()
        {
            // Arrange
            _mockServicio.Setup(s => s.AuthenticateAsync(999, "password123")).ReturnsAsync((UsuarioDTO)null);

            // Act
            var resultado = await _servicioUsuario.AuthenticateAsync(999, "password123");

            // Assert
            Assert.Null(resultado);
        }

        [Fact]
        public async Task AuthenticateAsync_Deberia_LanzarExcepcion_Cuando_ContrasenaEsNula()
        {
            // Arrange
            _mockServicio.Setup(s => s.AuthenticateAsync(1, null)).ThrowsAsync(new ArgumentNullException("password"));

            // Act & Assert
            var excepcion = await Assert.ThrowsAsync<ArgumentNullException>(() => _servicioUsuario.AuthenticateAsync(1, null));
            Assert.Equal("password", excepcion.ParamName);
        }

        [Fact]
        public async Task AuthenticateAsync_Deberia_LanzarExcepcion_Cuando_IdUsuarioEsNegativo()
        {
            // Arrange
            _mockServicio.Setup(s => s.AuthenticateAsync(-1, "password123")).ThrowsAsync(new ArgumentException("ID no válido"));

            // Act & Assert
            var excepcion = await Assert.ThrowsAsync<ArgumentException>(() => _servicioUsuario.AuthenticateAsync(-1, "password123"));
            Assert.Equal("ID no válido", excepcion.Message);
        }
    }
}
