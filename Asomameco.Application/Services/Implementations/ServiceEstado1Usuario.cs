using Asomameco.Application.Services.Interfaces;
using AutoMapper;
using Asomameco.Application.DTOs;
using Asomameco.Infraestructure.Repository.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Asomameco.Application.Profiles;

namespace Asomameco.Application.Services.Implementations
{
    public class ServiceEstado1Usuario : IServiceEstado1Usuario
    {
        private readonly IRepositoryEstado1Usuario _repository;
        private readonly IMapper _mapper;
        public ServiceEstado1Usuario(IRepositoryEstado1Usuario repository, IMapper mapper)
        {
            _repository = repository;
            _mapper = mapper;
        }
        public async Task<Estado1UsuarioDTO> FindByIdAsync(int id)
        {
            var @object = await _repository.FindByIdAsync(id);
            var objectMapped = _mapper.Map<Estado1UsuarioDTO>(@object);
            return objectMapped;
        }
        public async Task<ICollection<Estado1UsuarioDTO>> ListAsync()
        {
            //Obtener datos del repositorio
            var list = await _repository.ListAsync();
            var collection = _mapper.Map<ICollection<Estado1UsuarioDTO>>(list);
            // Return lista
            return collection;
        }
    }
}

