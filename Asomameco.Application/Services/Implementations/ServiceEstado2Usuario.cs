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
    public class ServiceEstado2Usuario : IServiceEstado2Usuario
    {
        private readonly IRepositoryEstado2Usuario _repository;
        private readonly IMapper _mapper;
        public ServiceEstado2Usuario(IRepositoryEstado2Usuario repository, IMapper mapper)
        {
            _repository = repository;
            _mapper = mapper;
        }
        public async Task<Estado2UsuarioDTO> FindByIdAsync(int id)
        {
            var @object = await _repository.FindByIdAsync(id);
            var objectMapped = _mapper.Map<Estado2UsuarioDTO>(@object);
            return objectMapped;
        }
        public async Task<ICollection<Estado2UsuarioDTO>> ListAsync()
        {
            //Obtener datos del repositorio
            var list = await _repository.ListAsync();
            var collection = _mapper.Map<ICollection<Estado2UsuarioDTO>>(list);
            // Return lista
            return collection;
        }
    }
}

