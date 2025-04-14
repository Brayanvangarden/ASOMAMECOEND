using AutoMapper;
using Asomameco.Application.DTOs;
using Asomameco.Application.Services.Interfaces;
using Asomameco.Infraestructure.Repository.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.Services.Implementations
{
    public class ServiceTipoUsuario : IServiceTipoUsuario
    {
        private readonly IRepositoryTipoUsuario _repository;
        private readonly IMapper _mapper;
        public ServiceTipoUsuario(IRepositoryTipoUsuario repository, IMapper mapper)
        {
            _repository = repository;
            _mapper = mapper;
        }
        public async Task<TipoUsuarioDTO> FindByIdAsync(int id)
        {
            var @object = await _repository.FindByIdAsync(id);
            var objectMapped = _mapper.Map<TipoUsuarioDTO>(@object);
            return objectMapped;
        }
        public async Task<ICollection<TipoUsuarioDTO>> ListAsync()
        {
            //Obtener datos del repositorio
            var list = await _repository.ListAsync();
            var collection = _mapper.Map<ICollection<TipoUsuarioDTO>>(list);
            // Return lista
            return collection;
        }
    }
}

