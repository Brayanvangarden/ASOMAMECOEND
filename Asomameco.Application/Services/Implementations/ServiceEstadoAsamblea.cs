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
    public class ServiceEstadoAsamblea : IServiceEstadoAsamblea
    {
        private readonly IRepositoryEstadoAsamblea _repository;
        private readonly IMapper _mapper;
        public ServiceEstadoAsamblea(IRepositoryEstadoAsamblea repository, IMapper mapper)
        {
            _repository = repository;
            _mapper = mapper;
        }
        public async Task<EstadoAsambleaDTO> FindByIdAsync(int id)
        {
            var @object = await _repository.FindByIdAsync(id);
            var objectMapped = _mapper.Map<EstadoAsambleaDTO>(@object);
            return objectMapped;
        }
        public async Task<ICollection<EstadoAsambleaDTO>> ListAsync()
        {
            //Obtener datos del repositorio
            var list = await _repository.ListAsync();
            var collection = _mapper.Map<ICollection<EstadoAsambleaDTO>>(list);
            // Return lista
            return collection;
        }
    }
}

