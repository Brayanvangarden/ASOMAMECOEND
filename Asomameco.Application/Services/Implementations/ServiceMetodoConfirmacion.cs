using Asomameco.Application.Services.Interfaces;
using AutoMapper;
using Asomameco.Application.DTOs;
using Asomameco.Infraestructure.Repository.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.Services.Implementations
{
    public class ServiceMetodoConfirmacion : IServiceMetodoConfirmacion
    {
        private readonly IRepositoryMetodoConfirmacion _repository;
        private readonly IMapper _mapper;
        public ServiceMetodoConfirmacion(IRepositoryMetodoConfirmacion repository, IMapper mapper)
        {
            _repository = repository;
            _mapper = mapper;
        }
        public async Task<MetodoConfirmacionDTO> FindByIdAsync(int id)
        {
            var @object = await _repository.FindByIdAsync(id);
            var objectMapped = _mapper.Map<MetodoConfirmacionDTO>(@object);
            return objectMapped;
        }
        public async Task<ICollection<MetodoConfirmacionDTO>> ListAsync()
        {
            //Obtener datos del repositorio
            var list = await _repository.ListAsync();
            var collection = _mapper.Map<ICollection<MetodoConfirmacionDTO>>(list);
            // Return lista
            return collection;
        }
    }
}

