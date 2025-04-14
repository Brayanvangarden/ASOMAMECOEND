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
    public class ServiceConfirmacion : IServiceConfirmacion
    {
        private readonly IRepositoryConfirmacion _repository;
        private readonly IMapper _mapper;
        public ServiceConfirmacion(IRepositoryConfirmacion repository, IMapper mapper)
        {
            _repository = repository;
            _mapper = mapper;
        }
        public async Task<ConfirmacionDTO> FindByIdAsync(int id)
        {
            var @object = await _repository.FindByIdAsync(id);
            var objectMapped = _mapper.Map<ConfirmacionDTO>(@object);
            return objectMapped;
        }
        public async Task<ICollection<ConfirmacionDTO>> ListAsync()
        {
            //Obtener datos del repositorio
            var list = await _repository.ListAsync();
            var collection = _mapper.Map<ICollection<ConfirmacionDTO>>(list);
            // Return lista
            return collection;
        }
    }
}

