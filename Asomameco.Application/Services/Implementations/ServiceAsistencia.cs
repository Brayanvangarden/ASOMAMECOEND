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
    public class ServiceAsistencia : IServiceAsistencia
    {
        private readonly IRepositoryAsistencia _repository;
        private readonly IMapper _mapper;
        public ServiceAsistencia(IRepositoryAsistencia repository, IMapper mapper)
        {
            _repository = repository;
            _mapper = mapper;
        }
        public async Task<AsistenciaDTO> FindByIdAsync(int id)
        {
            var @object = await _repository.FindByIdAsync(id);
            var objectMapped = _mapper.Map<AsistenciaDTO>(@object);
            return objectMapped;
        }
        public async Task<ICollection<AsistenciaDTO>> ListAsync()
        {
            //Obtener datos del repositorio
            var list = await _repository.ListAsync();
            var collection = _mapper.Map<ICollection<AsistenciaDTO>>(list);
            // Return lista
            return collection;
        }
    }
}

