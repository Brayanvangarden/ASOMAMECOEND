using AutoMapper;
using Asomameco.Application.DTOs;
using Asomameco.Application.Services.Interfaces;
using Asomameco.Infraestructure.Models;
using Asomameco.Infraestructure.Repository.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Asomameco.Infraestructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Asomameco.Application.Services.Implementations
{
    public class ServiceAsamblea : IServiceAsamblea
    {
        private readonly IRepositoryAsamblea _repository;
        private readonly IMapper _mapper;
        private readonly AsomamecoContext context;
        public ServiceAsamblea(IRepositoryAsamblea repository, IMapper mapper, AsomamecoContext _context)
        {
            _repository = repository;
            _mapper = mapper;
            context = _context;
    }   

  
        public async Task<int> ConfirmAttendance(AsistenciaDTO confirmacion)
        {
            var objectMapped = _mapper.Map<Asistencia>(confirmacion);
            return await _repository.ConfirmAttendance(objectMapped);
        }


        public async Task<int> Confirmation(ConfirmacionDTO confirmacion)
        {
            var objectMapped = _mapper.Map<Confirmacion>(confirmacion);
            return await _repository.Confirmation(objectMapped);
        }

        public async Task<bool> VerificarAsistencia(int idMiembro, int idAsamblea)
        {
            return await context.Confirmacion
                .AnyAsync(c => c.IdMiembro == idMiembro && c.IdAsamblea == idAsamblea);
        }

   
        public async Task<AsambleaDTO> FindByIdAsync(int id)
        {
            var @object = await _repository.FindByIdAsync(id);
            var objectMapped = _mapper.Map<AsambleaDTO>(@object);
            return objectMapped;
        }
        public async Task<ICollection<AsambleaDTO>> ListAsync()
        {
            //Obtener datos del repositorio
            var list = await _repository.ListAsync();
            var collection = _mapper.Map<ICollection<AsambleaDTO>>(list);
            // Return lista
            return collection;
        }


        public async Task<int> AddAsync(AsambleaDTO dto)
        {
            var objectMapped = _mapper.Map<Asamblea>(dto);
            return await _repository.AddAsync(objectMapped);
        }

        public async Task UpdateAsync(int id, AsambleaDTO dto)
        {
            var @object = await _repository.FindByIdAsync(id);
            var entity = _mapper.Map(dto, @object!);

            await _repository.UpdateAsync(id, entity);
        }
        public async Task DeleteAsync(int id, AsambleaDTO dto)
        {
            var @object = await _repository.FindByIdAsync(id);
            var entity = _mapper.Map(dto, @object!);

            await _repository.DeleteAsync(id, entity);
        }

    }
}

