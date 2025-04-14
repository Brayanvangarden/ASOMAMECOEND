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

namespace Asomameco.Application.Services.Implementations
{
    public class ServiceUsuario : IServiceUsuario
    {
        private readonly IRepositoryUsuario _repository;
        private readonly IMapper _mapper;
        public ServiceUsuario(IRepositoryUsuario repository, IMapper mapper)
        {
            _repository = repository;
            _mapper = mapper;
        }

        public async  Task<UsuarioDTO> AuthenticateAsync(int username, string password)
        {
            UsuarioDTO usuarioDTO = null!;
            var @object = await _repository.LoginAsync(username, password);

            if (@object != null)
            {
                usuarioDTO = _mapper.Map<UsuarioDTO>(@object);
            }

            return usuarioDTO;
        }

        public async Task<int> AddAsync(UsuarioDTO dto)
        {
            var objectMapped = _mapper.Map<Usuario>(dto);
            return await _repository.AddAsync(objectMapped);
        }
        public async Task UpdateAsync(int id, UsuarioDTO dto)
        {
            var @object = await _repository.FindByIdAsync(id);
            var entity = _mapper.Map(dto, @object!);

            await _repository.UpdateAsync(id, entity);
        }
        public async Task<UsuarioDTO> FindByIdAsync(int id)
        {
            var @object = await _repository.FindByIdAsync(id);
            var objectMapped = _mapper.Map<UsuarioDTO>(@object);
            return objectMapped;
        }
        public async Task<ICollection<UsuarioDTO>> ListAsync()
        {
            //Obtener datos del repositorio
            var list = await _repository.ListAsync();
            var collection = _mapper.Map<ICollection<UsuarioDTO>>(list);
            // Return lista
            return collection;
        }


        public async Task DeleteAsync(int id, UsuarioDTO dto)
        {
            var @object = await _repository.FindByIdAsync(id);
            var entity = _mapper.Map(dto, @object!);

            await _repository.DeleteAsync(id, entity);
        }

    }
}

