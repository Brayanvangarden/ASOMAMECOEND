using System;
using Asomameco.Application.DTOs;
using Asomameco.Infraestructure;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using Asomameco.Infraestructure.Models;

namespace Asomameco.Application.Profiles
{
    public class Estado2UsuarioProfile : Profile
    {
        public Estado2UsuarioProfile()
        {
            CreateMap<Estado2UsuarioDTO, Estado2Usuario>().ReverseMap();
        }
    }
}
