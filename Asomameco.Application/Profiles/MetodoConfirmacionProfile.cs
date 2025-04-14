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
    public class MetodoConfirmacionProfile : Profile
    {
        public MetodoConfirmacionProfile()
        {
            CreateMap<MetodoConfirmacionDTO, MetodoConfirmacion>().ReverseMap();
        }
    }
}
