using Asomameco.Application.DTOs;
using Asomameco.Infraestructure.Models;
using AutoMapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.Profiles
{
    public class LugarProfile:Profile
    {
        public LugarProfile()
        {
            CreateMap<LugarDTO, Lugar>().ReverseMap();
        }
    }
}
