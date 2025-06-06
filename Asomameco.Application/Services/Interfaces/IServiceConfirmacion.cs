﻿ 
using Asomameco.Application.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asomameco.Application.Services.Interfaces
{
    public interface IServiceConfirmacion
    {
        Task<ICollection<ConfirmacionDTO>> ListAsync();
        Task<ConfirmacionDTO> FindByIdAsync(int id);
    }
}
