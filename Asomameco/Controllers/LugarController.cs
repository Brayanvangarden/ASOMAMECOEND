using Asomameco.Application.DTOs;
using Asomameco.Application.Services.Interfaces;
using Asomameco.Application.Services.Implementations;
using Asomameco.Infraestructure.Data;
using Asomameco.Infraestructure.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Crypto.Generators;
using X.PagedList;
using X.PagedList.Extensions;
using SkiaSharp;
using Org.BouncyCastle.Cmp;
using Asomameco.Web.Models;
using Microsoft.IdentityModel.Tokens;

namespace Asomameco.Web.Controllers
{
    public class LugarController : Controller
    {
        private readonly IServiceLugar _serviceLugar;
        private readonly IServiceAsistencia _serviceAsistencia;
        private readonly IServiceUsuario _serviceUsuario;
        private readonly IServiceConfirmacion _confirmacionService;
        private readonly EmailService _emailService;
        private readonly QrService _qrService;
        private readonly AsomamecoContext context;

        public LugarController(IServiceLugar serviceLugar, IServiceAsistencia serviceAsistencia, 
            IServiceConfirmacion serviceConfirmacion,   
            AsomamecoContext _context, EmailService emailService, QrService qrService, 
            IServiceUsuario serviceUsuario)
        {
            _serviceLugar = serviceLugar;
            _serviceAsistencia = serviceAsistencia;
            _emailService = emailService;
            _confirmacionService = serviceConfirmacion; 
            _qrService = qrService;
            context = _context;
            _serviceUsuario = serviceUsuario;
 
        }



        public async Task<ActionResult> IndexAdmin(int? page)
        {
            var collection = await _serviceLugar.ListAsync();
            //Cantidad de elementos por página
            return View(collection.ToPagedList(page ?? 1, 10));
        }

        [Authorize]
        public async Task<ActionResult> Details(int id)
        {
            try
            {
            
                var @object = await _serviceLugar.FindByIdAsync(id);
                if (@object == null)
                {
                    throw new Exception("Lugar no existente");

                }

                return View(@object);

            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }




        [Authorize]
        [HttpGet]
        public async Task<ActionResult> Create()
        {
            var consecutivo = await context.Lugar.OrderByDescending(x => x.Id).FirstOrDefaultAsync();
            ViewBag.id = consecutivo?.Id + 1 ?? 1;

            // Obtener todos lugares
            var allLugares = await _serviceLugar.ListAsync();

            // Filtrar los lugares 
            var allLugaresFiltrados = allLugares
                .Where(tu => tu.Estado == true)
                .OrderBy(asa => asa.NombreLugar)
                .ToList();

            // Asignar los lugares filtrados al ViewBag
            ViewBag.ListLugares = allLugaresFiltrados;

            //var estados = await _serviceEstadoLugar.ListAsync();
            //ViewBag.ListEstado = new SelectList(estados, "Id", "Descripcion"); // Cambio de MultiSelectList a SelectList

            return View();
        }
        
   

        [Authorize]
        // POST: LugarController/Create
        [HttpPost]

        public async Task<ActionResult> Create(LugarDTO dto)
        {
            try
            {

                //Validación del formulario
                if (!ModelState.IsValid)
                {
                    // Lee del ModelState todos los errores que
                    // vienen para el lado del server
                    string errors = string.Join("; ", ModelState.Values
                                       .SelectMany(x => x.Errors)
                                       .Select(x => x.ErrorMessage));
                    ViewBag.ErrorMessage = errors;
                    return View();
                } 

                //Crear
                await _serviceLugar.AddAsync(dto); 

  
                return RedirectToAction("IndexAdmin");
            }
            catch (Exception ex)
            {
                var innerException = ex.InnerException?.Message ?? ex.Message;
                ViewBag.ErrorMessage = $"Error al guardar el Lugar: {innerException}";  
                return View(dto);
            }
        }
 

        [Authorize]
        // GET: LugarController/Edit/
        public async Task<ActionResult> Edit(int id)
        {
            var @object = await _serviceLugar.FindByIdAsync(id);

            //Lista de Estados 
            var listaEstados = new List<LugarDTO>
            {
                new LugarDTO { Estado = true},   new LugarDTO { Estado = false}
            };

            // Retorno de informacion a través del Viewbag
            ViewBag.ListaEstados = listaEstados;
            ViewBag.Id = @object.Id;
            ViewBag.SelectedLugar = @object.Id;

            // Pasar el estado actual del lugar a la vista
            ViewBag.EstadoActual = @object.Estado;

            return View(@object);
        }

        //// POST: ProcesoPreparacionController/Edit/5
        [HttpPost]
        [Authorize]

        public async Task<ActionResult> Edit(int id, LugarDTO dto)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    // Lee del ModelState todos los errores que vienen para el lado del servidor
                    string errors = string.Join("; ", ModelState.Values
                                         .SelectMany(x => x.Errors)
                                         .Select(x => x.ErrorMessage));
                    ViewBag.ErrorMessage = errors;
                    return View(dto);

                }
                else
                {
                    await _serviceLugar.UpdateAsync(id, dto);
                }
            }
            catch (Exception ex)
            {
                var innerException = ex.InnerException?.Message ?? ex.Message;
                ViewBag.ErrorMessage = $"Error al guardar el Lugar: {innerException}";
                return View(dto);

            }
            return RedirectToAction("IndexAdmin");
        }


        [HttpPost]
        [Authorize]

        public async Task<ActionResult> Delete(int id)
        {
            try
            {
                var Lugar = await _serviceLugar.FindByIdAsync(id);
                if (Lugar == null)
                {
                    throw new Exception("Lugar no existente");
                }


                // Actualizar
                await _serviceLugar.DeleteAsync(id, Lugar);

                // Redirigir a IndexAdmin después de eliminar
                return RedirectToAction("IndexAdmin");
            }
            catch (Exception ex)
            {
                var innerException = ex.InnerException?.Message ?? ex.Message;
                ViewBag.ErrorMessage = $"Error al eliminar el Lugar: {innerException}";

                // Redirigir a IndexAdmin en caso de error
                return RedirectToAction("IndexAdmin");
            }
        }
    }
}
