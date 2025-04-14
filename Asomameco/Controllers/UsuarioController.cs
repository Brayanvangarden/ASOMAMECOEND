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

namespace Asomameco.Web.Controllers
{
    public class UsuarioController : Controller
    {
        private readonly IServiceUsuario _serviceUsuario;
        private readonly IServiceTipoUsuario _serviceTipoUsuario;
        private readonly AsomamecoContext context;

        public UsuarioController(IServiceUsuario serviceUsuario, IServiceTipoUsuario serviceTipoUsuario, AsomamecoContext _context)
        {
            _serviceUsuario = serviceUsuario;
            _serviceTipoUsuario = serviceTipoUsuario;
            context = _context;
        }

        [Authorize]

        public async Task<ActionResult> IndexAdmin(int? page)
        {
            var collection = await _serviceUsuario.ListAsync();
            //Cantidad de elementos por página
            return View(collection.ToPagedList(page ?? 1, 10));
        }

        [Authorize]
        public async Task<ActionResult> Details(int id)
        {
            try
            {
                if (id == null)
                {
                    return RedirectToAction("IndexAdmin");
                }
                var @object = await _serviceUsuario.FindByIdAsync(id);
                if (@object == null)
                {
                    throw new Exception("Usuario no existente");

                }

                return View(@object);

            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }


        [HttpGet]
        public IActionResult VerificarIdExiste(int id)
        {
            bool existe = context.Usuario.Any(u => u.Id == id);
            return Json(existe);
        }


        [Authorize]
        // GET: UsuarioController/Create
        [HttpGet]
        public async Task<ActionResult> Create()
        {



            // Obtener todos los tipos de usuario
            var allTiposUsuario = await _serviceTipoUsuario.ListAsync();

            // Filtrar los tipos de usuario con valores 2 y 3
            var tiposUsuarioFiltrados = allTiposUsuario
                .Where(tu => tu.Id == 1 || tu.Id == 2) // Suponiendo que 'Id' es el campo que contiene el valor de tipo
                .ToList();

            // Asignar los tipos de usuario filtrados al ViewBag
            ViewBag.ListRol = tiposUsuarioFiltrados;

            return View();
        }


 


        [Authorize]
        // POST: UsuarioController/Create
        [HttpPost]

        public async Task<ActionResult> Create(UsuarioDTO dto)
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
                dto.Estado1 = 1;

                //Crear
                await _serviceUsuario.AddAsync(dto);
                return RedirectToAction("IndexAdmin");
            }
            catch (Exception ex)
            {
                var innerException = ex.InnerException?.Message ?? ex.Message;
                ViewBag.ErrorMessage = $"Error al guardar el usuario: {innerException}";
                await CargarListas(dto);
                return View(dto);
            }
        }


        private async Task CargarListas(UsuarioDTO UsuarioDTO)
        {
            // Obtener todos los tipos de usuario
            var allTiposUsuario = await _serviceTipoUsuario.ListAsync();

            // Filtrar los tipos de usuario con valores 2 y 3
            var tiposUsuarioFiltrados = allTiposUsuario
                .Where(tu => tu.Id == 2 || tu.Id == 3) // Suponiendo que 'Id' es el campo que contiene el valor de tipo
                .ToList();

            // Asignar los tipos de usuario filtrados al ViewBag
            ViewBag.ListRol = tiposUsuarioFiltrados;

        }



        [Authorize]
        // GET: UsuarioController/Edit/
        public async Task<ActionResult> Edit(int id)
        {
            var @object = await _serviceUsuario.FindByIdAsync(id);
          

            // Obtener todos los tipos de usuario
            var allTiposUsuario = await _serviceTipoUsuario.ListAsync();

            // Filtrar los tipos de usuario con valores 2 y 3
            var tiposUsuarioFiltrados = allTiposUsuario
                .Where(tu => tu.Id == 1 || tu.Id == 2) // Suponiendo que 'Id' es el campo que contiene el valor de tipo
                .ToList();

            // Asignar los tipos de usuario filtrados al ViewBag
            ViewBag.ListRol = tiposUsuarioFiltrados;
            ViewBag.Id = @object.Id;

            // Enviar el tipo de usuario actual al ViewBag para que sea seleccionado
            ViewBag.SelectedTipoUsuario = @object.TipoNavigation.Id; // Asegúrate de que 'TipoUsuarioId' es el campo adecuado

            return View(@object);
        }

        //// POST: ProcesoPreparacionController/Edit/5
        [HttpPost]
        [Authorize]

        public async Task<ActionResult> Edit(int id, UsuarioDTO dto)
        {
            try
            {
                // Obtener el usuario actual de la base de datos
                var usuarioActual = await _serviceUsuario.FindByIdAsync(id);

                if (dto.Contraseña == "********" || dto.Contraseña == null)
                {
                    // Mantener la contraseña actual si el usuario no la cambió
                    dto.Contraseña = usuarioActual.Contraseña;


                }
                

                if (HttpContext.Session.GetString("UserId") == dto.Id.ToString())
                {
                    dto.Estado1 = usuarioActual.Estado1;
                }

               
                ModelState.Remove("Contraseña");
                if (!ModelState.IsValid)
                {
                    ViewBag.ErrorMessage = string.Join("; ", ModelState.Values
                                          .SelectMany(x => x.Errors)
                                          .Select(x => x.ErrorMessage));
                    return View(dto);
                }

                await _serviceUsuario.UpdateAsync(id, dto);

                return RedirectToAction("IndexAdmin");
            }
            catch (Exception ex)
            {
                ViewBag.ErrorMessage = $"Error al actualizar el usuario: {ex.InnerException?.Message ?? ex.Message}";
                return RedirectToAction("IndexAdmin");
            }
        }


        [HttpPost]
        [Authorize]

        public async Task<ActionResult> Delete(int id)
        {
            try
            {
                var Usuario = await _serviceUsuario.FindByIdAsync(id);
                if (Usuario == null)
                {
                    throw new Exception("Usuario no existente");
                }


                // Actualizar
                await _serviceUsuario.DeleteAsync(id, Usuario);

                // Redirigir a IndexAdmin después de eliminar
                return RedirectToAction("IndexAdmin");
            }
            catch (Exception ex)
            {
                var innerException = ex.InnerException?.Message ?? ex.Message;
                ViewBag.ErrorMessage = $"Error al eliminar el Usuario: {innerException}";

                // Redirigir a IndexAdmin en caso de error
                return RedirectToAction("IndexAdmin");
            }
        }
    }
}
