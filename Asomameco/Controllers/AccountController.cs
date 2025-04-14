using Asomameco.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;
using Asomameco.Application.Services.Interfaces;
using Microsoft.EntityFrameworkCore;
using Asomameco.Infraestructure.Data;
using System.Net.Mail;
using System.Net;
using Asomameco.Infraestructure.Models;
 
using Org.BouncyCastle.Crypto.Generators;
using System.Text.RegularExpressions;

namespace Asomameco.Controllers
{
    public class AccountController : Controller
    {
        private readonly IServiceUsuario _usuarioService;
        private readonly AsomamecoContext context;

        private readonly EmailService _emailService;
        public AccountController(IServiceUsuario usuarioService, EmailService emailService, AsomamecoContext _context)
        {
            _usuarioService = usuarioService;
            context = _context;
            _emailService = emailService;
        }
        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(int username, string password)
        {
            var user = await _usuarioService.AuthenticateAsync(username, password);

            if (user != null)
            {

                // Verificar si el usuario está activo
                if (user.Estado1 == 2) // Asegúrate de que la propiedad sea `Estado` o cambia según tu modelo
                {
                    return RedirectToAction("CuentaDesactivada");
                }
                // Si el usuario tiene Estado 3, redirigir a la vista de cambio de contraseña
                if (user.Estado1 == 3)
                {
                    HttpContext.Session.SetString("UserId", user.Id.ToString());
                    return RedirectToAction("ChangePassword");
                }
                HttpContext.Session.SetString("UsuarioIniciadoSesion", "1"); // Establecer variable de sesión
                HttpContext.Session.SetString("UserId", user.Id.ToString());
                HttpContext.Session.SetString("UserType", user.TipoNavigation.Id.ToString());
                HttpContext.Session.SetString("UserName", user.Nombre);
                HttpContext.Session.SetString("UserSurname", user.Apellidos); // Guardamos el apellido en la sesión


                List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Nombre +" "+ user.Apellidos),
                new Claim(ClaimTypes.Role, user.TipoNavigation.Descripcion),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            };
                ClaimsIdentity claimsIdentity = new ClaimsIdentity(
                    claims, CookieAuthenticationDefaults.AuthenticationScheme);
                AuthenticationProperties properties = new AuthenticationProperties()
                {
                    AllowRefresh = true,
                };
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity), properties);



                return RedirectToAction("Index", "Home");
            }

            ViewBag.ErrorMessage = "Usuario y/o contraseña inválidos";
            return View();
        }

        [HttpGet]
        public IActionResult ChangePassword()
        {
            var userId = HttpContext.Session.GetString("UserId");
            if (string.IsNullOrEmpty(userId))
            {
                return RedirectToAction("Login");
            }

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ChangePassword(string NewPassword, string ConfirmPassword)
        {
            var userId = HttpContext.Session.GetString("UserId");
            if (string.IsNullOrEmpty(userId))
            {
                return RedirectToAction("Login");
            }

            var usuario = await context.Usuario.FindAsync(Convert.ToInt32(userId));

            if (NewPassword == usuario.Contraseña)
            {
                ModelState.AddModelError("NewPassword", "La contraseña debe ser diferente a la que se proporcionó por correo.");
                return View();
            }

            if (NewPassword.Length < 6)
            {
                TempData["ErrorMessage"] = "La contraseña debe tener al menos 6 caracteres.";
                return View();
            }

            if (NewPassword != ConfirmPassword)
            {
                TempData["ErrorMessage"] = "Las contraseñas no coinciden.";
                return View();
            }

         
            if (usuario == null)
            {


                return RedirectToAction("Login");

            }

            // Actualizar la contraseña y cambiar el estado a 1
            usuario.Contraseña = NewPassword;
            usuario.Estado1 = 1;

            await context.SaveChangesAsync();

            // Cerrar sesión para que el usuario vuelva a iniciar sesión con su nueva contraseña
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.Session.Clear();

            TempData["SuccessMessage"] = "Contraseña actualizada con éxito. Inicie sesión nuevamente.";



            usuario.TipoNavigation = await context.TipoUsuario.FindAsync(usuario.Tipo);
            HttpContext.Session.SetString("UserId", usuario.Id.ToString());
            HttpContext.Session.SetString("UserType", usuario.TipoNavigation.Id.ToString());
            HttpContext.Session.SetString("UserName", usuario.Nombre);
            HttpContext.Session.SetString("UserSurname", usuario.Apellidos); // Guardamos el apellido en la sesión
            HttpContext.Session.SetString("UsuarioIniciadoSesion", "1"); // Establecer variable de sesión



            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, usuario.Nombre +" "+ usuario.Apellidos),
                new Claim(ClaimTypes.Role, usuario.TipoNavigation.Descripcion),
                new Claim(ClaimTypes.NameIdentifier, usuario.Id.ToString())
            };
            ClaimsIdentity claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);
            AuthenticationProperties properties = new AuthenticationProperties()
            {
                AllowRefresh = true,
            };
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity), properties);




            return RedirectToAction("Index", "Home");
        }


        // Método para mostrar la vista cuando el usuario está desactivado
        [HttpGet]
        public IActionResult CuentaDesactivada()
        {
            return View();
        }

        [HttpGet]
        public IActionResult RecuperarContraseña()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> RecuperarContraseña(string correo)
        {
            if (string.IsNullOrEmpty(correo))
            {
                TempData["MensajeError"] = "Debe ingresar un correo.";
                return RedirectToAction("RecuperarContraseña");
            }

            if (correo.Trim().Equals(""))
            {
                TempData["MensajeError"] = "Debe ingresar un correo.";
                return RedirectToAction("RecuperarContraseña");
            }


            // Validación de formato de correo electrónico
            string patronCorreo = @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";
            if (!Regex.IsMatch(correo, patronCorreo))
            {
                TempData["MensajeError"] = "El correo ingresado no tiene un formato válido.";
                return RedirectToAction("RecuperarContraseña");
            }

            var usuario = await context.Usuario.FirstOrDefaultAsync(u => u.Correo == correo);

            if (usuario == null)
            {
                TempData["MensajeError"] = "El correo no está registrado.";
                return RedirectToAction("RecuperarContraseña");
            }




            // Generar contraseña temporal
            string nuevaContraseña = GenerarContraseñaTemporal();

            // Guardar nueva contraseña (preferiblemente hasheada si usas autenticación segura)
            usuario.Contraseña = nuevaContraseña;
            usuario.Estado1 = 3;
            await context.SaveChangesAsync();

            // Enviar correo con la nueva contraseña
            string destinatario = usuario.Correo;
            string asunto = "Recuperación de Contraseña";
            string mensaje = $"Su nueva contraseña temporal es: {nuevaContraseña} Cambie su contraseña una vez que inicie sesión.";
            await _emailService.EnviarCorreoAsync(destinatario, asunto, mensaje);


            TempData["MensajeExito"] = "Se ha enviado un correo con instrucciones para restablecer la contraseña.";
            return RedirectToAction("RecuperarContraseña");

        }


        private string GenerarContraseñaTemporal()
        {
            const string caracteres = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            Random random = new Random();
            return new string(Enumerable.Repeat(caracteres, 10)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }



        private async Task<bool> EnviarCorreoRecuperacion(string correo, string nuevaContraseña)
        {
            try
            {
                var smtpClient = new SmtpClient("smtp.gmail.com")
                {
                    Port = 587,
                    Credentials = new NetworkCredential("noreplyAsomamecojafethjimenez@gmail.com", "gvbh ueos xzyy pbmm\r\n"),
                    EnableSsl = true
                };

                var mensaje = new MailMessage
                {
                    From = new MailAddress("noreplyAsomamecojafethjimenez@gmail.com"),
                    Subject = "Recuperación de Contraseña",
                    Body = $"Su nueva contraseña temporal es: {nuevaContraseña} Cambie su contraseña una vez que inicie sesión.",
                    IsBodyHtml = false
                };

                mensaje.To.Add(correo);

                await smtpClient.SendMailAsync(mensaje);
                return true;
            }
            catch
            {
                return false;
            }
        }

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.Session.Clear(); // También limpia la sesión

            return RedirectToAction("Login");
        }




    }
}
