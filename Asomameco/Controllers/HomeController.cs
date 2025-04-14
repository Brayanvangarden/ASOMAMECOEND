using Asomameco.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace Asomameco.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        private readonly EmailService _ServiceEmail;
        public HomeController(ILogger<HomeController> logger, EmailService serviceEmail)
        {
            _logger = logger;
            _ServiceEmail = serviceEmail;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Contacto()
        {
            return View();
        }
        public IActionResult Servicios()
        {
            return View();
        }


        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [HttpPost]
        public async Task<IActionResult> EnviarConsulta(string name, string email, string subject, string message)
        {
            var body = $"Nombre: {name}\nCorreo: {email}\nAsunto: {subject}\n\nMensaje: {message}";
            //Este es el correo al que llegaría la consulta
            await _ServiceEmail.EnviarCorreoAsync("asociacionmaridosamecatecorto@gmail.com", subject, body);

            // Puedes redirigir a una página de agradecimiento o mostrar un mensaje
            TempData["MensajeExito"] = "Tu consulta ha sido enviada exitosamente.";
            return RedirectToAction("Contacto");
        }
    }
}
