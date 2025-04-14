using Microsoft.AspNetCore.Mvc;

namespace Asomameco.Web.Controllers
{
    public class ErrorController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
        public IActionResult NotFound() => View(); // Esto renderizará Views/Error/NotFound.cshtml

        public IActionResult UsuarioNoConfirmado() => View(); // Esto renderizará Views/Error/NotFound.cshtml

    }
}
